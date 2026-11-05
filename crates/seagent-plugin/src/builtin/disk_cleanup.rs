//! `disk-cleanup` (Hermes `plugins/disk-cleanup/{__init__.py,disk_cleanup.py}`, MIT) — ported as a
//! built-in seagent plugin.
//!
//! Upstream silently tracks the ephemeral files a tool call *creates* and deletes the ones whose
//! category says they are scratch:
//!
//! | category | threshold | confirmation |
//! |---|---|---|
//! | `test` | every session end (age >= 0) | never |
//! | `temp` | > 7 days since tracked | never |
//! | `cron-output` | > 14 days since tracked | never |
//! | empty dirs under the home | always | never |
//! | `research` | > 30 days (deep only; `status` shows all) | always |
//! | `chrome-profile` | > 14 days | always |
//! | files > 500 MB | never automatic | always |
//!
//! Scope is adapted from `$HERMES_HOME` + `/tmp/hermes-*` to `paths.data` (seagent's data home, what
//! the docs call `SEAGENT_HOME`) + `/tmp/seagent-*`. Everything else — Windows mounts, system dirs, the
//! plugin's own state dir, logs/memory/sessions/skills/plugins, the cron control plane and the
//! user project trees — is refused by `is_safe_path` / `guess_category` (upstream `is_safe_path`,
//! `_NEVER_TRACK_TOP_LEVEL`, `_EMPTY_DIR_PROTECTED_TOP_LEVEL`, `_protected_cron_paths`,
//! `_is_protected_dir`).
//!
//! Upstream is a hook-only plugin; seagent also exposes the same six verbs as a `disk_cleanup` tool and
//! keeps `/disk-cleanup` as a slash command. `[builtin_plugins.disk-cleanup] dry_run = true` makes
//! every delete a no-op (upstream only had `/disk-cleanup dry-run` as a one-off preview).

use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::hooks::{Hook, HookDecision, HookEvent};
use seagent_kernel::slash::{Slash, SlashCtx, SlashReply};
use seagent_kernel::util::{civil_from_days, days_from_civil, unix_now};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// `_LARGE_FILE_BYTES`: never auto-deleted, always offered in the prompt list.
const LARGE_FILE_BYTES: u64 = 500 * 1024 * 1024;

/// `ALLOWED_CATEGORIES` (not a set upstream, but only membership matters).
const ALLOWED_CATEGORIES: &[&str] = &["temp", "test", "research", "download", "chrome-profile", "cron-output", "other"];

/// `_TEST_PATTERNS` / `_TEST_SUFFIXES`: names `guess_category` treats as scratch.
const TEST_PATTERNS: &[&str] = &["test_", "tmp_"];
const TEST_SUFFIXES: &[&str] = &[".test.py", ".test.js", ".test.ts", ".test.md"];

/// Top-level home dirs whose empty subdirs are never swept (`_EMPTY_DIR_PROTECTED_TOP_LEVEL`).
/// Upstream's list, plus the names seagent's data home actually uses (`memory`, `approvals`,
/// `channels`, `hooks`, `checkpoints`, the cron script dir and friends).
const EMPTY_DIR_PROTECTED_TOP_LEVEL: &[&str] = &[
    // upstream (Hermes) names, kept where seagent uses the same directory
    "logs",
    "memories",
    "sessions",
    "cron",
    "cronjobs",
    "cache",
    "skills",
    "plugins",
    "disk-cleanup",
    "optional-skills",
    "backups",
    "profiles",
    ".worktrees",
    "patches",
    "projects",
    "skins",
    "themes",
    "contributors",
    "workspace",
    "plans",
    "home",
    "kanban",
    // seagent's own layout: control plane, channel/hook state, checkpoints, durable artifacts
    "memory",
    "approvals",
    "channels",
    "hooks",
    "hook_outputs",
    "checkpoints",
    "scripts",
    "sandboxes",
    "boards",
    "logbook",
    "transcripts",
    "mcp-cache",
    "skill-bundles",
    "commands",
    "routes",
    "rooms",
    "meetings",
    "workflows",
    "cron_runs",
];

/// `_EMPTY_DIR_SWEEP_PRUNE_DIRS`: never descend into these (a checkout or venv under the home
/// would stall the sweep for minutes).
const EMPTY_DIR_SWEEP_PRUNE_DIRS: &[&str] = &[".git", "node_modules", "venv", ".venv", "site-packages", "__pycache__"];

/// Top-level home entries `guess_category` never auto-tracks (`_NEVER_TRACK_TOP_LEVEL`): state,
/// logs, memory, sessions, config/secrets, seagent's control plane and the user project trees.
const NEVER_TRACK_TOP_LEVEL: &[&str] = &[
    "disk-cleanup",
    "logs",
    "memories",
    "memory",
    "sessions",
    "config.yaml",
    "config.toml",
    "skills",
    "plugins",
    ".env",
    "USER.md",
    "MEMORY.md",
    "SOUL.md",
    "auth.json",
    // seagent control plane: approvals, channel bindings, hooks, checkpoints, cron job scripts
    "approvals",
    "channels",
    "hooks",
    "hook_outputs",
    "checkpoints",
    "scripts",
    "sandboxes",
    // user-authored project trees: a `test_*` there is not session scratch
    "patches",
    "projects",
    "skins",
    "themes",
    "contributors",
    "profiles",
    "backups",
    "optional-skills",
    "workspace",
    "plans",
    "home",
    "kanban",
    ".worktrees",
];

/// Tools whose argument paths the hook snapshots (upstream `write_file`, `patch`, `terminal`).
fn extracts(tool: &str) -> bool {
    matches!(tool, "write" | "edit" | "patch" | "apply_patch" | "shell" | "run")
}

/// `_PRE_CALL_TTL_S`: a call whose post hook never fires (blocked) must not leak its snapshot.
const PRE_CALL_TTL_SECS: i64 = 3600;

// ───────────────────────── paths & time helpers ─────────────────────────

/// Resolve `.`/`..` lexically (upstream non-strict `Path.resolve` tail).
fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `Path.resolve()`: canonicalise what exists (following symlinks), keep a non-existent tail
/// lexical. `None` only when neither the path nor any ancestor can be made absolute.
fn resolve(path: &Path) -> Option<PathBuf> {
    let abs = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir().ok()?.join(path) };
    if let Ok(c) = abs.canonicalize() {
        return Some(c);
    }
    let norm = lexical(&abs);
    if let Ok(c) = norm.canonicalize() {
        return Some(c);
    }
    // Not there yet: canonicalise the deepest existing ancestor (macOS /tmp → /private/tmp and
    // friends) and append the rest.
    let mut tail: Vec<OsString> = Vec::new();
    let mut cur = norm.as_path();
    loop {
        if let Ok(base) = cur.canonicalize() {
            let mut out = base;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return Some(out);
        }
        tail.push(cur.file_name()?.to_os_string());
        cur = cur.parent()?;
    }
}

/// `/tmp` as resolved by the OS, plus `$TMPDIR`: upstream resolves `/tmp` itself so the same
/// directory matches under `/private/tmp`; seagent honours a sandbox's temp root the same way.
fn tmp_roots() -> &'static [PathBuf] {
    static ROOTS: OnceLock<Vec<PathBuf>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let mut v: Vec<PathBuf> = Vec::new();
        for p in [PathBuf::from("/tmp"), std::env::temp_dir()] {
            let c = resolve(&p).unwrap_or(p);
            if !v.contains(&c) {
                v.push(c);
            }
        }
        v
    })
}

/// Windows mounts (`/mnt/c`, `/mnt/d/…`) are never in scope, however the home is configured.
fn is_windows_mount(p: &Path) -> bool {
    let mut it = p.components();
    let (Some(Component::RootDir), Some(Component::Normal(mnt)), Some(Component::Normal(drive))) = (it.next(), it.next(), it.next()) else {
        return false;
    };
    let d = drive.to_string_lossy();
    mnt == "mnt" && d.len() == 1 && d.chars().all(|c| c.is_ascii_alphabetic())
}

/// `fmt_size`: `f"{n:.1f} {unit}"` over B/KB/MB/GB/TB and PB last.
fn fmt_size(n: u64) -> String {
    let mut n = n as f64;
    for unit in ["B", "KB", "MB", "GB", "TB"] {
        if n < 1024.0 {
            return format!("{n:.1} {unit}");
        }
        n /= 1024.0;
    }
    format!("{n:.1} PB")
}

/// `datetime.now(UTC).isoformat()`, second precision (`…+00:00`).
fn iso_of(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let s = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}+00:00", s / 3600, (s / 60) % 60, s % 60)
}

/// `datetime.fromisoformat` for what we (and upstream) write: `YYYY-MM-DDTHH:MM:SS[.fff][±HH:MM]`.
fn parse_iso(s: &str) -> Option<i64> {
    let s = s.trim();
    let num = |i: usize, n: usize| -> Option<i64> { s.get(i..i + n)?.parse::<i64>().ok() };
    let (y, mo, d, h, mi, sec) = (num(0, 4)?, num(5, 2)?, num(8, 2)?, num(11, 2)?, num(14, 2)?, num(17, 2)?);
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let mut t = days_from_civil(y, mo as u32, d as u32) * 86_400 + h * 3600 + mi * 60 + sec;
    let rest = s.get(19..).unwrap_or("");
    if let Some(i) = rest.find(['+', '-']) {
        let off = &rest[i..];
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let hh: i64 = off.get(1..3).and_then(|x| x.parse().ok()).unwrap_or(0);
        let mm: i64 = off.get(4..6).and_then(|x| x.parse().ok()).unwrap_or(0);
        t -= sign * (hh * 3600 + mm * 60);
    }
    Some(t)
}

/// Python `timedelta.days` (floor) between two unix second counts.
fn days_between(now: i64, then: i64) -> i64 {
    (now - then).div_euclid(86_400)
}

/// `[{cat!r} for cat in sorted(...)]` — the exact `LIST` repr upstream puts in its message.
fn py_list(items: &[&str]) -> String {
    let mut v: Vec<&str> = items.to_vec();
    v.sort_unstable();
    format!("[{}]", v.iter().map(|s| format!("'{s}'")).collect::<Vec<_>>().join(", "))
}

/// `repr(guess_category(p))`.
fn py_repr(cat: Option<&str>) -> String {
    cat.map(|c| format!("'{c}'")).unwrap_or_else(|| "None".to_string())
}

/// `shlex.split(cmd, posix=True)`; a malformed quote yields no tokens (upstream swallows the
/// `ValueError`).
fn shell_words(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) if c == q => quote = None,
            Some('"') if c == '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            Some(_) => cur.push(c),
            None if c == '\'' || c == '"' => quote = Some(c),
            None if c == '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            None if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(c),
        }
    }
    if quote.is_some() {
        return Vec::new();
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Candidate paths named in a `shell` command (`_extract_paths_from_terminal`).
fn paths_from_command(cmd: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in shell_words(cmd) {
        let mut t = tok.as_str();
        if t.len() >= 2 && t.starts_with(['\'', '"']) && t.ends_with(['\'', '"']) {
            t = &t[1..t.len() - 1];
        }
        let drive = {
            let b = t.as_bytes();
            b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'/' || b[2] == b'\\')
        };
        if t.starts_with('/') || t.starts_with('~') || drive {
            out.push(t.to_string());
        }
    }
    out
}

/// Paths a call names: the single `path` arg, a patch's `edits[].path`, or a shell command's
/// absolute/`~`/drive-letter tokens. `None` = the tool is not one of those (upstream
/// `_PATH_EXTRACTORS` miss).
fn extract_paths(tool: &str, input: &Value) -> Option<Vec<String>> {
    match tool {
        "write" | "edit" | "patch" | "apply_patch" => {
            let mut v: Vec<String> = Vec::new();
            if let Some(p) = input.get("path").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                v.push(p.to_string());
            }
            for e in input.get("edits").and_then(Value::as_array).into_iter().flatten() {
                if let Some(p) = e.get("path").and_then(Value::as_str).filter(|s| !s.is_empty()) {
                    v.push(p.to_string());
                }
            }
            v.dedup();
            Some(v)
        }
        "shell" | "run" => Some(paths_from_command(input.get("command").and_then(Value::as_str).unwrap_or(""))),
        _ => None,
    }
}

/// seagent's payload has no tool-call id, so the pre-call snapshot is keyed by the session plus a
/// stable digest of (tool name, tool input) — the same call yields the same key in pre and post.
fn call_key(tool: &str, input: &Value) -> String {
    let body = format!("{tool}\u{1}{input}");
    seagent_net::crypto::hex(&seagent_net::crypto::sha256(body.as_bytes())[..8])
}

fn session_of(payload: &Value) -> String {
    payload.get("session_id").and_then(Value::as_str).filter(|s| !s.is_empty()).unwrap_or("default").to_string()
}

// ───────────────────────── state ─────────────────────────

/// One `tracked.json` entry (upstream `{path, timestamp, category, size}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Item {
    path: String,
    #[serde(default)]
    timestamp: String,
    #[serde(default = "other_category")]
    category: String,
    #[serde(default)]
    size: u64,
}

fn other_category() -> String {
    "other".into()
}

/// What `quick()` did (`{deleted, empty_dirs, freed, errors}` upstream). With `dry_run` the
/// counters describe what *would* happen and nothing was touched.
#[derive(Debug, Default, Clone)]
struct Quick {
    deleted: usize,
    empty_dirs: usize,
    freed: u64,
    errors: Vec<String>,
    dry_run: bool,
}

/// `status()`: per-category breakdown and the 10 largest tracked files that still exist.
#[derive(Debug, Default)]
struct Status {
    cats: BTreeMap<String, (usize, u64)>,
    top10: Vec<(String, u64, String)>,
    /// Upstream's `total_tracked`: the web API reads it, the text table does not.
    #[allow(dead_code)]
    total: usize,
}

/// The library behind the plugin, bound to one home (`paths.data`) and one dry-run setting.
#[derive(Debug, Clone)]
struct Cleaner {
    home: PathBuf,
    dry_run: bool,
}

impl Cleaner {
    fn new(cfg: &Config, paths: &Paths) -> Cleaner {
        Cleaner {
            home: resolve(&paths.data).unwrap_or_else(|| paths.data.clone()),
            dry_run: crate::builtin::dry_run(cfg),
        }
    }

    /// `<home>/disk-cleanup/<name>` — deliberately outside `<home>/logs/` (`_state_file`).
    fn state_file(&self, name: &str) -> PathBuf {
        self.home.join("disk-cleanup").join(name)
    }

    /// Append to the audit log; never let it break the agent loop (`_log`).
    fn log(&self, message: &str) {
        let f = self.state_file("cleanup.log");
        if let Some(d) = f.parent() {
            let _ = fs::create_dir_all(d);
        }
        let t = unix_now();
        let (y, mo, d) = civil_from_days(t.div_euclid(86_400));
        let s = t.rem_euclid(86_400);
        if let Ok(mut fh) = fs::OpenOptions::new().create(true).append(true).open(&f) {
            let _ = writeln!(fh, "[{y:04}-{mo:02}-{d:02} {:02}:{:02}:{:02}] {message}", s / 3600, (s / 60) % 60, s % 60);
        }
    }

    // ── scope ──

    /// `is_safe_path`: only `<home>` or `<tmp>/seagent-*`, never a Windows mount or a system dir.
    fn is_safe_path(&self, path: &Path) -> bool {
        resolve(path).map(|r| self.in_scope(&r)).unwrap_or(false)
    }

    fn in_scope(&self, resolved: &Path) -> bool {
        if is_windows_mount(resolved) {
            return false;
        }
        if resolved.starts_with(&self.home) {
            return true;
        }
        tmp_roots().iter().any(|root| match resolved.strip_prefix(root) {
            Ok(rel) => rel.components().next().map(|c| c.as_os_str().to_string_lossy().starts_with("seagent-")).unwrap_or(false),
            Err(_) => false,
        })
    }

    /// Components of `path` relative to the home (empty when it is not under it).
    fn rel_parts(&self, resolved: &Path) -> Option<Vec<String>> {
        let rel = resolved.strip_prefix(&self.home).ok()?;
        Some(
            rel.components()
                .filter_map(|c| match c {
                    Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                    _ => None,
                })
                .collect(),
        )
    }

    /// A tracked DIRECTORY that is the home itself or lives under a protected top-level tree
    /// (`cache/terminal` holds terminal snapshots) is never `rmtree`'d (`_is_protected_dir`).
    fn is_protected_dir(&self, p: &Path) -> bool {
        if !p.is_dir() {
            return false;
        }
        let resolved = resolve(p).unwrap_or_else(|| p.to_path_buf());
        match self.rel_parts(&resolved) {
            Some(parts) => parts.first().map(|t| EMPTY_DIR_PROTECTED_TOP_LEVEL.contains(&t.as_str())).unwrap_or(true),
            None => false,
        }
    }

    /// EXACT cron control-plane paths, never deleted regardless of the stored category
    /// (`_protected_cron_paths`): `cron/` itself, its `output/` root, `jobs.json`, `.tick.lock`.
    /// Adapted to seagent: `cron`, `cronjobs` and the scheduler registry `schedules.json` /
    /// `cron_runs/` root. Never widen this to everything under `cron/output/` — run artifacts
    /// there are disposable, only wholesale deletion is fatal.
    fn is_protected_cron_path(&self, p: &Path) -> bool {
        let r = resolve(p).unwrap_or_else(|| p.to_path_buf());
        if r == self.home.join("schedules.json") || r == self.home.join("schedules.json.tmp") || r == self.home.join(".tick.lock") {
            return true;
        }
        for parent in ["cron", "cronjobs", "cron_runs"] {
            let base = self.home.join(parent);
            if [base.clone(), base.join("output"), base.join("jobs.json"), base.join(".tick.lock")].contains(&r) {
                return true;
            }
        }
        false
    }

    // ── tracked.json ──

    /// Load `tracked.json`, restoring from `.bak` on corruption (`load_tracked`).
    fn load_tracked(&self) -> Vec<Item> {
        let tf = self.state_file("tracked.json");
        if let Some(d) = tf.parent() {
            let _ = fs::create_dir_all(d);
        }
        if !tf.exists() {
            return Vec::new();
        }
        let parse = |p: &Path| -> Option<Vec<Item>> {
            let t = fs::read_to_string(p).ok()?;
            serde_json::from_str(t.trim_start_matches('\u{feff}')).ok()
        };
        if let Some(v) = parse(&tf) {
            return v;
        }
        if let Some(v) = parse(&self.state_file("tracked.json.bak")) {
            self.log("WARN: tracked.json corrupted — restored from .bak");
            return v;
        }
        self.log("WARN: tracked.json corrupted, no backup — starting fresh");
        Vec::new()
    }

    /// Atomic write: `.tmp` → backup old → rename (`save_tracked`).
    fn save_tracked(&self, tracked: &[Item]) {
        let tf = self.state_file("tracked.json");
        if let Some(d) = tf.parent() {
            let _ = fs::create_dir_all(d);
        }
        let tmp = self.state_file("tracked.json.tmp");
        let body = serde_json::to_string_pretty(tracked).unwrap_or_else(|_| "[]".into());
        if fs::write(&tmp, body).is_err() {
            return;
        }
        if tf.exists() {
            let _ = fs::copy(&tf, self.state_file("tracked.json.bak"));
        }
        let _ = fs::rename(&tmp, &tf);
    }

    /// Register a file for tracking (`track(..., silent=True)`). `Ok(line)` when newly tracked —
    /// upstream's stdout line — else `Err(reason)` after writing the same `SKIP`/`REJECT` audit line.
    fn track(&self, path_str: &str, category: &str) -> Result<String, String> {
        let category = if ALLOWED_CATEGORIES.contains(&category) {
            category
        } else {
            self.log(&format!("WARN: unknown category '{category}', using 'other'"));
            "other"
        };
        let Some(path) = resolve(&seagent_core::tool::expand_home(path_str)) else {
            self.log(&format!("REJECT: {path_str} (could not resolve path)"));
            return Err(format!("{path_str} (could not resolve path)"));
        };
        if !path.exists() {
            self.log(&format!("SKIP: {} (does not exist)", path.display()));
            return Err(format!("{} (does not exist)", path.display()));
        }
        if !self.is_safe_path(&path) {
            self.log(&format!("REJECT: {} (outside SEAGENT_HOME)", path.display()));
            return Err(format!("{} (outside SEAGENT_HOME)", path.display()));
        }
        let size = if path.is_file() { fs::metadata(&path).map(|m| m.len()).unwrap_or(0) } else { 0 };
        let mut tracked = self.load_tracked();
        let s = path.to_string_lossy().into_owned();
        if tracked.iter().any(|i| i.path == s) {
            return Err(format!("{s} (already tracked)"));
        }
        tracked.push(Item {
            path: s,
            timestamp: iso_of(unix_now()),
            category: category.to_string(),
            size,
        });
        self.save_tracked(&tracked);
        self.log(&format!("TRACKED: {} ({category}, {})", path.display(), fmt_size(size)));
        Ok(format!("Tracked: {} ({category}, {})", path.display(), fmt_size(size)))
    }

    /// Remove a path from tracking without deleting the file (`forget`). Returns entries removed.
    fn forget(&self, path_str: &str) -> usize {
        let p = resolve(&seagent_core::tool::expand_home(path_str)).unwrap_or_else(|| PathBuf::from(path_str));
        let tracked = self.load_tracked();
        let (kept, removed): (Vec<Item>, Vec<Item>) = tracked.into_iter().partition(|i| resolve(Path::new(&i.path)).unwrap_or_else(|| PathBuf::from(&i.path)) != p);
        if !removed.is_empty() {
            self.save_tracked(&kept);
            self.log(&format!("FORGOT: {} ({} entries)", p.display(), removed.len()));
        }
        removed.len()
    }

    // ── classification ──

    /// Category label for a path, or `None` when it must not be tracked (`guess_category`).
    fn guess_category(&self, path: &Path) -> Option<&'static str> {
        let resolved = resolve(path)?;
        if !self.in_scope(&resolved) {
            return None;
        }
        if let Some(parts) = self.rel_parts(&resolved) {
            let top = parts.first().map(String::as_str).unwrap_or("");
            if NEVER_TRACK_TOP_LEVEL.contains(&top) || self.is_protected_dir(&resolved) {
                return None;
            }
            if matches!(top, "cron" | "cronjobs") {
                // Only the disposable `output/` subtree; control-plane state (jobs.json,
                // .tick.lock) must never be tracked — deleting it wipes the scheduler registry.
                return (parts.len() >= 3 && parts[1] == "output").then_some("cron-output");
            }
            if top == "cron_runs" {
                // seagent keeps run artifacts as `cron_runs/<job>.jsonl` (upstream `cron/output/*`).
                return (parts.len() >= 2 && resolved.is_file()).then_some("cron-output");
            }
            if top == "cache" || top == "tmp" {
                // `cache/` is upstream's transient area; `tmp/` is seagent's in-home scratch dir.
                return Some("temp");
            }
        }
        let name = path.file_name()?.to_string_lossy().into_owned();
        if TEST_PATTERNS.iter().any(|p| name.starts_with(p)) || TEST_SUFFIXES.iter().any(|s| name.ends_with(s)) {
            // Git-owned trees manage their own files: never classify a test_* there as disposable.
            return if self.inside_git_worktree(&resolved) { None } else { Some("test") };
        }
        None
    }

    /// `git -C <dir> ls-files --error-unmatch -- :(literal)<name>` (`_git_tracks`): the enclosing
    /// repo actually tracks this file. `:(literal)` stops git globbing the name. Git missing, not a
    /// repo, or untracked all mean "not tracked".
    fn git_tracks(&self, path: &Path) -> bool {
        let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
            return false;
        };
        let out = std::process::Command::new("git")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .arg("-C")
            .arg(dir)
            .args(["ls-files", "--error-unmatch", "--"])
            .arg(format!(":(literal){}", name.to_string_lossy()))
            .output();
        out.map(|o| o.status.success()).unwrap_or(false)
    }

    /// `_inside_git_worktree`: a `.git` entry on the directory chain BELOW the home means Git owns
    /// the tree (a normal checkout has a directory, a linked worktree a pointer file); an enclosing
    /// repo (the home itself or one above it) only counts when it actually tracks the file.
    fn inside_git_worktree(&self, path: &Path) -> bool {
        let resolved = resolve(path).unwrap_or_else(|| path.to_path_buf());
        let mut below: Vec<&Path> = Vec::new();
        let mut above: Vec<&Path> = Vec::new();
        for (n, parent) in resolved.ancestors().enumerate() {
            if parent == self.home {
                above.extend(resolved.ancestors().skip(n));
                break;
            }
            below.push(parent);
        }
        if below.iter().any(|p| p.join(".git").exists()) {
            return true;
        }
        above.iter().any(|p| p.join(".git").exists()) && self.git_tracks(&resolved)
    }

    // ── rules ──

    /// Entries whose path still exists, with their age in days (`_live_items`).
    fn live_items(&self, log_stale: bool) -> Vec<(Item, PathBuf, i64)> {
        let now = unix_now();
        let mut out = Vec::new();
        for item in self.load_tracked() {
            let p = PathBuf::from(&item.path);
            if p.exists() {
                let age = parse_iso(&item.timestamp).map(|t| days_between(now, t)).unwrap_or(0);
                out.push((item, p, age));
            } else if log_stale {
                self.log(&format!("STALE: {} (removed from tracking)", p.display()));
            }
        }
        out
    }

    /// `_is_auto_delete`: nothing prompts for these.
    fn is_auto_delete(cat: &str, age: i64) -> bool {
        cat == "test" || (cat == "temp" && age > 7) || (cat == "cron-output" && age > 14)
    }

    /// `_prompt_group`: `research` / `chrome` / `large`, or `None`.
    fn prompt_group(item: &Item, age: i64) -> Option<&'static str> {
        match item.category.as_str() {
            "research" if age > 30 => Some("research"),
            "chrome-profile" if age > 14 => Some("chrome"),
            _ if item.size > LARGE_FILE_BYTES => Some("large"),
            _ => None,
        }
    }

    /// `dry_run()`: (auto-delete list, needs-prompt list) without touching files.
    fn dry_run_lists(&self) -> (Vec<Item>, Vec<Item>) {
        let (mut auto, mut prompt) = (Vec::new(), Vec::new());
        for (item, p, age) in self.live_items(false) {
            let cat = item.category.as_str();
            // Stale cron-output entries and protected dirs are skipped by quick(); omit them here.
            if (cat == "cron-output" && self.guess_category(&p) != Some("cron-output")) || self.is_protected_dir(&p) {
                continue;
            }
            if Self::is_auto_delete(cat, age) {
                auto.push(item);
            } else if Self::prompt_group(&item, age).is_some() {
                prompt.push(item);
            }
        }
        (auto, prompt)
    }

    /// Delete a tracked file/dir and audit-log it (`_delete_item`).
    fn delete_item(&self, item: &Item) -> Result<(), String> {
        let p = PathBuf::from(&item.path);
        let r = if p.is_file() {
            fs::remove_file(&p)
        } else if p.is_dir() {
            fs::remove_dir_all(&p)
        } else {
            Ok(())
        };
        match r {
            Err(e) => {
                self.log(&format!("ERROR deleting {}: {e}", p.display()));
                Err(format!("{}: {e}", p.display()))
            }
            Ok(()) => {
                self.log(&format!("DELETED: {} ({}, {})", p.display(), item.category, fmt_size(item.size)));
                Ok(())
            }
        }
    }

    /// Safe deterministic cleanup, no prompts (`quick()`).
    fn quick(&self) -> Quick {
        let mut q = Quick {
            dry_run: self.dry_run,
            ..Default::default()
        };
        let mut kept: Vec<Item> = Vec::new();
        for (item, p, age) in self.live_items(!self.dry_run) {
            let cat = item.category.clone();
            // Stored categories re-validated: an old entry may say `test` for a file under a
            // protected tree or `cron-output` for a control-plane file. Drop it, don't delete it.
            if matches!(cat.as_str(), "cron-output" | "test") {
                let re = self.guess_category(&p);
                if re != Some(cat.as_str()) {
                    let note = if cat == "test" { " — under protected tree" } else { "" };
                    self.log(&format!("SKIP stale {cat} entry: {} (re-classified as {}{note})", p.display(), py_repr(re)));
                    continue;
                }
            }
            // Hard safety net even if re-validation above somehow let it through.
            if self.is_protected_cron_path(&p) {
                self.log(&format!("SKIP protected cron path: {}", p.display()));
                continue;
            }
            if self.is_protected_dir(&p) {
                self.log(&format!("SKIPPED: {} (protected top-level dir)", p.display()));
                continue;
            }
            if !Self::is_auto_delete(&cat, age) {
                kept.push(item);
                continue;
            }
            if self.dry_run {
                self.log(&format!("DRY_RUN: would delete {} ({}, {})", p.display(), cat, fmt_size(item.size)));
                q.deleted += 1;
                q.freed += item.size;
                kept.push(item);
                continue;
            }
            match self.delete_item(&item) {
                Ok(()) => {
                    q.freed += item.size;
                    q.deleted += 1;
                }
                Err(e) => {
                    q.errors.push(e);
                    kept.push(item);
                }
            }
        }
        q.empty_dirs = self.sweep_empty_dirs(!self.dry_run);
        if self.dry_run {
            self.log(&format!("QUICK_SUMMARY (dry run): would delete {} files ({}), {} dirs", q.deleted, fmt_size(q.freed), q.empty_dirs));
        } else {
            self.save_tracked(&kept);
            self.log(&format!("QUICK_SUMMARY: {} files, {} dirs, {}", q.deleted, q.empty_dirs, fmt_size(q.freed)));
        }
        q
    }

    /// Subdirectories of `dir` that are not symlinks and not in `exclude` (`_subdirs`).
    fn subdirs(&self, dir: &Path, exclude: &[&str]) -> Vec<PathBuf> {
        let Ok(rd) = fs::read_dir(dir) else {
            return Vec::new();
        };
        rd.filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir() && !p.is_symlink() && !exclude.contains(&p.file_name().unwrap_or_default().to_string_lossy().as_ref()))
            .collect()
    }

    /// Remove empty dirs under the home without recursing into durable/heavy trees
    /// (`_sweep_empty_dirs`); iterative post-order so parents emptied by child removal are caught.
    /// `remove == false` only counts what a dry run would remove.
    fn sweep_empty_dirs(&self, remove: bool) -> usize {
        let mut removed = 0;
        let mut tops = EMPTY_DIR_PROTECTED_TOP_LEVEL.to_vec();
        tops.extend_from_slice(EMPTY_DIR_SWEEP_PRUNE_DIRS);
        let mut stack: Vec<(PathBuf, bool)> = self.subdirs(&self.home, &tops).into_iter().map(|p| (p, false)).collect();
        while let Some((dir, visited)) = stack.pop() {
            if visited {
                let empty = fs::read_dir(&dir).map(|mut it| it.next().is_none()).unwrap_or(false);
                if !empty {
                    continue;
                }
                if !remove {
                    removed += 1;
                } else if fs::remove_dir(&dir).is_ok() {
                    removed += 1;
                    self.log(&format!("DELETED: {} (empty dir)", dir.display()));
                }
                continue;
            }
            stack.push((dir.clone(), true));
            for child in self.subdirs(&dir, EMPTY_DIR_SWEEP_PRUNE_DIRS) {
                stack.push((child, false));
            }
        }
        removed
    }

    /// `status()`: per-category breakdown and the top 10 largest tracked files.
    fn status(&self) -> Status {
        let tracked = self.load_tracked();
        let mut s = Status {
            total: tracked.len(),
            ..Default::default()
        };
        for item in &tracked {
            let e = s.cats.entry(item.category.clone()).or_insert((0, 0));
            e.0 += 1;
            e.1 += item.size;
        }
        let mut existing: Vec<(String, u64, String)> = tracked.iter().filter(|i| Path::new(&i.path).exists()).map(|i| (i.path.clone(), i.size, i.category.clone())).collect();
        existing.sort_by_key(|a| std::cmp::Reverse(a.1));
        existing.truncate(10);
        s.top10 = existing;
        s
    }

    /// `format_status`: the `Category / Files / Size` table and `Top 10 largest tracked files:`.
    fn format_status(&self, s: &Status) -> String {
        let mut lines = vec![format!("{:<20} {:>6}  {:>10}", "Category", "Files", "Size"), "-".repeat(40)];
        let mut cats: Vec<(&String, &(usize, u64))> = s.cats.iter().collect();
        cats.sort_by_key(|a| std::cmp::Reverse(a.1 .1));
        for (cat, (count, size)) in &cats {
            lines.push(format!("{:<20} {:>6}  {:>10}", cat, count, fmt_size(*size)));
        }
        if cats.is_empty() {
            lines.push("(nothing tracked yet)".into());
        }
        lines.push(String::new());
        lines.push("Top 10 largest tracked files:".into());
        if s.top10.is_empty() {
            lines.push("  (none)".into());
        }
        for (rank, (path, size, cat)) in s.top10.iter().enumerate() {
            lines.push(format!("  {:>2}. {:>8}  [{}]  {}", rank + 1, fmt_size(*size), cat, path));
        }
        lines.join("\n")
    }

    // ── slash / tool surface ──

    /// `_handle_slash`: `help` / no args → the help text, else the subcommand handler.
    fn handle_slash(&self, raw: &str) -> String {
        self.handle_args(&raw.split_whitespace().collect::<Vec<_>>())
    }

    /// The same dispatch on pre-split arguments — the tool passes `path` as one argument, so a
    /// path containing spaces survives (the slash surface splits on whitespace, as upstream does).
    fn handle_args(&self, argv: &[&str]) -> String {
        match argv.first().copied() {
            None | Some("help" | "-h" | "--help") => HELP.to_string(),
            Some("status") => self.format_status(&self.status()),
            Some("dry-run") => self.cmd_dry_run(),
            Some("quick") => fmt_summary(&self.quick()),
            Some("deep") => self.cmd_deep(),
            Some("track") => self.cmd_track(argv),
            Some("forget") => self.cmd_forget(argv),
            Some(other) => format!("Unknown subcommand: {other}\n\n{HELP}"),
        }
    }

    fn cmd_dry_run(&self) -> String {
        let (auto, prompt) = self.dry_run_lists();
        let mut lines = vec!["Dry-run preview (nothing deleted):".to_string()];
        lines.extend(item_block("  Auto-delete : {n} files ({size})", &auto, "    "));
        lines.extend(item_block("  Needs prompt: {n} files ({size})", &prompt, "    "));
        let total = auto.iter().chain(prompt.iter()).map(|i| i.size).sum();
        lines.push(format!("\n  Total potential: {}", fmt_size(total)));
        lines.join("\n")
    }

    fn cmd_deep(&self) -> String {
        // In-session deep can't prompt — show what quick cleaned plus items needing confirmation.
        let q = self.quick();
        let (_, prompt) = self.dry_run_lists();
        let mut lines = vec![fmt_summary(&q)];
        if !prompt.is_empty() {
            lines.extend(item_block("\n{n} item(s) need confirmation ({size}):", &prompt, "  "));
            lines.push("\nRun `/disk-cleanup forget <path>` to skip, or delete manually via shell.".into());
        }
        lines.join("\n")
    }

    fn cmd_track(&self, argv: &[&str]) -> String {
        if argv.len() < 3 {
            return "Usage: /disk-cleanup track <path> <category>".into();
        }
        let (path_arg, category) = (argv[1], argv[2]);
        if !ALLOWED_CATEGORIES.contains(&category) {
            return format!("Unknown category '{category}'. Allowed: {}", py_list(ALLOWED_CATEGORIES));
        }
        match self.track(path_arg, category) {
            Ok(_) => format!("Tracked {path_arg} as '{category}'."),
            Err(_) => {
                format!("Not tracked (already present, missing, or outside SEAGENT_HOME): {path_arg}")
            }
        }
    }

    fn cmd_forget(&self, argv: &[&str]) -> String {
        if argv.len() < 2 {
            return "Usage: /disk-cleanup forget <path>".into();
        }
        let n = self.forget(argv[1]);
        if n == 0 {
            format!("Not found in tracking: {}", argv[1])
        } else {
            format!("Removed {n} tracking entr{} for {}.", if n == 1 { "y" } else { "ies" }, argv[1])
        }
    }
}

/// ``header`` with `{n}` / `{size}` filled in, then one line per item (`_item_block`).
fn item_block(header: &str, items: &[Item], indent: &str) -> Vec<String> {
    let size = fmt_size(items.iter().map(|i| i.size).sum());
    let mut v = vec![header.replace("{n}", &items.len().to_string()).replace("{size}", &size)];
    v.extend(items.iter().map(|i| format!("{indent}[{}] {}", i.category, i.path)));
    v
}

/// `_fmt_summary`: one line, plus the error tail. A dry run says so instead of "Cleaned".
fn fmt_summary(q: &Quick) -> String {
    let mut base = if q.dry_run {
        format!(
            "[disk-cleanup] Dry run — nothing deleted: would clean {} files + {} empty dirs, freeing {}.",
            q.deleted,
            q.empty_dirs,
            fmt_size(q.freed)
        )
    } else {
        format!("[disk-cleanup] Cleaned {} files + {} empty dirs, freed {}.", q.deleted, q.empty_dirs, fmt_size(q.freed))
    };
    if !q.errors.is_empty() {
        base.push_str(&format!("\n  {} error(s); see cleanup.log.", q.errors.len()));
    }
    base
}

/// `_HELP_TEXT` (`Hermes` → `seagent`, `HERMES_HOME` → `SEAGENT_HOME`).
const HELP: &str = "\
/disk-cleanup — ephemeral-file cleanup

Subcommands:
  status                     Per-category breakdown + top-10 largest
  dry-run                    Preview what quick/deep would delete
  quick                      Run safe cleanup now (no prompts)
  deep                       Run quick, then list items that need prompts
  track <path> <category>    Manually add a path to tracking
  forget <path>              Stop tracking a path (does not delete)

Categories: temp | test | research | download | chrome-profile | cron-output | other

All operations are scoped to SEAGENT_HOME and /tmp/seagent-*.
Test files are auto-tracked on write / shell and auto-cleaned at session end.";

// ───────────────────────── tool ─────────────────────────

/// The `disk_cleanup` tool (status / dry-run / quick / deep / track / forget).
pub fn tools(cfg: &Config, paths: &Paths) -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(DiskCleanupTool(Cleaner::new(cfg, paths)))]
}

struct DiskCleanupTool(Cleaner);

impl Tool for DiskCleanupTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "disk_cleanup".into(),
            description: "Track and clean up ephemeral files created during this session (test scripts, temp outputs, cron logs). action=status: per-category breakdown + top-10 largest tracked; dry-run: preview what quick/deep would delete; quick: safe cleanup now (no prompts); deep: quick, then list items needing confirmation; track: add `path` with `category`; forget: stop tracking `path` (does not delete). Scoped to SEAGENT_HOME and /tmp/seagent-*.".into(),
            input_schema: json!({"type":"object","properties":{
                "action":{"type":"string","enum":["status","dry-run","quick","deep","track","forget"]},
                "path":{"type":"string","description":"File or directory (track / forget)"},
                "category":{"type":"string","enum":["temp","test","research","download","chrome-profile","cron-output","other"],"description":"Category (track)"}},
                "required":["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    /// No gate effects: every path is confined to the home or `/tmp/seagent-*` by `is_safe_path`, and
    /// upstream asks for no confirmation for the auto-delete categories.
    fn effects(&self, _ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        Vec::new()
    }
    fn call(&self, _ctx: &ToolCtx, input: Value) -> ToolOutput {
        let action = input.get("action").and_then(Value::as_str).unwrap_or("").trim().to_string();
        if action.is_empty() {
            return ToolOutput::err(format!("missing `action`: status, dry-run, quick, deep, track or forget\n\n{HELP}"));
        }
        // Structured args, not a re-split command line: a path may contain spaces.
        let path = input.get("path").and_then(Value::as_str).filter(|s| !s.is_empty());
        let category = input.get("category").and_then(Value::as_str).filter(|s| !s.is_empty());
        let mut argv = vec![action.as_str()];
        argv.extend(path);
        argv.extend(category);
        ToolOutput::ok(self.0.handle_args(&argv))
    }
}

// ───────────────────────── slash ─────────────────────────

/// `/disk-cleanup <status|dry-run|quick|deep|track|forget>`.
pub fn slash(cfg: &Config, paths: &Paths) -> impl Slash {
    DiskCleanupSlash(Cleaner::new(cfg, paths))
}

struct DiskCleanupSlash(Cleaner);

impl Slash for DiskCleanupSlash {
    fn commands(&self) -> Vec<(String, String)> {
        vec![("disk-cleanup".into(), "Track and clean up ephemeral seagent session files.".into())]
    }
    fn run(&self, _ctx: &SlashCtx, name: &str, args: &str) -> Option<Result<SlashReply, String>> {
        (name == "disk-cleanup").then(|| Ok(SlashReply::text(self.0.handle_slash(args))))
    }
}

// ───────────────────────── hooks ─────────────────────────

#[derive(Default)]
struct HookState {
    /// (session, tool-input digest) → (snapshot time, argument paths absent before the call).
    pre: HashMap<(String, String), (i64, BTreeSet<String>)>,
    /// Sessions that tracked at least one `test` file this turn.
    recent_tests: HashMap<String, BTreeSet<String>>,
}

/// `pre_tool` / `post_tool` / `session_end` tracking and cleanup.
pub struct CleanupHook {
    c: Cleaner,
    state: Mutex<HookState>,
}

impl CleanupHook {
    pub fn new(cfg: &Config, paths: &Paths) -> CleanupHook {
        CleanupHook {
            c: Cleaner::new(cfg, paths),
            state: Mutex::new(HookState::default()),
        }
    }

    /// Snapshot which argument paths are absent before the call; post tracks only those, so
    /// pre-existing files and paths swapped in after the snapshot fail closed.
    fn pre_tool(&self, payload: &Value) {
        let Some(tool) = payload.get("tool_name").and_then(Value::as_str) else {
            return;
        };
        let Some(input) = payload.get("tool_input").filter(|v| v.is_object()) else {
            return;
        };
        let Some(paths) = extract_paths(tool, input) else {
            return;
        };
        let now = unix_now();
        let absent: BTreeSet<String> = paths
            .iter()
            .filter_map(|s| {
                let p = seagent_core::tool::expand_home(s);
                (!p.exists()).then(|| p.to_string_lossy().into_owned())
            })
            .collect();
        let Ok(mut st) = self.state.lock() else {
            return;
        };
        st.pre.retain(|_, (taken, _)| now - *taken <= PRE_CALL_TTL_SECS);
        st.pre.insert((session_of(payload), call_key(tool, input)), (now, absent));
    }

    /// Auto-track ephemeral files THIS call created: a path from the call's final arguments that
    /// its own pre-call snapshot saw absent and that exists now.
    fn post_tool(&self, payload: &Value) {
        let Some(tool) = payload.get("tool_name").and_then(Value::as_str) else {
            return;
        };
        let Some(input) = payload.get("tool_input").filter(|v| v.is_object()) else {
            return;
        };
        let Some(paths) = extract_paths(tool, input) else {
            return;
        };
        let absent = match self.state.lock() {
            Ok(mut st) => st.pre.remove(&(session_of(payload), call_key(tool, input))).map(|(_, a)| a).unwrap_or_default(),
            Err(_) => return,
        };
        if absent.is_empty() {
            return;
        }
        let mut test_paths: Vec<String> = Vec::new();
        for path_str in paths {
            let p = seagent_core::tool::expand_home(&path_str);
            let s = p.to_string_lossy().into_owned();
            if !absent.contains(&s) || !p.exists() {
                continue;
            }
            let Some(category) = self.c.guess_category(&p) else {
                continue;
            };
            if self.c.track(&s, category).is_ok() && category == "test" {
                test_paths.push(s);
            }
        }
        if test_paths.is_empty() {
            return;
        }
        if let Ok(mut st) = self.state.lock() {
            st.recent_tests.entry(session_of(payload)).or_default().extend(test_paths);
        }
    }

    /// Run `quick` when any test files were tracked this turn (drain the session bucket plus every
    /// task-scoped bucket — sub-agents record into their own).
    fn session_end(&self, payload: &Value) {
        let session = session_of(payload);
        let had = match self.state.lock() {
            Ok(mut st) => {
                let drained = st.recent_tests.remove(&session).map(|s| !s.is_empty()).unwrap_or(false);
                let had = drained || !st.recent_tests.is_empty();
                st.recent_tests.clear();
                had
            }
            Err(_) => return,
        };
        if !had {
            return;
        }
        let q = self.c.quick();
        if q.deleted > 0 || q.empty_dirs > 0 {
            self.c
                .log(&format!("AUTO_QUICK (session_end): deleted={} dirs={} freed={}", q.deleted, q.empty_dirs, fmt_size(q.freed)));
        }
    }

    /// One event; every failure is swallowed (hooks must never block a tool).
    fn handle(&self, event: HookEvent, payload: &Value) {
        match event {
            HookEvent::PreTool => self.pre_tool(payload),
            HookEvent::PostTool => self.post_tool(payload),
            HookEvent::SessionEnd => self.session_end(payload),
            _ => {}
        }
    }
}

impl Hook for CleanupHook {
    fn name(&self) -> String {
        "builtin:disk-cleanup".into()
    }
    fn wants(&self, event: HookEvent, tool: Option<&str>) -> bool {
        match event {
            HookEvent::PreTool | HookEvent::PostTool => tool.is_some_and(extracts),
            HookEvent::SessionEnd => true,
            _ => false,
        }
    }
    fn run(&self, event: HookEvent, payload: &Value) -> Result<HookDecision, String> {
        self.handle(event, payload);
        Ok(HookDecision::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::tool::SpawnRequest;
    use seagent_core::{Cancel, Provider};

    // ── fixtures ──

    fn root(tag: &str) -> PathBuf {
        let d = seagent_core::tmp::scratch_path(format!("seagent-disk-cleanup-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("data")).unwrap();
        d
    }

    fn paths_of(d: &Path) -> Paths {
        Paths {
            data: d.join("data"),
            config_dir: d.join("cfg"),
            runtime: d.join("run"), ..Default::default()
        }
    }

    fn cleaner(tag: &str) -> (Cleaner, Paths) {
        let d = root(tag);
        let paths = paths_of(&d);
        (Cleaner::new(&Config::default(), &paths), paths)
    }

    fn dry_cleaner(tag: &str) -> (Cleaner, Paths) {
        let d = root(tag);
        let paths = paths_of(&d);
        let mut cfg = Config::default();
        cfg.builtin_plugins
            .insert("disk-cleanup".into(), toml::Value::Table(toml::Table::from_iter([("dry_run".to_string(), toml::Value::Boolean(true))])));
        (Cleaner::new(&cfg, &paths), paths)
    }

    fn write(p: &Path, body: &str) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn log_text(c: &Cleaner) -> String {
        fs::read_to_string(c.state_file("cleanup.log")).unwrap_or_default()
    }

    fn iso_days_ago(days: i64) -> String {
        iso_of(unix_now() - days * 86_400)
    }

    struct NoProvider;
    impl seagent_kernel::kernel::Resolver for NoProvider {
        fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    struct NoHost;
    impl seagent_core::ToolHost for NoHost {
        fn spawn_agent(&self, _: SpawnRequest, _: &Cancel) -> Result<String, String> {
            Err("no sub-agents in this test".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("nobody to ask".into())
        }
    }

    fn tool_ctx(paths: &Paths) -> ToolCtx {
        ToolCtx {
            workspace: paths.data.clone(),
            session_id: "s1".into(),
            artifacts: paths.data.join("art"),
            home: paths.data.clone(),
            cancel: Cancel::new(),
            host: Arc::new(NoHost),
            secrets: Arc::new(|s: &str| s.to_string()),
        }
    }

    fn slash_ctx(paths: &Paths) -> SlashCtx {
        let mut cfg = Config::default();
        cfg.model.default = "fake/m".into();
        let k = seagent_kernel::kernel::new_kernel(
            cfg,
            paths.clone(),
            Arc::new(NoProvider),
            vec![],
            Arc::new(seagent_kernel::vault::Vault::empty()),
            Arc::new(seagent_kernel::approver::Policy {
                allow_privilege: false,
                allow_egress: false,
            }),
        );
        SlashCtx {
            kernel: k,
            session: Some("s1".into()),
            surface: "cli".into(),
        }
    }

    // ── tests ──

    #[test]
    fn tracks_and_cleans_test_files() {
        let (c, paths) = cleaner("track-clean");
        let f = paths.data.join("scratch/test_generated.py");
        write(&f, "print(1)");
        assert_eq!(c.guess_category(&f), Some("test"), "name rule inside the home");
        let msg = c.track(f.to_str().unwrap(), "test").unwrap();
        assert!(msg.starts_with(&format!("Tracked: {} (test, 8.0 B)", f.canonicalize().unwrap().display())), "{msg}");
        assert_eq!(c.load_tracked().len(), 1);
        assert_eq!(c.load_tracked()[0].size, 8, "byte size recorded from the file");
        assert!(c.track(f.to_str().unwrap(), "test").is_err(), "already tracked stays single");
        assert_eq!(c.load_tracked().len(), 1);

        let q = c.quick();
        assert_eq!((q.deleted, q.freed, q.dry_run), (1, 8, false));
        assert!(!f.exists(), "test files are deleted at age 0");
        assert!(c.load_tracked().is_empty(), "deleted entries leave the state file");
        let log = log_text(&c);
        assert!(log.contains("TRACKED: ") && log.contains("DELETED: ") && log.contains("QUICK_SUMMARY: 1 files"), "{log}");

        // `test_*`, `tmp_*` and `*.test.*` names, and the `.test.*` suffixes, all classify as test.
        for rel in ["scratch/tmp_run.sh", "scratch/thing.test.py", "scratch/a.test.js", "scratch/b.test.ts", "scratch/c.test.md"] {
            let p = paths.data.join(rel);
            write(&p, "x");
            assert_eq!(c.guess_category(&p), Some("test"), "{rel}");
        }
        // A plain name is never classified.
        let plain = paths.data.join("scratch/report.txt");
        write(&plain, "x");
        assert_eq!(c.guess_category(&plain), None);
    }

    #[test]
    fn protected_and_unsafe_paths_are_never_tracked() {
        let d = root("protect");
        let paths = paths_of(&d);
        let c = Cleaner::new(&Config::default(), &paths);
        let h = paths.data.clone();
        for rel in [
            "logs/test_a.py",
            "sessions/2026/test_a.py",
            "memory/tmp_x.md",
            "skills/test_s/SKILL.md",
            "plugins/test_p/x.py",
            "workspace/proj/test_x.py",
            "projects/p/tmp_y.py",
            "backups/b/test_z.py",
            "disk-cleanup/test_z.py",
            "scripts/test_cron.py",
            "approvals/test_apr.json",
        ] {
            let p = h.join(rel);
            write(&p, "x");
            assert_eq!(c.guess_category(&p), None, "{rel} is control plane / user tree");
        }
        // Cron control plane is never classified; cron *output* is disposable.
        write(&h.join("cron/jobs.json"), "{}");
        assert_eq!(c.guess_category(&h.join("cron/jobs.json")), None);
        let run = h.join("cron/output/night/run.log");
        write(&run, "log");
        assert_eq!(c.guess_category(&run), Some("cron-output"));
        let cron_runs = h.join("cron_runs/nightly.jsonl");
        write(&cron_runs, "{}");
        assert_eq!(c.guess_category(&cron_runs), Some("cron-output"), "seagent keeps run logs in cron_runs/");
        // `cache/` files age out as temp; `cache/` subdirs are protected.
        let cached = h.join("cache/build.log");
        write(&cached, "log");
        assert_eq!(c.guess_category(&cached), Some("temp"));
        fs::create_dir_all(h.join("cache/terminal")).unwrap();
        assert_eq!(c.guess_category(&h.join("cache/terminal")), None, "protected dir, never tracked");

        // Out of scope: system dirs, temp dirs that are not `seagent-*`, Windows mounts.
        assert_eq!(c.guess_category(Path::new("/etc/test_x.py")), None);
        let outside = seagent_core::tmp::scratch_path(format!("not-seagent-disk-cleanup-{}/test_x.py", std::process::id()));
        write(&outside, "x");
        assert_eq!(c.guess_category(&outside), None, "a temp dir not named `seagent-*` is out of scope");
        assert!(!c.is_safe_path(Path::new("/mnt/c/Users/x/test_a.py")));
        // In scope: `<home>` itself and `/tmp/seagent-*`.
        assert!(c.is_safe_path(&h.join("scratch/test_new.py")));
        assert!(c.is_safe_path(&seagent_core::tmp::scratch_path("seagent-scope-probe/test_x.py")));
        assert!(!c.is_safe_path(&seagent_core::tmp::scratch_path("notseagent-scope-probe/test_x.py")));

        // Explicit tracking refuses out-of-scope and missing paths, and audits both.
        assert!(c.track(outside.to_str().unwrap(), "test").is_err());
        assert!(log_text(&c).contains("REJECT: ") && log_text(&c).contains("(outside SEAGENT_HOME)"));
        assert!(c.track(h.join("scratch/test_missing.py").to_str().unwrap(), "test").is_err());
        assert!(log_text(&c).contains("(does not exist)"));
        let _ = fs::remove_dir_all(outside.parent().unwrap());

        // quick() never deletes the cron registry, even when a stale entry says `test`.
        assert!(c.track(h.join("cron/jobs.json").to_str().unwrap(), "test").is_ok());
        let q = c.quick();
        assert_eq!(q.deleted, 0);
        assert!(h.join("cron/jobs.json").exists(), "control plane survives quick()");
        assert!(log_text(&c).contains("SKIP stale test entry"), "{}", log_text(&c));
        assert!(c.load_tracked().is_empty(), "the stale entry is dropped, not kept");
    }

    #[test]
    fn dry_run_deletes_nothing() {
        let (c, paths) = dry_cleaner("dry");
        assert!(c.dry_run, "`[builtin_plugins.disk-cleanup] dry_run = true`");
        let f = paths.data.join("scratch/test_dry.py");
        write(&f, "abc");
        c.track(f.to_str().unwrap(), "test").unwrap();
        let q = c.quick();
        assert!(q.dry_run && q.deleted == 1 && q.freed == 3);
        assert!(f.exists(), "nothing is deleted");
        assert_eq!(c.load_tracked().len(), 1, "tracking is left alone");
        assert!(fmt_summary(&q).starts_with("[disk-cleanup] Dry run — nothing deleted: would clean 1 files + "), "{}", fmt_summary(&q));
        assert!(fmt_summary(&q).ends_with("freeing 3.0 B."), "{}", fmt_summary(&q));

        let empty = paths.data.join("scratch/deep/empty");
        fs::create_dir_all(&empty).unwrap();
        let q = c.quick();
        assert!(q.empty_dirs >= 1, "dry run counts the dirs it would sweep");
        assert!(empty.exists() && empty.parent().unwrap().exists(), "empty dirs survive a dry run");
        assert!(log_text(&c).contains("QUICK_SUMMARY (dry run): would delete 1 files (3.0 B)"), "{}", log_text(&c));

        // deep reports through the same wording, and /disk-cleanup quick too.
        assert!(c.handle_slash("deep").starts_with("[disk-cleanup] Dry run — nothing deleted: would clean 1 files + "));
        assert!(c.handle_slash("quick").starts_with("[disk-cleanup] Dry run — nothing deleted: "));
        assert!(f.exists());
    }

    #[test]
    fn empty_dirs_swept_but_protected_trees_kept() {
        let (c, paths) = cleaner("sweep");
        let h = paths.data.clone();
        let scratch = h.join("scratch/a/b/c");
        fs::create_dir_all(&scratch).unwrap();
        for rel in ["logs/empty/inner", "sessions/s1/empty", "cache/term/empty", "workspace/proj/empty"] {
            fs::create_dir_all(h.join(rel)).unwrap();
        }
        write(&h.join("scratch/keep.txt"), "x");
        let q = c.quick();
        assert_eq!(q.empty_dirs, 3, "scratch/a/b/c, a/b and a; scratch/ itself still holds keep.txt");
        assert!(!scratch.exists() && !h.join("scratch/a").exists());
        assert!(h.join("scratch").exists(), "a non-empty dir is kept");
        for rel in ["logs/empty/inner", "sessions/s1/empty", "cache/term/empty", "workspace/proj/empty"] {
            assert!(h.join(rel).exists(), "protected tree {rel} is never swept");
        }
        assert!(log_text(&c).contains("(empty dir)"));
        assert!(h.join("disk-cleanup").exists(), "the plugin's own state dir is never swept");
    }

    #[test]
    fn hook_tracks_created_path_and_session_end_cleans() {
        let d = root("hook");
        let paths = paths_of(&d);
        let cfg = Config::default();
        let hook = CleanupHook::new(&cfg, &paths);
        assert_eq!(hook.name(), "builtin:disk-cleanup");
        assert!(hook.wants(HookEvent::PreTool, Some("write")) && hook.wants(HookEvent::PostTool, Some("shell")));
        assert!(!hook.wants(HookEvent::PreTool, Some("read")) && hook.wants(HookEvent::SessionEnd, None));

        // A file the call created is tracked; a file that already existed is not.
        let fresh = paths.data.join("scratch/test_hook.py");
        let payload = json!({"session_id": "s1", "tool_name": "write", "tool_input": {"path": fresh.to_str().unwrap(), "content": "x"}});
        let _ = hook.run(HookEvent::PreTool, &payload).unwrap();
        assert!(Cleaner::new(&cfg, &paths).load_tracked().is_empty(), "pre only snapshots, it tracks nothing");
        write(&fresh, "x");
        let _ = hook.run(HookEvent::PostTool, &payload).unwrap();

        let existing = paths.data.join("scratch/test_preexisting.py");
        write(&existing, "x");
        let p2 = json!({"session_id": "s1", "tool_name": "write", "tool_input": {"path": existing.to_str().unwrap(), "content": "y"}});
        let _ = hook.run(HookEvent::PreTool, &p2).unwrap();
        let _ = hook.run(HookEvent::PostTool, &p2).unwrap();

        let items = Cleaner::new(&cfg, &paths).load_tracked();
        assert_eq!(items.len(), 1, "{items:?}");
        assert_eq!((items[0].category.as_str(), items[0].path.as_str()), ("test", fresh.canonicalize().unwrap().to_str().unwrap()));

        // A post hook whose pre snapshot is missing (blocked call) tracks nothing; neither does a
        // path that only appears after the snapshot (another hook's `modify` swapped it in).
        let orphan = paths.data.join("scratch/test_orphan.py");
        write(&orphan, "x");
        let _ = hook
            .run(
                HookEvent::PostTool,
                &json!({"session_id": "s1", "tool_name": "write", "tool_input": {"path": orphan.to_str().unwrap()}}),
            )
            .unwrap();
        let swapped = paths.data.join("scratch/test_swapped.py");
        let pre = json!({"session_id": "s1", "tool_name": "write", "tool_input": {"path": paths.data.join("scratch/test_other.py").to_str().unwrap()}});
        let _ = hook.run(HookEvent::PreTool, &pre).unwrap();
        write(&swapped, "x");
        let _ = hook
            .run(
                HookEvent::PostTool,
                &json!({"session_id": "s1", "tool_name": "write", "tool_input": {"path": swapped.to_str().unwrap()}}),
            )
            .unwrap();
        assert_eq!(Cleaner::new(&cfg, &paths).load_tracked().len(), 1, "only the snapshot-matched path is tracked");
        let _ = fs::remove_file(&orphan);
        let _ = fs::remove_file(&swapped);

        // A path named in a shell command is picked up the same way.
        let shelled = paths.data.join("scratch/tmp_from_shell.sh");
        let p3 = json!({"session_id": "s1", "tool_name": "shell", "tool_input": {"command": format!("touch {}", shelled.display())}});
        let _ = hook.run(HookEvent::PreTool, &p3).unwrap();
        write(&shelled, "#!/bin/sh\n");
        let _ = hook.run(HookEvent::PostTool, &p3).unwrap();
        assert_eq!(Cleaner::new(&cfg, &paths).load_tracked().len(), 2);

        // Session end: any tracked test file ⇒ quick cleanup, and the audit line upstream writes.
        let _ = hook.run(HookEvent::SessionEnd, &json!({"session_id": "s1", "reason": "exit"})).unwrap();
        assert!(!fresh.exists() && !shelled.exists(), "session end deletes what it tracked");
        assert!(existing.exists(), "an untracked file is untouched");
        let log = log_text(&Cleaner::new(&cfg, &paths));
        assert!(log.contains("AUTO_QUICK (session_end): deleted=2 dirs="), "{log}");

        // A session that tracked nothing runs no cleanup.
        let quiet = paths.data.join("scratch/test_quiet.py");
        write(&quiet, "x");
        let _ = hook.run(HookEvent::SessionEnd, &json!({"session_id": "s2"})).unwrap();
        assert!(quiet.exists());

        // Hooks never fail, whatever the payload.
        for ev in [HookEvent::PreTool, HookEvent::PostTool, HookEvent::SessionEnd] {
            assert_eq!(hook.run(ev, &json!({})).unwrap(), HookDecision::Allow);
            assert_eq!(hook.run(ev, &json!({"session_id": 5, "tool_name": ["x"], "tool_input": 1})).unwrap(), HookDecision::Allow);
        }
    }

    #[test]
    fn tool_and_slash_surface() {
        let d = root("surface");
        let paths = paths_of(&d);
        let cfg = Config::default();
        let tools = tools(&cfg, &paths);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].spec().name, "disk_cleanup");
        let ctx = tool_ctx(&paths);
        let t = &tools[0];

        let f = paths.data.join("scratch/test_surface.py");
        write(&f, "abc");
        let out = t.call(&ctx, json!({"action": "track", "path": f.to_str().unwrap(), "category": "test"}));
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.starts_with("Tracked ") && out.content.ends_with("'test'."), "{}", out.content);

        let st = t.call(&ctx, json!({"action": "status"}));
        let head = format!("{:<20} {:>6}  {:>10}", "Category", "Files", "Size");
        assert!(st.content.starts_with(&format!("{head}\n{}", "-".repeat(40))), "{}", st.content);
        assert!(st.content.contains(&format!("{:<20} {:>6}  {:>10}", "test", 1, fmt_size(3))), "{}", st.content);
        assert!(st.content.contains("Top 10 largest tracked files:") && st.content.contains("test_surface.py"), "{}", st.content);

        let dr = t.call(&ctx, json!({"action": "dry-run"}));
        assert!(dr.content.starts_with("Dry-run preview (nothing deleted):"), "{}", dr.content);
        assert!(
            dr.content.contains("  Auto-delete : 1 files (3.0 B)") && dr.content.contains("  Needs prompt: 0 files (0.0 B)"),
            "{}",
            dr.content
        );
        assert!(dr.content.contains("  Total potential: 3.0 B") && f.exists());

        let q = t.call(&ctx, json!({"action": "quick"}));
        assert!(q.content.starts_with("[disk-cleanup] Cleaned 1 files + ") && q.content.contains("freed 3.0 B."), "{}", q.content);
        assert!(!f.exists(), "the tool really deletes");

        let g = paths.data.join("scratch/test_forget.py");
        write(&g, "x");
        assert!(t
            .call(&ctx, json!({"action": "track", "path": g.to_str().unwrap()}))
            .content
            .starts_with("Usage: /disk-cleanup track <path> <category>"));
        assert!(t
            .call(&ctx, json!({"action": "track", "path": g.to_str().unwrap(), "category": "nope"}))
            .content
            .contains("Unknown category 'nope'. Allowed: "));
        t.call(&ctx, json!({"action": "track", "path": g.to_str().unwrap(), "category": "test"}));
        let fg = t.call(&ctx, json!({"action": "forget", "path": g.to_str().unwrap()}));
        assert_eq!(fg.content, format!("Removed 1 tracking entry for {}.", g.to_str().unwrap()));
        assert!(g.exists(), "forget never deletes");
        assert!(t.call(&ctx, json!({"action": "forget", "path": g.to_str().unwrap()})).content.starts_with("Not found in tracking: "));

        assert!(t.call(&ctx, json!({"action": "deep"})).content.starts_with("[disk-cleanup] Cleaned 0 files + "));
        assert!(t
            .call(&ctx, json!({"action": "bogus"}))
            .content
            .starts_with("Unknown subcommand: bogus\n\n/disk-cleanup — ephemeral-file cleanup"));
        assert!(t.call(&ctx, json!({})).is_error);

        // Structured arguments: a path containing spaces is one argument, not two.
        let spaced = paths.data.join("scratch/test with space.py");
        write(&spaced, "x");
        assert!(t
            .call(&ctx, json!({"action": "track", "path": spaced.to_str().unwrap(), "category": "test"}))
            .content
            .starts_with("Tracked "));
        assert!(t.call(&ctx, json!({"action": "status"})).content.contains("test with space.py"));
        assert!(t
            .call(&ctx, json!({"action": "forget", "path": spaced.to_str().unwrap()}))
            .content
            .starts_with("Removed 1 tracking entry for "));

        // Slash: same handlers, through a real SlashCtx.
        let s = slash(&cfg, &paths);
        let ctx = slash_ctx(&paths);
        assert_eq!(s.commands(), vec![("disk-cleanup".to_string(), "Track and clean up ephemeral seagent session files.".to_string())]);
        assert!(s.run(&ctx, "achievements", "status").is_none());
        let help = s.run(&ctx, "disk-cleanup", "").unwrap().unwrap().text.unwrap();
        assert!(help.starts_with("/disk-cleanup — ephemeral-file cleanup\n\nSubcommands:"), "{help}");
        assert!(help.contains("track <path> <category>") && help.contains("All operations are scoped to SEAGENT_HOME and /tmp/seagent-*."));
        assert_eq!(s.run(&ctx, "disk-cleanup", "help").unwrap().unwrap().text.unwrap(), help);
        let h = paths.data.join("scratch/test_slash.py");
        write(&h, "xy");
        let tracked = s.run(&ctx, "disk-cleanup", &format!("track {} test", h.display())).unwrap().unwrap().text.unwrap();
        assert_eq!(tracked, format!("Tracked {} as 'test'.", h.display()));
        let status = s.run(&ctx, "disk-cleanup", "status").unwrap().unwrap().text.unwrap();
        assert!(status.contains("Top 10 largest tracked files:") && status.contains("test_slash.py"), "{status}");
        let quick = s.run(&ctx, "disk-cleanup", "quick").unwrap().unwrap().text.unwrap();
        assert!(quick.starts_with("[disk-cleanup] Cleaned 1 files + "), "{quick}");
        assert!(!h.exists());
        assert_eq!(s.run(&ctx, "disk-cleanup", "track").unwrap().unwrap().text.unwrap(), "Usage: /disk-cleanup track <path> <category>");
        assert_eq!(s.run(&ctx, "disk-cleanup", "forget").unwrap().unwrap().text.unwrap(), "Usage: /disk-cleanup forget <path>");
        assert!(s
            .run(&ctx, "disk-cleanup", "track /tmp/x nope")
            .unwrap()
            .unwrap()
            .text
            .unwrap()
            .starts_with("Unknown category 'nope'. Allowed: ['chrome-profile', 'cron-output', 'download', 'other', 'research', 'temp', 'test']"));
    }

    #[test]
    fn thresholds_match_upstream() {
        let (c, paths) = cleaner("thresholds");
        let h = paths.data.clone();
        let mk = |rel: &str, cat: &str, days: i64, size: u64| {
            let p = h.join(rel);
            write(&p, &"x".repeat(size as usize));
            Item {
                path: p.canonicalize().unwrap().to_string_lossy().into_owned(),
                timestamp: iso_days_ago(days),
                category: cat.into(),
                size,
            }
        };
        let items = vec![
            mk("scratch/temp_6.bin", "temp", 6, 10),
            mk("scratch/temp_8.bin", "temp", 8, 10),
            mk("cron/output/night/new.log", "cron-output", 10, 10),
            mk("cron/output/night/old.log", "cron-output", 15, 10),
            mk("scratch/test_now.py", "test", 0, 10),
            mk("scratch/research_notes.md", "research", 31, 10),
            mk("scratch/chrome", "chrome-profile", 15, 10),
        ];
        c.save_tracked(&items);
        let q = c.quick();
        assert_eq!(q.deleted, 3, "temp>7d, cron-output>14d, test at age 0");
        assert!(h.join("scratch/temp_6.bin").exists(), "temp keeps until 7 days");
        assert!(!h.join("scratch/temp_8.bin").exists());
        assert!(h.join("cron/output/night/new.log").exists(), "cron-output keeps until 14 days");
        assert!(!h.join("cron/output/night/old.log").exists());
        assert!(!h.join("scratch/test_now.py").exists());
        // Prompt-only buckets are never auto-deleted; they show up in dry-run/deep instead.
        assert!(h.join("scratch/research_notes.md").exists() && h.join("scratch/chrome").exists());
        let (auto, prompt) = c.dry_run_lists();
        assert!(auto.is_empty(), "{auto:?}");
        let cats: Vec<&str> = prompt.iter().map(|i| i.category.as_str()).collect();
        assert_eq!(cats, ["research", "chrome-profile"], "{prompt:?}");
        let deep = c.handle_slash("deep");
        assert!(deep.contains("2 item(s) need confirmation (20.0 B):"), "{deep}");
        assert!(deep.contains("Run `/disk-cleanup forget <path>` to skip"), "{deep}");
        // `deep` re-runs quick first, so its summary heads the block.
        assert!(deep.starts_with("[disk-cleanup] Cleaned 0 files + "), "{deep}");
        // Entries for files that vanished are logged STALE and dropped by quick().
        fs::remove_file(h.join("scratch/temp_6.bin")).unwrap();
        let _ = c.quick();
        assert!(log_text(&c).contains("STALE: ") && log_text(&c).contains("(removed from tracking)"));
        assert!(!c.load_tracked().iter().any(|i| i.path.ends_with("temp_6.bin")));
        // A tracked directory under a protected top level is never rmtree'd.
        let dir = h.join("cache/terminal");
        fs::create_dir_all(dir.join("snap")).unwrap();
        write(&dir.join("snap/x.bin"), "x");
        c.save_tracked(&[Item {
            path: dir.canonicalize().unwrap().to_string_lossy().into_owned(),
            timestamp: iso_days_ago(40),
            category: "temp".into(),
            size: 0,
        }]);
        let q = c.quick();
        assert_eq!(q.deleted, 0);
        assert!(dir.exists(), "cache/terminal holds terminal snapshots");
        assert!(log_text(&c).contains("SKIPPED: ") && log_text(&c).contains("(protected top-level dir)"));
    }

    #[test]
    fn fmt_size_matches_upstream() {
        assert_eq!(fmt_size(0), "0.0 B");
        assert_eq!(fmt_size(999), "999.0 B");
        assert_eq!(fmt_size(1024), "1.0 KB");
        assert_eq!(fmt_size(1536), "1.5 KB");
        assert_eq!(fmt_size(1024 * 1024), "1.0 MB");
        assert_eq!(fmt_size(LARGE_FILE_BYTES), "500.0 MB");
        assert_eq!(fmt_size(1024u64.pow(4)), "1.0 TB");
        // Upstream's loop ends after TB, so 1024^5 bytes is "1.0 PB" (not "1024.0 PB").
        assert_eq!(fmt_size(1024u64.pow(5)), "1.0 PB");
        // ISO round-trip and the day floor upstream's `timedelta.days` gives.
        let t = 1_700_000_000;
        assert_eq!(parse_iso(&iso_of(t)), Some(t));
        assert_eq!(parse_iso("2026-11-04T01:31:00.123456+00:00"), Some(parse_iso("2026-11-04T01:31:00+00:00").unwrap()));
        assert_eq!(parse_iso("2026-11-04T01:31:00+08:00"), Some(parse_iso("2026-11-03T17:31:00+00:00").unwrap()));
        assert_eq!(days_between(t + 7 * 86_400 + 3600, t), 7);
        assert_eq!(parse_iso("nonsense"), None);
    }

    #[test]
    fn tracked_json_recovers_from_backup() {
        let (c, paths) = cleaner("corrupt");
        let f = paths.data.join("scratch/test_backup.py");
        write(&f, "x");
        c.track(f.to_str().unwrap(), "test").unwrap();
        assert!(c.state_file("tracked.json").exists() && !c.state_file("tracked.json.bak").exists(), "no backup on the first write");
        let g = paths.data.join("scratch/test_second.py");
        write(&g, "x");
        c.track(g.to_str().unwrap(), "test").unwrap();
        let bak = fs::read_to_string(c.state_file("tracked.json.bak")).unwrap();
        assert!(c.state_file("tracked.json.bak").exists());
        write(&c.state_file("tracked.json"), "{ not json");
        assert_eq!(c.load_tracked().len(), serde_json::from_str::<Vec<Item>>(&bak).unwrap().len());
        assert!(log_text(&c).contains("WARN: tracked.json corrupted — restored from .bak"));
        write(&c.state_file("tracked.json"), "garbage");
        let _ = fs::remove_file(c.state_file("tracked.json.bak"));
        assert!(c.load_tracked().is_empty());
        assert!(log_text(&c).contains("WARN: tracked.json corrupted, no backup — starting fresh"));
        assert!(!c.state_file("tracked.json.tmp").exists(), "atomic write leaves no temp file");
    }

    #[test]
    fn git_owned_test_files_are_not_tracked() {
        let (c, paths) = cleaner("git");
        let h = paths.data.clone();
        // A `.git` on the directory chain below the home: the tree manages its own files.
        fs::create_dir_all(h.join("repo/.git")).unwrap();
        let owned = h.join("repo/test_committed.py");
        write(&owned, "x");
        assert_eq!(c.guess_category(&owned), None, "a checkout's test_* is a committed regression test");
        // A sibling without a `.git` is ordinary scratch.
        let scratch = h.join("scratch/test_scratch.py");
        write(&scratch, "x");
        assert_eq!(c.guess_category(&scratch), Some("test"));
        // A `.git` *file* (linked worktree) counts the same way.
        write(&h.join("worktree/.git"), "gitdir: /elsewhere\n");
        let wt = h.join("worktree/tmp_wt.py");
        write(&wt, "x");
        assert_eq!(c.guess_category(&wt), None);

        // An enclosing repo only counts when it actually tracks the file (`git ls-files`).
        if std::process::Command::new("git").arg("--version").output().map(|o| o.status.success()).unwrap_or(false) {
            let d = h.parent().unwrap();
            let git = |args: &[&str]| std::process::Command::new("git").arg("-C").arg(d).args(args).output().map(|o| o.status.success()).unwrap_or(false);
            if git(&["init", "-q"]) {
                let inside = h.join("tracked-repo/test_x.py");
                write(&inside, "x");
                if git(&["add", "data/tracked-repo/test_x.py"]) {
                    assert_eq!(c.guess_category(&inside), None, "tracked by an enclosing repo");
                    assert!(c.git_tracks(&inside.canonicalize().unwrap()));
                }
                let untracked = h.join("tracked-repo/test_y.py");
                write(&untracked, "x");
                assert_eq!(c.guess_category(&untracked), Some("test"), "untracked scratch in the same repo stays disposable");
            }
        }
    }
}
