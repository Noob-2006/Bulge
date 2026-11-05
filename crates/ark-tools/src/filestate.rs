//! File-tool bookkeeping and guards (ports of Hermes `tools/file_state.py`,
//! `tools/file_tools_read_tracking.py`, `tools/file_tools_write_guards.py`,
//! `agent/file_safety.py`, `tools/binary_extensions.py` (MIT), plus OpenClaw's
//! `tools.fs.workspaceOnly` containment):
//! - per-session read tracking: dedup of unchanged re-reads, repeated-read loop guard,
//!   full-content baselines (one read or contiguous pages) for whole-file overwrites;
//! - a process-wide registry of who read/wrote what, so a write that would clobber a
//!   sibling agent's (or an external) change is refused or warned about;
//! - per-path locks so concurrent sub-agents serialize read→modify→write;
//! - path guards: devices/FIFOs, credential files, system paths, binary documents,
//!   read_file display text written back as content, workspace containment.

use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

// ───────────────────── config ─────────────────────

/// `[files]` settings (all optional; defaults below).
#[derive(Debug, Clone, PartialEq)]
pub struct FilesConfig {
    /// Read budget in characters per call (Hermes `file_read_max_chars`).
    pub read_max_chars: usize,
    /// Confine read/write/edit/patch/grep/glob to the workspace (OpenClaw `tools.fs.workspaceOnly`).
    pub workspace_only: bool,
    /// Confine apply_patch to the workspace (OpenClaw `tools.exec.applyPatch.workspaceOnly`).
    pub apply_patch_workspace_only: bool,
    /// Refuse stale or blind whole-file overwrites (Hermes file-state guard).
    pub stale_write_guard: bool,
    /// Post-write syntax check (Hermes file_operations_lint).
    pub lint: bool,
    /// Writes to AGENTS.md / CLAUDE.md / SOUL.md / .cursorrules need approval.
    pub protected_instructions: bool,
    /// Identical re-reads of an unchanged file return a short stub.
    pub read_dedup: bool,
    /// Run linters that resolve their toolchain from the workspace (`npx tsc`, `rustfmt`).
    pub lint_project_toolchains: bool,
    /// Append security-guidance warnings for dangerous constructs in new content
    /// (Hermes `plugins/security-guidance`; `SECURITY_GUIDANCE_DISABLE` still wins).
    pub security_guidance: bool,
}

impl Default for FilesConfig {
    fn default() -> Self {
        FilesConfig { read_max_chars: 100_000, workspace_only: false, apply_patch_workspace_only: true, stale_write_guard: true, lint: true, protected_instructions: true, read_dedup: true, lint_project_toolchains: false, security_guidance: true }
    }
}

static CFG: RwLock<Option<FilesConfig>> = RwLock::new(None);

/// Install `[files]` from the config (a JSON view of the TOML table). Unknown keys are ignored.
pub fn configure_files(v: &Value) {
    *CFG.write().unwrap() = Some(parse_files(v));
}

pub fn parse_files(v: &Value) -> FilesConfig {
    let mut c = FilesConfig::default();
    let b = |k: &str, d: bool| v.get(k).and_then(Value::as_bool).unwrap_or(d);
    c.read_max_chars = v.get("read_max_chars").and_then(Value::as_u64).filter(|n| *n > 0).map(|n| n as usize).unwrap_or(c.read_max_chars);
    c.workspace_only = b("workspace_only", c.workspace_only);
    c.apply_patch_workspace_only = b("apply_patch_workspace_only", c.apply_patch_workspace_only);
    c.stale_write_guard = b("stale_write_guard", c.stale_write_guard);
    c.lint = b("lint", c.lint);
    c.protected_instructions = b("protected_instructions", c.protected_instructions);
    c.read_dedup = b("read_dedup", c.read_dedup);
    c.lint_project_toolchains = b("lint_project_toolchains", c.lint_project_toolchains);
    c.security_guidance = b("security_guidance", c.security_guidance);
    c
}

pub fn cfg() -> FilesConfig {
    CFG.read().unwrap().clone().unwrap_or_default()
}

// ───────────────────── versions ─────────────────────

/// (mtime ns, size, inode): changes whenever the file's bytes may have.
pub type Version = (i128, u64, u64);

pub fn version(p: &Path) -> Option<Version> {
    let m = std::fs::metadata(p).ok()?;
    let mt = m.modified().ok()?.duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i128).unwrap_or(0);
    Some((mt, m.len(), m.ino()))
}

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

fn fmt_ts(ts: f64) -> String {
    let s = ts as u64 % 86_400;
    format!("{:02}:{:02}:{:02} UTC", s / 3600, (s / 60) % 60, s % 60)
}

// ───────────────────── per-session tracker ─────────────────────

pub const DEDUP_STATUS: &str = "File unchanged since last read. The content from the earlier read result in this conversation is still current — refer to that instead of re-reading. (If that result is no longer visible to you, e.g. after compaction, call read again with fresh=true.)";

type ReadKey = (PathBuf, usize, usize);

#[derive(Default)]
struct Task {
    dedup: HashMap<ReadKey, Version>,
    dedup_hits: HashMap<ReadKey, usize>,
    last_key: Option<(String, String)>,
    consecutive: usize,
    read_mtime: HashMap<PathBuf, Version>,
    baselines: HashMap<PathBuf, Version>,
    coverage: HashMap<PathBuf, (Version, Vec<(usize, usize)>)>,
    blind_patches: HashSet<PathBuf>,
}

static TASKS: Mutex<Option<HashMap<String, Task>>> = Mutex::new(None);

fn with_task<R>(session: &str, f: impl FnOnce(&mut Task) -> R) -> R {
    let mut g = TASKS.lock().unwrap();
    let map = g.get_or_insert_with(HashMap::new);
    f(map.entry(session.to_string()).or_default())
}

/// Count consecutive identical file-tool calls (any other file-tool call resets it).
pub fn bump_consecutive(session: &str, kind: &str, key: &str) -> usize {
    with_task(session, |t| {
        let k = (kind.to_string(), key.to_string());
        if t.last_key.as_ref() == Some(&k) {
            t.consecutive += 1;
        } else {
            t.last_key = Some(k);
            t.consecutive = 1;
        }
        t.consecutive
    })
}

/// A file tool other than an identical read ran: break the consecutive chain.
pub fn note_other_call(session: &str) {
    with_task(session, |t| {
        t.last_key = None;
        t.consecutive = 0;
    })
}

/// Drop dedup memory (after compaction the model may no longer have the content).
pub fn reset_read_dedup(session: &str) {
    with_task(session, |t| {
        t.dedup.clear();
        t.dedup_hits.clear();
    })
}

/// Repeated identical read of an unchanged file: the stub, escalating to a block.
pub fn dedup_check(session: &str, path: &Path, offset: usize, limit: usize) -> Option<Result<String, String>> {
    if !cfg().read_dedup {
        return None;
    }
    let v = version(path)?;
    let key = (path.to_path_buf(), offset, limit);
    with_task(session, |t| {
        if t.dedup.get(&key) != Some(&v) {
            return None;
        }
        let hits = t.dedup_hits.entry(key).or_insert(0);
        *hits += 1;
        if *hits >= 2 {
            return Some(Err(format!("BLOCKED: You have called read on this exact region {} times and the file has NOT changed. STOP calling read for this path — the content from your earlier read result in this conversation is still current. Proceed with your task using the information you already have.", *hits + 1)));
        }
        Some(Ok(DEDUP_STATUS.to_string()))
    })
}

/// Bookkeeping after a real read. Returns the consecutive-read count.
#[allow(clippy::too_many_arguments)]
pub fn record_read(session: &str, path: &Path, offset: usize, limit: usize, end_line: usize, total_lines: usize, partial: bool, before: Option<Version>) -> usize {
    let count = bump_consecutive(session, "read", &format!("{}:{offset}:{limit}", path.display()));
    let after = version(path);
    let stable = before.is_some() && before == after;
    let complete = with_task(session, |t| {
        let key = (path.to_path_buf(), offset, limit);
        t.dedup_hits.remove(&key);
        if let Some(v) = after {
            t.read_mtime.insert(path.to_path_buf(), v);
        }
        let mut complete = false;
        if let (true, Some(v)) = (stable, after) {
            if count < 4 {
                t.dedup.insert(key.clone(), v);
            }
            complete = t.baselines.get(path) == Some(&v);
            if !complete {
                complete = !partial;
                if partial {
                    let cov = t.coverage.entry(path.to_path_buf()).or_insert((v, vec![]));
                    if cov.0 != v {
                        *cov = (v, vec![]);
                    }
                    cov.1.push((offset, end_line));
                    cov.1.sort();
                    let mut reach = 0;
                    for &(s, e) in &cov.1 {
                        if s <= reach + 1 {
                            reach = reach.max(e);
                        }
                    }
                    complete = total_lines > 0 && reach >= total_lines;
                }
            }
            if complete {
                t.baselines.insert(path.to_path_buf(), v);
                t.blind_patches.remove(path);
            }
        }
        if !complete {
            t.baselines.remove(path);
        }
        if !stable || count >= 4 {
            t.dedup.remove(&key);
        }
        complete
    });
    registry_record_read(session, path, !complete);
    count
}

pub fn has_baseline(session: &str, path: &Path) -> bool {
    let v = version(path);
    with_task(session, |t| v.is_some() && t.baselines.get(path) == v.as_ref())
}

fn read_mtime_drifted(session: &str, path: &Path) -> bool {
    let cur = version(path);
    with_task(session, |t| match (t.read_mtime.get(path), cur) {
        (Some(r), Some(c)) => r.0 != c.0 || r.1 != c.1,
        _ => false,
    })
}

/// After a successful write/edit: the session now knows the whole current content (write)
/// or edited it (patch; blind unless it had a baseline).
pub fn note_edited(session: &str, path: &Path, full_write: bool) {
    let v = version(path);
    with_task(session, |t| {
        if let Some(v) = v {
            t.read_mtime.insert(path.to_path_buf(), v);
            let had = t.baselines.contains_key(path);
            if full_write || had {
                t.baselines.insert(path.to_path_buf(), v);
                t.blind_patches.remove(path);
            } else {
                t.blind_patches.insert(path.to_path_buf());
            }
        }
        t.dedup.retain(|k, _| k.0 != path);
        t.last_key = None;
    });
    registry_note_write(session, path);
}

/// Forget a finished session (sub-agent teardown).
pub fn forget_session(session: &str) {
    if let Some(m) = TASKS.lock().unwrap().as_mut() {
        m.remove(session);
    }
    let mut r = REG.lock().unwrap();
    if let Some(r) = r.as_mut() {
        r.reads.remove(session);
        r.last_writer.retain(|_, (w, _)| w != session);
    }
}

// ───────────────────── cross-agent registry ─────────────────────

#[derive(Default)]
struct Registry {
    /// session → path → (version, read ts, partial)
    reads: HashMap<String, HashMap<PathBuf, (Version, f64, bool)>>,
    last_writer: HashMap<PathBuf, (String, f64)>,
}

static REG: Mutex<Option<Registry>> = Mutex::new(None);
const MAX_PATHS: usize = 4096;

fn with_reg<R>(f: impl FnOnce(&mut Registry) -> R) -> R {
    let mut g = REG.lock().unwrap();
    f(g.get_or_insert_with(Registry::default))
}

fn registry_record_read(session: &str, path: &Path, partial: bool) {
    let Some(v) = version(path) else { return };
    with_reg(|r| {
        let m = r.reads.entry(session.to_string()).or_default();
        if m.len() >= MAX_PATHS {
            if let Some(k) = m.keys().next().cloned() {
                m.remove(&k);
            }
        }
        m.insert(path.to_path_buf(), (v, now(), partial));
    })
}

fn registry_note_write(session: &str, path: &Path) {
    let Some(v) = version(path) else { return };
    let ts = now();
    with_reg(|r| {
        if r.last_writer.len() >= MAX_PATHS {
            if let Some(k) = r.last_writer.keys().next().cloned() {
                r.last_writer.remove(&k);
            }
        }
        r.last_writer.insert(path.to_path_buf(), (session.to_string(), ts));
        r.reads.entry(session.to_string()).or_default().insert(path.to_path_buf(), (v, ts, false));
    })
}

/// Model-facing reason this write would be stale, else None. Severity order: a sibling
/// wrote after our read > on-disk change / partial read > never read.
pub fn check_stale(session: &str, path: &Path) -> Option<String> {
    let cur = version(path)?;
    let (stamp, writer) = with_reg(|r| (r.reads.get(session).and_then(|m| m.get(path)).cloned(), r.last_writer.get(path).cloned()));
    if stamp.is_none() && writer.is_none() {
        return None;
    }
    let p = path.display();
    if let Some((w, wts)) = writer {
        if w != session {
            match &stamp {
                None => return Some(format!("{p} was modified by sibling agent {w:?} but this agent never read it. Read the file before writing to avoid overwriting the sibling's changes.")),
                Some((_, rts, _)) if wts > *rts => return Some(format!("{p} was modified by sibling agent {w:?} at {} — after this agent's last read at {}. Re-read the file before writing.", fmt_ts(wts), fmt_ts(*rts))),
                _ => {}
            }
        }
    }
    match stamp {
        Some((v, _, partial)) => {
            if (v.0, v.1) != (cur.0, cur.1) {
                Some(format!("{p} was modified since you last read it on disk (external edit or unrecorded writer). Re-read the file before writing."))
            } else if partial {
                Some(format!("{p} was last read with offset/limit pagination (partial view). Read the remaining pages, or use edit, before overwriting it."))
            } else {
                None
            }
        }
        None => Some(format!("{p} was not read by this agent. Read the file first so you can write an informed edit.")),
    }
}

/// Paths other sessions wrote at or after `since` (for "a sub-agent changed files you read").
pub fn writes_since(exclude: &str, since: f64, paths: &[PathBuf]) -> HashMap<String, Vec<PathBuf>> {
    with_reg(|r| {
        let mut out: HashMap<String, Vec<PathBuf>> = HashMap::new();
        for (p, (w, ts)) in &r.last_writer {
            if w != exclude && *ts >= since && paths.contains(p) {
                out.entry(w.clone()).or_default().push(p.clone());
            }
        }
        out
    })
}

pub fn known_reads(session: &str) -> Vec<PathBuf> {
    with_reg(|r| r.reads.get(session).map(|m| m.keys().cloned().collect()).unwrap_or_default())
}

/// Why `write` must NOT replace the existing file (Hermes `_stale_overwrite_blocker`).
pub fn stale_overwrite_blocker(session: &str, path: &Path) -> Option<String> {
    if !cfg().stale_write_guard || !path.exists() {
        return None;
    }
    if let Some(s) = check_stale(session, path) {
        if !s.contains("was not read by this agent") {
            return Some(s);
        }
    }
    if read_mtime_drifted(session, path) {
        return Some(format!("{} was modified since you last read it (external edit or concurrent agent). Re-read the file before writing.", path.display()));
    }
    if has_baseline(session, path) {
        return None;
    }
    if with_task(session, |t| t.blind_patches.contains(path)) {
        return Some("Your edits changed this file without a full view of its current content. Read the current file in full before a whole-file overwrite, or continue with targeted edits.".into());
    }
    Some(format!("{} exists but this task has not seen its full current content (never read, edited without a prior full read, or only a partial view). Read the file — every page of it, if it needs offset/limit — or use edit for a targeted change; a stale conversation copy must not overwrite the current disk content.", path.display()))
}

/// Non-blocking pre-edit warning (cross-agent registry, then local staleness).
pub fn edit_warning(session: &str, path: &Path) -> Option<String> {
    if !cfg().stale_write_guard {
        return None;
    }
    let w = check_stale(session, path).filter(|s| !s.contains("was not read by this agent") && !s.contains("partial view"));
    w.or_else(|| read_mtime_drifted(session, path).then(|| format!("Warning: {} was modified since you last read it (external edit or concurrent agent). The content you read may be stale. Consider re-reading the file to verify before writing.", path.display())))
}

// ───────────────────── per-path locks ─────────────────────

type LockMap = HashMap<PathBuf, Arc<(Mutex<bool>, Condvar)>>;
static LOCKS: Mutex<Option<LockMap>> = Mutex::new(None);

pub struct PathLock {
    path: PathBuf,
    cell: Arc<(Mutex<bool>, Condvar)>,
}

/// Serialize read→modify→write on one path across concurrent agents; other paths proceed.
pub fn lock_path(p: &Path) -> PathLock {
    let cell = LOCKS.lock().unwrap().get_or_insert_with(HashMap::new).entry(p.to_path_buf()).or_insert_with(|| Arc::new((Mutex::new(false), Condvar::new()))).clone();
    {
        let (m, cv) = &*cell;
        let mut held = m.lock().unwrap();
        while *held {
            held = cv.wait(held).unwrap();
        }
        *held = true;
    }
    PathLock { path: p.to_path_buf(), cell }
}

impl Drop for PathLock {
    fn drop(&mut self) {
        let (m, cv) = &*self.cell;
        *m.lock().unwrap() = false;
        cv.notify_one();
        let mut g = LOCKS.lock().unwrap();
        if let Some(map) = g.as_mut() {
            if Arc::strong_count(&self.cell) <= 2 {
                map.remove(&self.path);
            }
        }
    }
}

// ───────────────────── path guards ─────────────────────

const BLOCKED_DEVICES: &[&str] = &["/dev/zero", "/dev/random", "/dev/urandom", "/dev/full", "/dev/stdin", "/dev/tty", "/dev/console", "/dev/stdout", "/dev/stderr", "/dev/fd/0", "/dev/fd/1", "/dev/fd/2"];
const BLOCKED_PROC_SUFFIXES: &[&str] = &["/fd/0", "/fd/1", "/fd/2", "/environ", "/cmdline", "/maps", "/smaps", "/smaps_rollup", "/numa_maps", "/mem", "/auxv", "/pagemap"];

/// Lexical normalization (`a/./b/../c` → `a/c`) without touching the file system.
pub fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c.as_os_str()),
        }
    }
    out
}

fn blocked_device_path(p: &Path) -> bool {
    let s = normalize(p).display().to_string();
    BLOCKED_DEVICES.contains(&s.as_str()) || (s.starts_with("/proc/") && BLOCKED_PROC_SUFFIXES.iter().any(|x| s.ends_with(x)))
}

/// Literal path, every symlink hop, or final realpath is a device that hangs or leaks.
pub fn blocked_device(p: &Path) -> bool {
    if blocked_device_path(p) {
        return true;
    }
    let mut cur = normalize(p);
    for _ in 0..20 {
        let Ok(t) = std::fs::read_link(&cur) else { break };
        let t = if t.is_absolute() { t } else { cur.parent().unwrap_or(Path::new("/")).join(t) };
        cur = normalize(&t);
        if blocked_device_path(&cur) {
            return true;
        }
    }
    std::fs::canonicalize(p).is_ok_and(|r| blocked_device_path(&r))
}

/// Human name for a non-regular file that would hang a read.
pub fn special_file_kind(p: &Path) -> Option<&'static str> {
    let ft = std::fs::metadata(p).ok()?.file_type();
    if ft.is_file() || ft.is_dir() {
        None
    } else if ft.is_fifo() {
        Some("a FIFO (named pipe)")
    } else if ft.is_socket() {
        Some("a socket")
    } else if ft.is_char_device() {
        Some("a character device")
    } else if ft.is_block_device() {
        Some("a block device")
    } else {
        Some("a special (non-regular) file")
    }
}

const BLOCKED_ENV_BASENAMES: &[&str] = &[".env", ".env.local", ".env.development", ".env.production", ".env.test", ".env.staging", ".envrc"];
const DID_SUFFIX: &str = " (Defense-in-depth — not a security boundary; the shell tool can still bypass.)";

/// ark's config dir, as `ark_kernel::Paths::from_env` computes it.
fn ark_config_dir() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("ARK_HOME") {
        return Some(PathBuf::from(h).join("config"));
    }
    let x = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).filter(|p| p.is_absolute());
    x.or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config"))).map(|d| d.join("ark"))
}

/// Reads denied to file tools: ark's secret vault, project `.env` files.
pub fn read_block_error(p: &Path) -> Option<String> {
    let r = std::fs::canonicalize(p).unwrap_or_else(|_| normalize(p));
    if let Some(cd) = ark_config_dir() {
        let cd = std::fs::canonicalize(&cd).unwrap_or(cd);
        if r == cd.join("secrets.toml") {
            return Some(format!("Access denied: {} is ark's credential vault and cannot be read directly; tools receive secrets through {{{{secret:NAME}}}} substitution.{DID_SUFFIX}", p.display()));
        }
    }
    let name = r.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    if BLOCKED_ENV_BASENAMES.contains(&name.as_str()) {
        return Some(format!("Access denied: {} is a secret-bearing environment file and cannot be read to prevent credential leakage. If you need to check the file structure, read .env.example instead.{DID_SUFFIX}", p.display()));
    }
    None
}

const SENSITIVE_PREFIXES: &[&str] = &["/etc/", "/boot/", "/usr/lib/systemd/", "/private/etc/", "/private/var/db/", "/private/var/root/"];
const SENSITIVE_EXACT: &[&str] = &["/var/run/docker.sock", "/run/docker.sock"];

/// Writes refused outright: system paths, the docker socket, ark's own config and vault.
pub fn sensitive_write_error(p: &Path) -> Option<String> {
    let cands = [std::fs::canonicalize(p).unwrap_or_else(|_| normalize(p)), normalize(p)];
    let hit = cands.iter().any(|c| {
        let s = c.display().to_string();
        SENSITIVE_PREFIXES.iter().any(|x| s.starts_with(x)) || SENSITIVE_EXACT.contains(&s.as_str())
    });
    if hit {
        return Some(format!("Refusing to write to sensitive system path: {}\nUse the shell tool (with sudo if needed) if you need to modify system files.", p.display()));
    }
    if let Some(cd) = ark_config_dir() {
        let cd = std::fs::canonicalize(&cd).unwrap_or(cd);
        if cands.iter().any(|c| *c == cd.join("config.toml") || *c == cd.join("secrets.toml")) {
            return Some(format!("Refusing to write to ark's own configuration: {}\nThe agent cannot modify security-sensitive configuration. Edit it yourself or use `ark config` / `ark secrets` instead.", p.display()));
        }
    }
    None
}

pub const PROTECTED_INSTRUCTION_BASENAMES: &[&str] = &["agents.md", "claude.md", "soul.md", ".cursorrules"];

/// Files that steer future agent behavior (prompt-injection persistence vector).
pub fn is_protected_instruction(p: &Path) -> bool {
    let r = std::fs::canonicalize(p).unwrap_or_else(|_| normalize(p));
    [r, p.to_path_buf()].iter().any(|x| x.file_name().is_some_and(|n| PROTECTED_INSTRUCTION_BASENAMES.contains(&n.to_string_lossy().to_ascii_lowercase().as_str())))
}

pub const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "tiff", "tif", "mp4", "mov", "avi", "mkv", "webm", "wmv", "flv", "m4v", "mpeg", "mpg", "mp3", "wav", "ogg", "flac", "aac", "m4a", "wma", "aiff", "opus", "zip", "tar", "gz", "bz2", "7z", "rar", "xz", "z", "tgz", "iso", "exe", "dll", "so", "dylib", "bin", "o", "a", "obj", "lib", "app", "msi", "deb", "rpm", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "ttf", "otf", "woff", "woff2", "eot", "pyc", "pyo", "class", "jar", "war", "ear", "node", "wasm", "rlib", "sqlite", "sqlite3", "db", "mdb", "idx", "psd", "ai", "eps", "sketch", "fig", "xd", "blend", "3ds", "max", "swf", "fla", "lockb", "dat", "data",
];
pub const OPAQUE_DOCUMENT_EXTENSIONS: &[&str] = &["doc", "docx", "docm", "xls", "xlsx", "xlsm", "xlsb", "ppt", "pps", "pot", "pptx", "pptm", "ppsx", "ppsm", "odt", "ods", "odp", "rtf", "epub"];

fn ext(p: &Path) -> String {
    p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

pub fn has_binary_extension(p: &Path) -> bool {
    BINARY_EXTENSIONS.contains(&ext(p).as_str()) || is_sqlite_sidecar(p)
}

pub fn is_sqlite_sidecar(p: &Path) -> bool {
    let n = p.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    ["-wal", "-shm", "-journal"].iter().any(|m| n.ends_with(m) && ["db", "sqlite", "sqlite3"].iter().any(|e| n.contains(&format!(".{e}{m}"))))
}

/// Text writes that would corrupt a binary document (read showed EXTRACTED text).
pub fn binary_document_write_error(p: &Path) -> Option<String> {
    let e = ext(p);
    if OPAQUE_DOCUMENT_EXTENSIONS.contains(&e.as_str()) {
        return Some(format!("Refusing to write plain text to binary document '{}' (.{e}). A text write cannot produce a valid document container and would corrupt the file (read showed you EXTRACTED text, not the real bytes). Use a library like python-docx/openpyxl/python-pptx via the shell tool to create or edit this document.", p.display()));
    }
    if is_sqlite_sidecar(p) {
        return Some(format!("Refusing to write plain text to binary SQLite sidecar '{}'. A -wal/-shm/-journal file holds raw database pages that SQLite reads on the next open; text there corrupts the database. Use the sqlite3 CLI or a SQLite library via the shell tool instead.", p.display()));
    }
    if (e == "pdf" || has_binary_extension(p)) && p.is_file() {
        if e == "pdf" {
            return Some(format!("Refusing to overwrite existing PDF '{}' with plain text. read showed you EXTRACTED text, not the real bytes — writing text back would destroy the document. Use a PDF library via the shell tool to modify it. (Creating a NEW .pdf file is allowed.)", p.display()));
        }
        return Some(format!("Refusing to overwrite existing binary file '{}' (.{e}) with plain text — read showed you extracted or mojibake text, not the real bytes, and writing text back would destroy the file. Use a binary-aware tool via the shell tool to modify it. (Creating a NEW file with this extension is allowed.)", p.display()));
    }
    None
}

/// Content that is read-tool display text (dedup stub, `   12\tline` numbering), not file bytes.
pub fn internal_content_error(content: &str) -> Option<String> {
    let s = content.trim();
    let stub = !s.is_empty() && s.contains(DEDUP_STATUS) && s.len() <= 2 * DEDUP_STATUS.len();
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut numbered = Vec::new();
    for l in &lines {
        let t = l.trim_start();
        let digits: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() && (t[digits.len()..].starts_with('\t') || t[digits.len()..].starts_with('|')) {
            numbered.push(digits.parse::<u64>().unwrap_or(0));
        }
    }
    let line_numbered = lines.len() >= 2 && numbered.len() >= 2 && numbered.len() as f64 / lines.len() as f64 >= 0.6 && numbered.windows(2).filter(|w| w[1] == w[0] + 1).count() + 1 >= numbered.len();
    (stub || line_numbered).then(|| "Refusing to write internal read display text as file content. Strip read's line-number prefixes or reconstruct the intended file contents before writing.".to_string())
}

/// Workspace containment (OpenClaw workspaceOnly): `p` must stay inside `root` lexically
/// and after resolving symlinks of its existing ancestors.
pub fn contain(root: &Path, p: &Path) -> Result<(), String> {
    let root_c = std::fs::canonicalize(root).unwrap_or_else(|_| normalize(root));
    let lex = normalize(p);
    let escape = || Err(format!("Path escapes workspace root ({}): {}", root.display(), p.display()));
    if !lex.starts_with(normalize(root)) && !lex.starts_with(&root_c) {
        return escape();
    }
    // Resolve the deepest existing ancestor (symlinks may point outside).
    let mut anc = lex.clone();
    let mut rest = Vec::new();
    while !anc.exists() {
        match (anc.file_name().map(|n| n.to_os_string()), anc.parent()) {
            (Some(n), Some(par)) => {
                rest.push(n);
                anc = par.to_path_buf();
            }
            _ => break,
        }
    }
    let real = std::fs::canonicalize(&anc).unwrap_or(anc);
    if !real.starts_with(&root_c) {
        return escape();
    }
    Ok(())
}

/// Up to 5 similar names next to a missing path (Hermes `_suggest_similar_files`).
pub fn similar_files(p: &Path) -> Vec<String> {
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let fname = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let lower = fname.to_lowercase();
    let stem = Path::new(&lower).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let e = Path::new(&lower).extension().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let Ok(rd) = std::fs::read_dir(dir) else { return vec![] };
    let mut names: Vec<String> = rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names.truncate(50);
    let mut scored: Vec<(u32, String)> = Vec::new();
    for f in names {
        let lf = f.to_lowercase();
        let fstem = Path::new(&lf).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let fext = Path::new(&lf).extension().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let mut score = if lf == lower {
            100
        } else if fstem == stem {
            90
        } else if lf.starts_with(&lower) || lower.starts_with(&lf) {
            70
        } else if lf.contains(&lower) {
            60
        } else if lower.contains(&lf) && lf.chars().count() > 2 {
            40
        } else if !e.is_empty() && fext == e {
            let a: HashSet<char> = lower.chars().collect();
            let b: HashSet<char> = lf.chars().collect();
            if a.intersection(&b).count() as f64 >= lower.chars().count().max(lf.chars().count()) as f64 * 0.4 {
                30
            } else {
                0
            }
        } else {
            0
        };
        if score == 0 && crate::fuzzy::similarity(&lower, &lf) >= 0.8 {
            score = 50;
        }
        if score > 0 {
            scored.push((score, dir.join(&f).display().to_string()));
        }
    }
    scored.sort_by_key(|s| std::cmp::Reverse(s.0));
    scored.into_iter().take(5).map(|s| s.1).collect()
}

/// Unresolved git merge-conflict blocks in `text`.
pub fn conflict_blocks(text: &str) -> usize {
    let mut n = 0;
    let mut state = 0;
    for l in text.lines() {
        let l = l.split_once('\t').map(|(_, r)| r).unwrap_or(l);
        if l.starts_with("<<<<<<< ") || l == "<<<<<<<" {
            state = 1;
        } else if state == 1 && l.starts_with("=======") {
            state = 2;
        } else if state == 2 && (l.starts_with(">>>>>>> ") || l == ">>>>>>>") {
            n += 1;
            state = 0;
        }
    }
    n
}

/// Trim line-numbered content to the last complete line within `max` chars:
/// (kept, lines kept, truncated).
pub fn char_budget(content: &str, max: usize) -> (String, usize, bool) {
    if content.chars().count() <= max {
        return (content.to_string(), if content.is_empty() { 0 } else { content.matches('\n').count() + 1 }, false);
    }
    let mut kept: Vec<&str> = Vec::new();
    let mut run = 0;
    for l in content.split('\n') {
        let add = l.chars().count() + usize::from(!kept.is_empty());
        if run + add > max {
            break;
        }
        kept.push(l);
        run += add;
    }
    if kept.is_empty() {
        let first = content.split('\n').next().unwrap_or("");
        let cut: String = first.chars().take(max).collect();
        return (cut, 1, true);
    }
    let n = kept.len();
    (kept.join("\n"), n, true)
}

/// Hint when a whole-file overwrite mostly re-sends what is on disk.
pub fn rewrite_hint(old: &str, new: &str) -> Option<String> {
    const MIN: usize = 20_000;
    const MAX: usize = 400_000;
    if !(MIN..=MAX).contains(&new.len()) || !(MIN..=MAX).contains(&old.len()) {
        return None;
    }
    let (ol, nl): (Vec<&str>, Vec<&str>) = (old.lines().collect(), new.lines().collect());
    if ol.is_empty() {
        return None;
    }
    let mut counts: HashMap<&str, isize> = HashMap::new();
    for l in &ol {
        *counts.entry(l).or_default() += 1;
    }
    let mut unchanged = 0;
    for l in &nl {
        if let Some(c) = counts.get_mut(l).filter(|c| **c > 0) {
            *c -= 1;
            unchanged += 1;
        }
    }
    let total = ol.len().max(nl.len());
    let ratio = unchanged as f64 / total as f64;
    if ratio < 0.80 {
        return None;
    }
    Some(format!("{unchanged} of {} lines were already on disk ({:.0}% unchanged); ~{} line(s) actually changed. Re-sending a {}-char file costs output tokens for every unchanged line; for edits like this use edit (old_string/new_string), which sends only the changed region.", nl.len(), ratio * 100.0, total - unchanged, new.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::tmpdir;

    #[test]
    fn baselines_from_full_or_contiguous_reads() {
        let d = tmpdir("fsbase");
        let f = d.join("a.txt");
        std::fs::write(&f, "1\n2\n3\n4\n").unwrap();
        let s = "sess-base";
        assert!(stale_overwrite_blocker(s, &f).unwrap().contains("has not seen its full"));
        let v = version(&f);
        record_read(s, &f, 1, 2, 2, 4, true, v);
        assert!(!has_baseline(s, &f), "half the file");
        record_read(s, &f, 3, 2, 4, 4, true, v);
        assert!(has_baseline(s, &f), "pages 1-2 + 3-4 cover everything");
        assert_eq!(stale_overwrite_blocker(s, &f), None);
        // External change after the read.
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&f, "changed!\n").unwrap();
        assert!(stale_overwrite_blocker(s, &f).unwrap().contains("modified since you last read it"));
        assert!(stale_overwrite_blocker(s, &d.join("new.txt")).is_none(), "net-new file");
    }

    #[test]
    fn sibling_writes_and_blind_patches() {
        let d = tmpdir("fssib");
        let f = d.join("b.txt");
        std::fs::write(&f, "x\n").unwrap();
        let (a, b) = ("sess-a", "sess-b");
        record_read(a, &f, 1, 2000, 1, 1, false, version(&f));
        std::thread::sleep(std::time::Duration::from_millis(10));
        std::fs::write(&f, "y\n").unwrap();
        note_edited(b, &f, true);
        let w = check_stale(a, &f).unwrap();
        assert!(w.contains("sibling agent \"sess-b\""), "{w}");
        assert!(edit_warning(a, &f).unwrap().contains("sibling"));
        assert_eq!(writes_since(a, 0.0, std::slice::from_ref(&f)).get(b).map(|v| v.len()), Some(1));
        // Blind edit then overwrite.
        let g = d.join("c.txt");
        std::fs::write(&g, "z\n").unwrap();
        note_edited("sess-c", &g, false);
        assert!(stale_overwrite_blocker("sess-c", &g).unwrap().contains("without a full view"));
        note_edited("sess-c", &g, true);
        assert!(stale_overwrite_blocker("sess-c", &g).is_none());
        forget_session(b);
        assert!(known_reads(b).is_empty());
    }

    #[test]
    fn dedup_stub_then_block_and_consecutive() {
        let d = tmpdir("fsdedup");
        let f = d.join("d.txt");
        std::fs::write(&f, "x\n").unwrap();
        let s = "sess-dedup";
        assert!(dedup_check(s, &f, 1, 2000).is_none());
        assert_eq!(record_read(s, &f, 1, 2000, 1, 1, false, version(&f)), 1);
        assert_eq!(dedup_check(s, &f, 1, 2000), Some(Ok(DEDUP_STATUS.to_string())));
        assert!(dedup_check(s, &f, 1, 2000).unwrap().unwrap_err().starts_with("BLOCKED"));
        reset_read_dedup(s);
        assert!(dedup_check(s, &f, 1, 2000).is_none());
        assert_eq!(record_read(s, &f, 1, 2000, 1, 1, false, version(&f)), 2);
        note_other_call(s);
        assert_eq!(record_read(s, &f, 1, 2000, 1, 1, false, version(&f)), 1);
    }

    #[test]
    fn path_lock_serializes() {
        let p = PathBuf::from("/tmp/ark-lock-test-path");
        let l = lock_path(&p);
        let p2 = p.clone();
        let t = std::thread::spawn(move || {
            let _g = lock_path(&p2);
            std::time::Instant::now()
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        let released = std::time::Instant::now();
        drop(l);
        assert!(t.join().unwrap() >= released);
    }

    #[test]
    fn guards() {
        assert!(blocked_device(Path::new("/dev/zero")) && blocked_device(Path::new("/proc/self/environ")) && blocked_device(Path::new("/dev/./urandom")));
        assert!(!blocked_device(Path::new("/etc/hostname")));
        assert!(read_block_error(Path::new("/x/proj/.env")).is_some());
        assert!(read_block_error(Path::new("/x/proj/.env.example")).is_none());
        assert!(sensitive_write_error(Path::new("/etc/passwd")).is_some() && sensitive_write_error(Path::new("/run/docker.sock")).is_some());
        assert!(sensitive_write_error(Path::new("/home/u/x")).is_none());
        assert!(is_protected_instruction(Path::new("/w/sub/CLAUDE.md")) && !is_protected_instruction(Path::new("/w/README.md")));
        assert!(binary_document_write_error(Path::new("/w/r.docx")).is_some());
        assert!(binary_document_write_error(Path::new("/w/x.db-wal")).is_some());
        assert!(binary_document_write_error(Path::new("/nonexistent/new.pdf")).is_none(), "new PDF allowed");
        assert!(internal_content_error("     1\tfoo\n     2\tbar\n     3\tbaz").is_some());
        assert!(internal_content_error(DEDUP_STATUS).is_some());
        assert!(internal_content_error("plain\ntext").is_none());
        let fifo = tmpdir("fifo").join("p");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
        assert_eq!(special_file_kind(&fifo), Some("a FIFO (named pipe)"));
    }

    #[test]
    fn containment_and_suggestions() {
        let d = tmpdir("contain");
        std::fs::create_dir_all(d.join("ws/sub")).unwrap();
        let ws = d.join("ws");
        assert!(contain(&ws, &ws.join("sub/new/x.txt")).is_ok());
        assert!(contain(&ws, &ws.join("../outside.txt")).unwrap_err().contains("escapes workspace root"));
        std::os::unix::fs::symlink(&d, ws.join("link")).unwrap();
        assert!(contain(&ws, &ws.join("link/x")).is_err(), "symlink escape");
        std::fs::write(ws.join("config.yaml"), "").unwrap();
        std::fs::write(ws.join("AGENTS.md"), "").unwrap();
        assert_eq!(similar_files(&ws.join("config.yml")), vec![ws.join("config.yaml").display().to_string()]);
        assert!(similar_files(&ws.join("AGENT.md")).iter().any(|s| s.ends_with("AGENTS.md")));
    }

    #[test]
    fn budget_conflicts_rewrite() {
        let (k, n, t) = char_budget("aaaa\nbbbb\ncccc", 10);
        assert_eq!((k.as_str(), n, t), ("aaaa\nbbbb", 2, true));
        assert_eq!(char_budget("x".repeat(20).as_str(), 5).0, "xxxxx");
        assert_eq!(conflict_blocks("<<<<<<< HEAD\na\n=======\nb\n>>>>>>> br\n"), 1);
        let old = (0..3000).map(|i| format!("line number {i}")).collect::<Vec<_>>().join("\n");
        let new = old.replace("line number 7\n", "line number seven\n");
        assert!(rewrite_hint(&old, &new).unwrap().contains("unchanged"));
        assert!(rewrite_hint("a", "b").is_none());
    }

    #[test]
    fn configure_parses_keys() {
        let c = parse_files(&serde_json::json!({"read_max_chars": 5, "workspace_only": true, "bogus": 1}));
        assert_eq!((c.read_max_chars, c.workspace_only, c.lint), (5, true, true));
        // `security_guidance` rides the same table (Hermes `plugins/security-guidance`).
        assert!(c.security_guidance, "on by default like lint");
        assert!(!parse_files(&serde_json::json!({"security_guidance": false})).security_guidance);
        assert_eq!(parse_files(&serde_json::json!({})), FilesConfig::default());
    }
}
