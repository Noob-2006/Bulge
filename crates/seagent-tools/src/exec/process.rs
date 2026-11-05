//! Background process registry shared by `job`, `process`, `shell` (a command that
//! outlives its `yield_ms` becomes a process here) and `terminal` panes.
//!
//! One entry per process: the backend child, the command, the session that started
//! it, a log file (the full transcript) and a rolling buffer of the last
//! `process_buffer_bytes` bytes (Hermes `process_registry`). A pump thread reads the
//! child's merged output into both. `exit` is set once the child ends, and a
//! `detach`-ed process survives an seagent restart through its `.json` snapshot
//! (pid + start time + log + exit file), which [`restore`] reads back.

use seagent_core::exec::{ExecBackend, ExecChild, ExitInfo};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How much of a log file one `log` page reads (older bytes are counted, not loaded).
const MAX_LOG_READ: u64 = 8 * 1024 * 1024;

pub struct Entry {
    pub id: u32,
    pub session: String,
    pub command: String,
    pub pty: bool,
    pub log: PathBuf,
    pub started: Instant,
    pub child: Arc<Mutex<Box<dyn ExecChild>>>,
    pub backend: Arc<dyn ExecBackend>,
    /// Rolling buffer: last `buffer_cap` bytes of output.
    pub buf: Vec<u8>,
    pub buffer_cap: usize,
    pub exit: Option<i32>,
    /// Detached processes keep running when this entry is dropped; their output is
    /// read from the log file (a wrapper writes it), never re-written by the pump.
    pub detached: bool,

    /// Host pid of the process, when it has one (needed for `handoff` and snapshots).
    pub pid: Option<u32>,
    /// `/proc/<pid>/stat` start time: tells a reused pid from ours.
    pub start: Option<u64>,
    /// Exit status file of a detached process (`echo $? > exit`).
    pub exit_file: Option<PathBuf>,
    /// Unix start time, for snapshots and `elapsed` after a restore.
    pub started_at: u64,
    /// Absolute offset of `buf[0]` in the whole output stream.
    pub buf_start: u64,
    /// Bytes seen so far (monotonic; survives buffer trimming).
    pub total: u64,
    /// Last output instant (OpenClaw `idleMs` / input-wait hint).
    pub last_output: Instant,
    /// Snapshot file of a restart-surviving process.
    pub snapshot: Option<PathBuf>,
    /// Deliver a completion notice into the session when the process exits.
    pub notify: bool,
    /// Word before the id in a completion notice (`"job "` → `Background process job 3`).
    pub label: String,
    /// Which surface started it (`job`, `shell`, `terminal`, …); `job` lists only its own.
    pub origin: String,
    /// Supervision was handed off: no completion notice, no waiting on it.
    pub handed_off: bool,
    /// The child's stdin is a pipe or PTY we can write to.
    pub stdin_open: bool,
    /// Adopted from a snapshot after a restart (no live child handle).
    pub restored: bool,
}

/// What a caller sees about one process.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: u32,
    pub session: String,
    pub command: String,
    pub running: bool,
    pub exit: Option<i32>,
    pub pty: bool,
    pub elapsed: Duration,
    pub bytes: u64,
    pub log: PathBuf,
    pub pid: Option<u32>,
    pub origin: String,
    pub detached: bool,
    pub stdin: bool,
    /// Time since this process last wrote output (OpenClaw `idleMs`).
    pub idle: Duration,
}

/// How [`add`] builds an entry.
#[derive(Clone, Default)]
pub struct Options {
    pub pty: bool,
    pub buffer_cap: usize,
    pub detached: bool,
    pub stdin: bool,
    pub notify: bool,
    pub label: String,
    pub origin: String,
    /// Write a snapshot so a restarted seagent can adopt the process again.
    pub persist: Option<Persist>,
}

/// What a snapshot needs to adopt a detached process after a restart.
#[derive(Clone, Debug, Default)]
pub struct Persist {
    /// `<home>/jobs`: where `<id>.json` lives.
    pub dir: PathBuf,
    pub pid: u32,
    pub start: Option<u64>,
    pub exit_file: PathBuf,
    pub scope: String,
    pub backend: String,
}

/// `<home>/jobs/<id>.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: u32,
    pub session: String,
    pub command: String,
    pub pid: u32,
    #[serde(default)]
    pub start: Option<u64>,
    pub log: PathBuf,
    pub exit_file: PathBuf,
    #[serde(default)]
    pub pty: bool,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub started_at: u64,
    #[serde(default)]
    pub buffer_cap: usize,
    #[serde(default)]
    pub origin: String,
}

fn registry() -> &'static Mutex<BTreeMap<u32, Arc<Mutex<Entry>>>> {
    static R: OnceLock<Mutex<BTreeMap<u32, Arc<Mutex<Entry>>>>> = OnceLock::new();
    R.get_or_init(Default::default)
}

/// Ids are handed out from here: a caller that must name files before spawning
/// (`job` writes the log / exit-file paths into the request) takes one first, and
/// two parallel starts can never take the same id.
static NEXT_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// A process id nothing else holds (ids are never reused within one seagent run).
pub fn next_free_id() -> u32 {
    use std::sync::atomic::Ordering;
    loop {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let taken = registry().lock().unwrap().contains_key(&id);
        if !taken {
            return id;
        }
    }
}

/// Keep the counter above the ids of processes adopted from snapshots.
fn bump_ids(max: u32) {
    use std::sync::atomic::Ordering;
    NEXT_ID.fetch_max(max.saturating_add(1), Ordering::Relaxed);
}

/// Start pumping a child into the registry under a new id.
pub fn register(session: &str, command: &str, child: Box<dyn ExecChild>, backend: Arc<dyn ExecBackend>, log: PathBuf, pty: bool, buffer_cap: usize) -> Arc<Mutex<Entry>> {
    let opts = Options { pty, buffer_cap, stdin: child.is_pty(), origin: "process".into(), ..Default::default() };
    add(None, session, command, child, backend, log, opts).unwrap_or_else(|e| panic!("register: {e}"))
}

/// Start pumping a child under a caller-chosen id (so `job` and `process` agree on it).
pub fn register_named(id: u32, session: &str, command: &str, child: Box<dyn ExecChild>, backend: Arc<dyn ExecBackend>, log: PathBuf, opts: Options) -> Result<Arc<Mutex<Entry>>, String> {
    add(Some(id), session, command, child, backend, log, opts)
}

/// Register a spawned child: rolling buffer + log file + completion notice.
pub fn add(id: Option<u32>, session: &str, command: &str, child: Box<dyn ExecChild>, backend: Arc<dyn ExecBackend>, log: PathBuf, opts: Options) -> Result<Arc<Mutex<Entry>>, String> {
    let cap = opts.buffer_cap.max(4096);
    let child_pid = child.pid();
    let id = match id {
        Some(i) => i,
        None => next_free_id(),
    };
    if registry().lock().unwrap().contains_key(&id) {
        return Err(format!("process id {id} is already in use"));
    }
    // Output written before the process was registered (a `shell` call that yielded
    // after it had printed something) belongs to the buffer too.
    let (mut seeded, mut seeded_start) = (Vec::new(), 0u64);
    if !opts.detached {
        if let Ok(mut f) = File::open(&log) {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            let skip = len.saturating_sub(cap as u64);
            if len > 0 {
                let _ = f.seek(SeekFrom::Start(skip));
                let _ = f.read_to_end(&mut seeded);
                seeded_start = skip;
            }
        }
    }
    let entry = Arc::new(Mutex::new(Entry {
        id,
        session: session.to_string(),
        command: command.to_string(),
        pty: opts.pty,
        log,
        started: Instant::now(),
        child: Arc::new(Mutex::new(child)),
        backend,
        buf: seeded,
        buffer_cap: cap,
        exit: None,
        detached: opts.detached,
        pid: opts.persist.as_ref().map(|p| p.pid).or(child_pid),
        start: opts.persist.as_ref().and_then(|p| p.start),
        exit_file: opts.persist.as_ref().map(|p| p.exit_file.clone()),
        started_at: now_secs(),
        buf_start: seeded_start,
        total: seeded_start,
        last_output: Instant::now(),
        snapshot: None,
        notify: opts.notify,
        label: opts.label,
        origin: opts.origin,
        handed_off: false,
        stdin_open: opts.stdin,
        restored: false,
    }));
    let mut reg = registry().lock().unwrap();
    if reg.contains_key(&id) {
        return Err(format!("process id {id} is already in use"));
    }
    reg.insert(id, entry.clone());
    drop(reg);
    if let Some(p) = &opts.persist {
        let path = write_record(&entry, p);
        entry.lock().unwrap().snapshot = path;
    }
    pump(entry.clone());
    Ok(entry)
}

/// Write `<dir>/<id>.json` for a process that must survive a restart.
fn write_record(entry: &Arc<Mutex<Entry>>, p: &Persist) -> Option<PathBuf> {
    let e = entry.lock().unwrap();
    let rec = Record {
        id: e.id,
        session: e.session.clone(),
        command: e.command.clone(),
        pid: p.pid,
        start: p.start,
        log: e.log.clone(),
        exit_file: p.exit_file.clone(),
        pty: e.pty,
        scope: p.scope.clone(),
        backend: p.backend.clone(),
        started_at: e.started_at,
        buffer_cap: e.buffer_cap,
        origin: e.origin.clone(),
    };
    drop(e);
    let _ = std::fs::create_dir_all(&p.dir);
    let path = record_path(&p.dir, rec.id);
    let data = serde_json::to_vec_pretty(&rec).ok()?;
    crate::util::atomic_write(&path, &data).ok()?;
    Some(path)
}

/// `<dir>/<id>.json`.
pub fn record_path(dir: &Path, id: u32) -> PathBuf {
    dir.join(format!("{id}.json"))
}

fn pump(entry: Arc<Mutex<Entry>>) {
    std::thread::spawn(move || {
        let (child, log, cap, detached) = {
            let e = entry.lock().unwrap();
            (e.child.clone(), e.log.clone(), e.buffer_cap, e.detached)
        };
        // A detached child already writes the log through its wrapper shell.
        let mut file = if detached { None } else { OpenOptions::new().create(true).append(true).open(&log).ok() };
        let mut buf = [0u8; 16384];
        loop {
            let n = {
                let mut c = child.lock().unwrap();
                match c.read(&mut buf, Duration::from_millis(50)) {
                    Ok(n) => n,
                    Err(_) => {
                        // Hands the child back: a tight re-lock loop starves a writer
                        // (and a `process write` must never wait seconds for the pump).
                        drop(c);
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                }
            };
            if n == 0 {
                break;
            }
            if let Some(f) = file.as_mut() {
                let _ = f.write_all(&buf[..n]);
                let _ = f.flush();
            }
            let mut e = entry.lock().unwrap();
            e.total += n as u64;
            e.buf.extend_from_slice(&buf[..n]);
            if e.buf.len() > cap {
                let cut = e.buf.len() - cap;
                e.buf.drain(..cut);
                e.buf_start += cut as u64;
            }
            e.last_output = Instant::now();
            drop(e);
        }
        // Record the exit status, giving the child one last moment to reap.
        let mut code = None;
        for _ in 0..200 {
            let st = { child.lock().unwrap().try_wait().ok().flatten() };
            match st {
                Some(st) => {
                    code = Some(st.code.unwrap_or_else(|| -st.signal.unwrap_or(1)));
                    break;
                }
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        let notice = {
            let mut e = entry.lock().unwrap();
            e.exit = Some(code.unwrap_or(-1));
            e.stdin_open = false;
            notice_text(&e).map(|text| (e.session.clone(), text))
        };
        // The notifier runs without the entry lock: it delivers into the session (and may
        // take locks of its own), so holding one process's entry here would stall any
        // `list`/`kill` that needs it.
        if let Some((session, text)) = notice {
            super::global().notify(&session, &text);
        }
    });
}

/// Completion notice into the owning session (Hermes `format_process_notification`).
fn notice_text(e: &Entry) -> Option<String> {
    if !e.notify || e.handed_off {
        return None;
    }
    let code = e.exit.unwrap_or(-1);
    let status = if code == 0 { "completed normally" } else if code == -9 { "terminated by kill" } else { "exited" };
    let tail = tail_of(e, 4096);
    Some(format!(
        "[IMPORTANT: Background process {}{} {status} (exit code {code}).\nCommand: {}\nOutput:\n{}]",
        e.label,
        e.id,
        e.command,
        tail.trim_end()
    ))
}

impl Entry {
    pub fn running(&self) -> bool {
        self.exit.is_none()
    }
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            id: self.id,
            session: self.session.clone(),
            command: self.command.clone(),
            running: self.running(),
            exit: self.exit,
            pty: self.pty,
            elapsed: self.started.elapsed(),
            bytes: std::fs::metadata(&self.log).map(|m| m.len()).unwrap_or(self.buf.len() as u64),
            log: self.log.clone(),
            pid: self.pid,
            origin: self.origin.clone(),
            detached: self.detached,
            stdin: self.stdin_open && self.exit.is_none(),
            idle: self.last_output.elapsed(),
        }
    }
    /// Milliseconds since this process last wrote anything (OpenClaw `idleMs`).
    pub fn idle_ms(&self) -> u64 {
        self.last_output.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

fn tail_of(e: &Entry, n: usize) -> String {
    let start = e.buf.len().saturating_sub(n);
    let kept = &e.buf[start..];
    let total = std::fs::metadata(&e.log).map(|m| m.len()).unwrap_or(kept.len() as u64);
    let earlier = total.saturating_sub(kept.len() as u64);
    let text = String::from_utf8_lossy(kept).into_owned();
    if earlier > 0 {
        format!("…[{earlier} earlier bytes in {}]\n{text}", e.log.display())
    } else {
        text
    }
}

/// Look up one process, checking it belongs to `session`.
pub fn get(session: &str, id: u32) -> Option<Arc<Mutex<Entry>>> {
    let e = registry().lock().unwrap().get(&id).cloned()?;
    let mine = e.lock().unwrap().session == session;
    mine.then_some(e)
}

/// All processes of a session, oldest first.
pub fn list(session: &str) -> Vec<Snapshot> {
    // Snapshot outside the registry lock: an entry lock is held by a caller that is
    // mid-read/mid-kill, and no process bookkeeping should queue behind that.
    let all: Vec<Arc<Mutex<Entry>>> = registry().lock().unwrap().values().cloned().collect();
    all.into_iter().filter_map(|e| {
        let e = e.lock().unwrap();
        (e.session == session).then(|| e.snapshot())
    }).collect()
}

/// Snapshot of one process.
pub fn poll(session: &str, id: u32) -> Option<Snapshot> {
    get(session, id).map(|e| e.lock().unwrap().snapshot())
}

/// Output of one process: the newest `n` bytes, or everything after `offset`.
pub fn tail(session: &str, id: u32, n: usize) -> Option<String> {
    let arc = get(session, id)?;
    let e = arc.lock().unwrap();
    Some(tail_of(&e, n))
}

/// Everything in the rolling buffer since `offset` (bytes), plus the new offset.
pub fn read_from(session: &str, id: u32, offset: usize) -> Option<(String, usize)> {
    let arc = get(session, id)?;
    let e = arc.lock().unwrap();
    let start = offset.min(e.buf.len());
    Some((String::from_utf8_lossy(&e.buf[start..]).into_owned(), e.buf.len()))
}

/// Output written since `offset` in the whole output stream (absolute byte
/// offset, the one [`poll`] callers keep): (text, new offset, bytes dropped
/// because the rolling buffer moved on). Polls do not consume output in Hermes
/// either — the model's cursor lives here, not in the entry.
pub fn read_since(session: &str, id: u32, offset: u64) -> Option<(String, u64, u64)> {
    let arc = get(session, id)?;
    let e = arc.lock().unwrap();
    let from = offset.max(e.buf_start);
    let dropped = from - offset;
    let start = (from - e.buf_start) as usize;
    Some((String::from_utf8_lossy(&e.buf[start..]).into_owned(), e.buf_start + e.buf.len() as u64, dropped))
}

/// One page of a process log, read from the log file (the complete transcript).
pub struct Page {
    pub text: String,
    pub total_lines: usize,
    pub shown: usize,
    /// Bytes of the log before the window that was read (never loaded).
    pub earlier_bytes: u64,
    /// True when `offset`/`limit` were not given and the tail was returned.
    pub tail: bool,
}

/// `offset`/`limit` are line numbers (Hermes `read_log`): no offset = the last
/// `limit` lines. ANSI escapes are stripped; a PTY log is rendered the way a
/// terminal would show it (carriage-return overwrites collapsed).
pub fn log_page(session: &str, id: u32, offset: Option<usize>, limit: usize) -> Result<Page, String> {
    let arc = get(session, id).ok_or_else(|| format!("unknown process id {id}; use action=list"))?;
    let e = arc.lock().unwrap();
    let pty = e.pty;
    let log = e.log.clone();
    drop(e);
    let mut f = File::open(&log).map_err(|err| format!("cannot read {}: {err}", log.display()))?;
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let skip = len.saturating_sub(MAX_LOG_READ);
    if skip > 0 {
        let _ = f.seek(SeekFrom::Start(skip));
    }
    let mut data = Vec::new();
    let _ = f.read_to_end(&mut data);
    let raw = String::from_utf8_lossy(&data).into_owned();
    let text = if pty { super::ansi::render_terminal_text(&raw) } else { super::ansi::strip_ansi(&raw).into_owned() };
    let lines: Vec<&str> = text.lines().collect();
    let total_lines = lines.len();
    let limit = limit.max(1);
    let (selected, tail) = match offset {
        None => (&lines[total_lines.saturating_sub(limit)..], true),
        Some(o) => (&lines[o.min(total_lines)..(o.saturating_add(limit)).min(total_lines)], false),
    };
    Ok(Page { text: selected.join("\n"), total_lines, shown: selected.len(), earlier_bytes: skip, tail })
}

/// The absolute offset just past the newest byte (where a poll cursor starts).
pub fn offset_now(session: &str, id: u32) -> Option<u64> {
    let arc = get(session, id)?;
    let e = arc.lock().unwrap();
    Some(e.buf_start + e.buf.len() as u64)
}

pub fn write(session: &str, id: u32, data: &[u8]) -> Result<(), String> {
    let arc = get(session, id).ok_or_else(|| "unknown process id; use action=list".to_string())?;
    let (child, running, exit) = {
        let e = arc.lock().unwrap();
        (e.child.clone(), e.running(), e.exit)
    };
    if !running {
        return Err(format!("process {id} has exited ({})", exit.unwrap_or(-1)));
    }
    let r = child.lock().unwrap().write_stdin(data);
    r.map_err(|e| format!("write: {e}"))
}

/// Write and keep the entry's "stdin is open" flag honest.
pub fn write_tracked(session: &str, id: u32, data: &[u8]) -> Result<(), String> {
    write(session, id, data)?;
    if let Some(arc) = get(session, id) {
        arc.lock().unwrap().stdin_open = true;
    }
    Ok(())
}

pub fn close_stdin(session: &str, id: u32) -> Result<(), String> {
    let arc = get(session, id).ok_or_else(|| "unknown process id".to_string())?;
    let (child, running) = {
        let e = arc.lock().unwrap();
        (e.child.clone(), e.running())
    };
    if !running {
        return Err(format!("process {id} has already exited ({})", arc.lock().unwrap().exit.unwrap_or(-1)));
    }
    child.lock().unwrap().close_stdin();
    arc.lock().unwrap().stdin_open = false;
    Ok(())
}

pub fn kill(session: &str, id: u32) -> Result<(), String> {
    let arc = get(session, id).ok_or_else(|| "unknown process id".to_string())?;
    // Signalling happens without the entry lock: the child lock is taken by the pump (and
    // by a pane reader), and a blocked signal would otherwise freeze the whole entry.
    let (child, pid) = {
        let e = arc.lock().unwrap();
        (e.child.clone(), e.pid)
    };
    child.lock().unwrap().kill(true);
    // A restored / tapped entry has no live child handle of its own: signal the
    // process group by pid (`setsid` gives a detached process pgid == pid).
    if let Some(pid) = pid {
        // SAFETY: signal only; never to pid 0/1.
        if pid > 1 {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }
    let mut e = arc.lock().unwrap();
    e.exit.get_or_insert(-9);
    e.stdin_open = false;
    Ok(())
}

/// Forget a finished process (its log file stays).
pub fn remove(session: &str, id: u32) -> Result<(), String> {
    let mut reg = registry().lock().unwrap();
    match reg.get(&id) {
        Some(e) if e.lock().unwrap().session == session => {
            let e = e.lock().unwrap();
            if e.running() {
                return Err(format!("process {id} is still running; kill it first (or action=handoff)"));
            }
            let snap = e.snapshot.clone();
            drop(e);
            reg.remove(&id);
            if let Some(s) = snap {
                let _ = std::fs::remove_file(s);
            }
            Ok(())
        }
        _ => Err(format!("unknown process id {id}; use action=list")),
    }
}

/// Drop an entry without touching the process (restart simulation, `handoff`).
pub fn forget(session: &str, id: u32) -> bool {
    let mut reg = registry().lock().unwrap();
    match reg.get(&id) {
        Some(e) if e.lock().unwrap().session == session => {
            reg.remove(&id);
            true
        }
        _ => false,
    }
}

/// Drop the buffered output of a process (the log file is truncated too).
pub fn clear(session: &str, id: u32) -> Result<(), String> {
    let arc = get(session, id).ok_or_else(|| format!("unknown process id {id}; use action=list"))?;
    let mut e = arc.lock().unwrap();
    e.total = e.buf_start;
    e.buf.clear();
    if let Ok(f) = File::create(&e.log) {
        drop(f);
    }
    Ok(())
}

/// Push a file's content back into the buffer (used after a restart).
pub fn adopt_log(session: &str, id: u32, log: &Path) -> Option<Snapshot> {
    let arc = get(session, id)?;
    let mut e = arc.lock().unwrap();
    if let Ok(mut f) = File::open(log) {
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        let skip = len.saturating_sub(e.buffer_cap as u64);
        let _ = f.seek(SeekFrom::Start(skip));
        let mut data = Vec::new();
        let _ = f.read_to_end(&mut data);
        e.buf = data;
        e.buf_start = skip;
        e.total = len;
    }
    Some(e.snapshot())
}

/// Wait for a process to exit, at most `timeout`.
pub fn wait(session: &str, id: u32, timeout: Duration) -> Option<Snapshot> {
    wait_with(session, id, timeout, || false)
}

/// [`wait`], released early when `cancelled` turns true (a new user message).
pub fn wait_with(session: &str, id: u32, timeout: Duration, cancelled: impl Fn() -> bool) -> Option<Snapshot> {
    let deadline = Instant::now() + timeout;
    loop {
        let s = poll(session, id)?;
        if !s.running || Instant::now() >= deadline || cancelled() {
            return Some(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn read_exit_file(p: &Path) -> Option<i32> {
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}

/// Adopt the detached processes recorded under `dir` (`<home>/jobs`) that this
/// registry does not already hold: an seagent restart keeps running processes and
/// their finished transcripts visible to `process list` / `poll` / `log`.
///
/// A process whose pid (and start time) is still alive is `running`; one whose
/// exit-file has a status is `exited`; one that vanished without a status shows
/// `exited (-1)`. Returns how many entries were adopted.
pub fn restore(dir: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
    files.sort();
    let mut n = 0;
    let mut max_id = 0;
    for f in files {
        if f.to_string_lossy().ends_with(".handoff.json") {
            continue; // a handoff released supervision: the record is a note, not a process to adopt
        }
        let Ok(txt) = std::fs::read_to_string(&f) else { continue };
        let Ok(rec) = serde_json::from_str::<Record>(&txt) else { continue };
        max_id = max_id.max(rec.id);
        if registry().lock().unwrap().contains_key(&rec.id) {
            continue;
        }
        let cap = if rec.buffer_cap == 0 { 200_000 } else { rec.buffer_cap.max(4096) };
        let len = std::fs::metadata(&rec.log).map(|m| m.len()).unwrap_or(0);
        let skip = len.saturating_sub(cap as u64);
        let mut buffered = Vec::new();
        if let Ok(mut lf) = File::open(&rec.log) {
            if lf.seek(SeekFrom::Start(skip)).is_ok() {
                let _ = lf.read_to_end(&mut buffered);
            }
        }
        let alive = super::local::pid_alive(rec.pid, rec.start);
        let exit = if alive { None } else { Some(read_exit_file(&rec.exit_file).unwrap_or(-1)) };
        let Ok(child) = super::local::LocalChild::reattach(rec.pid, rec.start, &rec.log, &rec.exit_file, len) else { continue };
        let started = Instant::now().checked_sub(Duration::from_secs(now_secs().saturating_sub(rec.started_at))).unwrap_or_else(Instant::now);
        let entry = Arc::new(Mutex::new(Entry {
            id: rec.id,
            session: rec.session.clone(),
            command: rec.command.clone(),
            pty: rec.pty,
            log: rec.log.clone(),
            started,
            child: Arc::new(Mutex::new(Box::new(child) as Box<dyn ExecChild>)),
            backend: Arc::new(super::local::LocalBackend::new()),
            buf: buffered,
            buffer_cap: cap,
            exit,
            detached: true,
            pid: Some(rec.pid),
            start: rec.start,
            exit_file: Some(rec.exit_file.clone()),
            started_at: rec.started_at,
            buf_start: skip,
            total: len,
            last_output: Instant::now(),
            snapshot: Some(f.clone()),
            notify: false,
            label: String::new(),
            origin: rec.origin.clone(),
            handed_off: false,
            stdin_open: false,
            restored: true,
        }));
        registry().lock().unwrap().insert(rec.id, entry.clone());
        if alive {
            pump(entry);
        }
        n += 1;
    }
    bump_ids(max_id);
    n
}

/// A second handle on a live entry's output stream (and its stdin): `terminal`
/// panes read through this so one child has exactly one reader.
pub fn tap(entry: &Arc<Mutex<Entry>>) -> Box<dyn ExecChild> {
    Box::new(Tap { entry: Arc::downgrade(entry), cursor: 0, dropped: 0 })
}

struct Tap {
    entry: Weak<Mutex<Entry>>,
    cursor: u64,
    dropped: u64,
}

impl ExecChild for Tap {
    fn pid(&self) -> Option<u32> {
        self.entry.upgrade().and_then(|e| e.lock().unwrap().pid)
    }
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> std::io::Result<usize> {
        let Some(entry) = self.entry.upgrade() else { return Ok(0) };
        {
            let e = entry.lock().unwrap();
            if self.cursor < e.buf_start {
                self.dropped += e.buf_start - self.cursor;
                self.cursor = e.buf_start;
            }
            let off = (self.cursor - e.buf_start) as usize;
            if off < e.buf.len() {
                let n = buf.len().min(e.buf.len() - off);
                buf[..n].copy_from_slice(&e.buf[off..off + n]);
                self.cursor += n as u64;
                return Ok(n);
            }
            if e.exit.is_some() {
                return Ok(0);
            }
        }
        std::thread::sleep(timeout.min(Duration::from_millis(50)));
        Err(std::io::ErrorKind::TimedOut.into())
    }
    fn write_stdin(&mut self, data: &[u8]) -> std::io::Result<()> {
        let Some(entry) = self.entry.upgrade() else { return Err(std::io::ErrorKind::BrokenPipe.into()) };
        let child = entry.lock().unwrap().child.clone();
        let r = child.lock().unwrap().write_stdin(data);
        r
    }
    fn close_stdin(&mut self) {
        let Some(entry) = self.entry.upgrade() else { return };
        let child = entry.lock().unwrap().child.clone();
        child.lock().unwrap().close_stdin();
    }
    /// The exit status, once this handle has handed over every buffered byte: a
    /// consumer that stops at the first `try_wait` hit would drop the tail of the
    /// output the process wrote just before exiting.
    fn try_wait(&mut self) -> std::io::Result<Option<ExitInfo>> {
        let Some(entry) = self.entry.upgrade() else { return Ok(Some(ExitInfo { code: None, signal: None })) };
        let e = entry.lock().unwrap();
        let drained = self.cursor.max(e.buf_start) >= e.buf_start + e.buf.len() as u64;
        Ok(match e.exit {
            Some(c) if drained => Some(ExitInfo::code(c)),
            _ => None,
        })
    }
    fn kill(&mut self, force: bool) {
        let Some(entry) = self.entry.upgrade() else { return };
        let child = entry.lock().unwrap().child.clone();
        child.lock().unwrap().kill(force);
    }
    fn resize(&mut self, rows: u16, cols: u16) -> std::io::Result<()> {
        let Some(entry) = self.entry.upgrade() else { return Err(std::io::ErrorKind::BrokenPipe.into()) };
        let child = entry.lock().unwrap().child.clone();
        let r = child.lock().unwrap().resize(rows, cols);
        r
    }
    fn is_pty(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::exec::ExecRequest;

    fn ctxmap(tag: &str) -> (PathBuf, PathBuf) {
        let d = crate::testutil::tmpdir(tag);
        let home = d.join("home");
        std::fs::create_dir_all(&home).unwrap();
        (d, home)
    }

    fn local() -> Arc<dyn ExecBackend> {
        Arc::new(super::super::local::LocalBackend::new())
    }

    fn spawn(ws: &Path, script: &str, stdin: bool, log: &Path) -> Box<dyn ExecChild> {
        let req = ExecRequest { script: script.into(), cwd: Some(ws.to_path_buf()), stdin, ..Default::default() };
        let _ = std::fs::write(log, b"");
        local().spawn(&req).unwrap()
    }

    /// `[exec] process_buffer_bytes`: keep the last `cap` bytes, note how much was omitted.
    #[test]
    fn rolling_buffer_keeps_the_tail_and_notes_omitted_bytes() {
        let (ws, _home) = ctxmap("procbuf");
        let log = ws.join("p.log");
        let child = spawn(&ws, "head -c 300000 /dev/zero | tr '\\0' a; echo; echo LAST", false, &log);
        let e = register("s", "big", child, local(), log.clone(), false, 8192);
        let id = e.lock().unwrap().id;
        let snap = wait("s", id, Duration::from_secs(10)).unwrap();
        assert!(!snap.running);
        assert_eq!(super::get("s", id).unwrap().lock().unwrap().buf.len(), 8192, "buffer is capped");
        let t = tail("s", snap.id, 8192).unwrap();
        assert!(t.contains("LAST") && t.contains("[") && t.contains("earlier bytes in"), "{t:.200}");
        // The cap applies to the buffered tail; the marker line naming the log path sits on top
        // and its length depends on TMPDIR, so bound the body, not the whole string.
        let marker = t.lines().find(|l| l.contains("earlier bytes in")).map(|l| l.len()).unwrap_or(0);
        assert!(t.len() <= 8192 + marker + 1, "only the tail plus the marker: {} bytes (marker {marker}): {t:.400}", t.len());
        let page = log_page("s", snap.id, None, 5).unwrap();
        assert!(page.text.contains("LAST") && page.total_lines >= 1);
        assert!(std::fs::metadata(&log).unwrap().len() > 300_000, "the full transcript is kept");
        // Only the tail is returned, the head is counted, not loaded.
        assert_eq!(log_page("s", snap.id, Some(0), 1).unwrap().shown, 1);
    }

    #[test]
    fn write_submit_close_and_wait_timeout() {
        let (ws, _home) = ctxmap("procwrite");
        let log = ws.join("cat.log");
        let child = spawn(&ws, "cat", true, &log);
        let id = register("ws", "cat", child, local(), log.clone(), false, 200_000).lock().unwrap().id;
        assert!(wait("ws", id, Duration::from_millis(0)).unwrap().running, "timeout_ms 0 returns at once");
        write("ws", id, b"hello\n").unwrap();
        let t = wait_output("ws", id, "hello");
        assert!(t.contains("hello"), "{t}");
        let t = tail("ws", id, 4096).unwrap();
        assert!(t.contains("hello"));
        close_stdin("ws", id).unwrap();
        let snap = wait("ws", id, Duration::from_secs(5)).unwrap();
        assert!(!snap.running, "stdin closed → cat exits");
        assert_eq!(snap.exit, Some(0));
        assert!(write("ws", id, b"x").unwrap_err().contains("has exited"));
        assert_eq!(read_since("ws", id, 0).unwrap().0, "hello\n");
    }

    fn wait_output(session: &str, id: u32, needle: &str) -> String {
        let t0 = Instant::now();
        loop {
            let t = tail(session, id, 8192).unwrap_or_default();
            if t.contains(needle) || t0.elapsed() > Duration::from_secs(5) {
                return t;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A detached process survives an seagent restart: the snapshot is written before
    /// the entry is dropped, and `restore` adopts it again — running first, then exited.
    #[test]
    fn detached_process_is_restored_after_a_restart() {
        let (ws, home) = ctxmap("procrestore");
        let dir = home.join("jobs");
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("7.log");
        let exit_file = dir.join("7.exit");
        let _ = std::fs::remove_file(&exit_file);
        let _ = std::fs::remove_file(&log);
        let req = ExecRequest {
            script: "sleep 1; echo done".into(),
            cwd: Some(ws.clone()),
            detach: true,
            log_file: Some(log.clone()),
            exit_file: Some(exit_file.clone()),
            ..Default::default()
        };
        let child = local().spawn(&req).unwrap();
        let pid = child.pid().unwrap();
        let start = super::super::local::proc_start_time(pid);
        assert!(super::super::local::pid_alive(pid, start));
        let opts = Options {
            detached: true,
            origin: "job".into(),
            persist: Some(Persist { dir: dir.clone(), pid, start, exit_file: exit_file.clone(), scope: "host-s".into(), backend: "local".into() }),
            ..Default::default()
        };
        let id = 7;
        register_named(id, "rs", "sleep 1; echo done", child, local(), log.clone(), opts).unwrap();
        assert!(record_path(&dir, id).exists(), "snapshot written");
        let rec: Record = serde_json::from_str(&std::fs::read_to_string(record_path(&dir, id)).unwrap()).unwrap();
        assert_eq!((rec.pid, rec.id, rec.session.as_str()), (pid, id, "rs"));

        // seagent dies: the entry (and its handle) is gone, the detached process is not.
        assert!(forget("rs", id));
        assert!(poll("rs", id).is_none());
        assert!(super::super::local::pid_alive(pid, start), "detached process outlived its entry");

        // A fresh seagent reads the snapshots back.
        assert_eq!(restore(&dir), 1, "one process adopted");
        let snap = poll("rs", id).unwrap();
        assert!(snap.running, "restored while still alive");
        assert_eq!((snap.pid, snap.detached, snap.log.clone()), (Some(pid), true, log.clone()));
        assert_eq!(restore(&dir), 0, "restoring twice is a no-op");
        let snap = wait("rs", id, Duration::from_secs(10)).unwrap();
        assert!(!snap.running);
        assert_eq!(snap.exit, Some(0), "exit status came from the exit file");
        let t = tail("rs", id, 4096).unwrap();
        assert!(t.contains("done"), "log adopted: {t:?}");
        assert!(remove("rs", id).is_ok() && !record_path(&dir, id).exists(), "removing forgets the snapshot");
    }

    /// A tap lets a second consumer (the `terminal` pane) read a live entry and
    /// still write to the same child.
    #[test]
    fn tap_tee_reads_and_writes() {
        let (ws, _home) = ctxmap("proctap");
        let log = ws.join("tap.log");
        let child = spawn(&ws, "echo ready; cat", true, &log);
        let e = register("t", "tee", child, local(), log, false, 200_000);
        let id = e.lock().unwrap().id;
        let mut tap = super::tap(&e);
        let mut buf = [0u8; 256];
        let mut got = Vec::new();
        for _ in 0..50 {
            match tap.read(&mut buf, Duration::from_millis(50)) {
                Ok(0) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
                Err(_) => {}
            }
            if String::from_utf8_lossy(&got).contains("ready") {
                break;
            }
        }
        assert!(String::from_utf8_lossy(&got).contains("ready"));
        tap.write_stdin(b"ping\n").unwrap();
        assert!(wait_output("t", id, "ping").contains("ping"));
        tap.kill(true);
        assert!(!wait("t", id, Duration::from_secs(5)).unwrap().running);
    }
}
