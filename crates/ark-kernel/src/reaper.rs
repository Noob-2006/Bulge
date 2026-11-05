//! Orphaned process groups (section C7): the registry, the guarded killer and the sweep.
//!
//! Every command ark starts gets its own process group (`setpgid(0,0)` for pipes, `setsid()`
//! for a PTY or a detached job), so the group id equals the child's pid. `ark-tools` appends
//! one line per spawned child to `<home>/reaper/procs.jsonl`
//! (`{"pgid","start","session","tool","ark_pid","ts_ms"}`); this module decides what to do
//! with those groups when nobody is left to wait for them.
//!
//! Design answers (audit §0):
//!
//! * ① *How many extra stops for an unattended long task?* **None.** The reaper never asks a
//!   human and never pauses a turn: it either leaves a group alone or removes one. A working
//!   agent's commands carry a live `ark_pid` and are simply kept, so a task running overnight
//!   is never interrupted by the bookkeeping.
//! * ② *Is there an isolate/undo alternative to asking?* This module *is* the undo. The
//!   alternative to asking "may I kill this leftover process?" is to make the leftovers
//!   impossible to confuse with somebody else's: the group id, the `/proc` start time (PID
//!   reuse), the owning ark pid and the session's finished marker must all agree before a
//!   signal is sent. Anything unprovable is left running — a leak, never a wrong kill.
//!
//! Safety rules (safe by default, see [`kill_group_at`]): never signal pgid 0/1, our own
//! process group, an ancestor's group, a group whose recorded start time is missing, or one
//! whose start time no longer matches the record. A group is only ever reaped when (a) its
//! recorded start time still matches, (b) the ark process that started it is gone *and* was
//! recorded — or the session it belonged to has been marked finished by [`on_session_end`] —
//! and (c) it is not a `detached` process (those are meant to survive an ark restart,
//! `req.detach`). Unprovable entries are dropped from the registry without a signal: a leaked
//! process is acceptable, a wrong kill is not.
//!
//! Ownership: the daemon owns [`spawn_sweeper`]; the kernel calls [`on_session_end`] when a
//! session or turn ends; `ark doctor` prints [`sweep_json`] (a **dry run** — it never sends a
//! signal).
//!
//! Known limits: the registry is a shared append-only file, so [`sweep`] compacts it by
//! rewriting the file and then re-appending whatever appeared while it was being read. A
//! writer that opened the old inode microseconds before the rename can lose its line; the
//! consequence is an *unregistered* (leaked) group, never a killed one.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// `<home>/reaper/procs.jsonl`: one JSON line per spawned child (written by `ark-tools`).
pub fn registry(home: &Path) -> PathBuf {
    home.join("reaper").join("procs.jsonl")
}

fn reap_log(home: &Path) -> PathBuf {
    home.join("reaper").join("reap.log")
}

fn finished_dir(home: &Path) -> PathBuf {
    home.join("reaper").join("finished")
}

/// One registry line. `start` is `/proc/<pgid>/stat` field 22 (`None` when it could not be
/// read — such an entry can never be verified, so it is never killed).
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub pgid: u32,
    pub start: Option<u64>,
    pub session: String,
    pub tool: String,
    pub ark_pid: u32,
    pub ts_ms: u64,
}

impl Record {
    /// Parse one line; `None` for malformed entries (a truncated line from an interrupted
    /// append, a hand-edited file), which callers skip instead of failing the whole sweep.
    pub fn from_json(v: &Value) -> Option<Record> {
        let pgid = v.get("pgid")?.as_u64()?;
        if pgid == 0 || pgid > u32::MAX as u64 {
            return None;
        }
        let text = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        Some(Record {
            pgid: pgid as u32,
            start: v.get("start").and_then(Value::as_u64),
            session: text("session"),
            tool: text("tool"),
            ark_pid: v.get("ark_pid").and_then(Value::as_u64).unwrap_or(0) as u32,
            ts_ms: v.get("ts_ms").and_then(Value::as_u64).unwrap_or(0),
        })
    }
    pub fn to_json(&self) -> Value {
        json!({
            "pgid": self.pgid,
            "start": self.start,
            "session": self.session,
            "tool": self.tool,
            "ark_pid": self.ark_pid,
            "ts_ms": self.ts_ms,
        })
    }
    /// `detached` groups (a job started with `detach: true`) are recorded but never reaped:
    /// surviving an ark restart is exactly what they were asked to do.
    pub fn reapable(&self) -> bool {
        self.tool != "detached"
    }
}

/// Parse a registry body, skipping malformed lines (and lines without a usable pgid).
pub fn parse(text: &str) -> Vec<Record> {
    text.lines().filter(|l| !l.trim().is_empty()).filter_map(|l| serde_json::from_str::<Value>(l).ok().as_ref().and_then(Record::from_json)).collect()
}

/// The registry of `home` (`[]` when it is missing or unreadable). Also refreshes the recorded
/// start times that [`kill_group`] checks against.
pub fn read(home: &Path) -> Vec<Record> {
    let recs = std::fs::read_to_string(registry(home)).map(|t| parse(&t)).unwrap_or_default();
    remember(&recs);
    recs
}

/// Append one record (used by tests and by any embedder that starts processes itself).
pub fn append(home: &Path, rec: &Record) -> std::io::Result<()> {
    std::fs::create_dir_all(home.join("reaper"))?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(registry(home))?;
    writeln!(f, "{}", rec.to_json())
}

fn known() -> &'static RwLock<BTreeMap<u32, Option<u64>>> {
    static K: std::sync::OnceLock<RwLock<BTreeMap<u32, Option<u64>>>> = std::sync::OnceLock::new();
    K.get_or_init(Default::default)
}

/// Remember the recorded start times of the last registry read.
fn remember(recs: &[Record]) {
    let mut k = known().write().unwrap();
    k.clear();
    for r in recs {
        k.insert(r.pgid, r.start);
    }
}

fn recorded_start(pgid: u32) -> Option<u64> {
    known().read().unwrap().get(&pgid).copied().flatten()
}

/// `/proc/<pid>/stat` fields 3 (state), 4 (ppid) and 5 (pgrp), after the `(comm)` field.
fn stat_fields(pid: u32) -> Option<(char, u32, u32)> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &s[s.rfind(')')? + 2..];
    let mut it = rest.split_whitespace();
    let state = it.next()?.chars().next()?;
    let ppid: u32 = it.next()?.parse().ok()?;
    let pgrp: u32 = it.next()?.parse().ok()?;
    Some((state, ppid, pgrp))
}

/// `/proc/<pid>/stat` start time (field 22): tells a reused pid from ours.
pub fn start_time(pgid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pgid}/stat")).ok()?;
    let after = &s[s.rfind(')')? + 2..];
    after.split_whitespace().nth(19)?.parse().ok()
}

/// Process group → does it still have a live (non-zombie) member? A zombie leader whose
/// children still run keeps the group alive: that is the orphan case this module is for.
fn pgrp_index() -> BTreeMap<u32, bool> {
    let mut out = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir("/proc") else { return out };
    for e in rd.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };
        let Some((state, _, pgrp)) = stat_fields(pid) else { continue };
        let live = state != 'Z' && state != 'X';
        let slot = out.entry(pgrp).or_insert(false);
        *slot |= live;
    }
    out
}

/// Is any process of group `pgid` still running?
pub fn alive(pgid: u32) -> bool {
    if pgid <= 1 {
        return false;
    }
    pgrp_index().get(&pgid).copied().unwrap_or(false)
}

/// Live process groups registered for `session` (what `[limits] max_processes_per_agent`
/// counts). Unattributed entries (`session = ""`) are not counted for anybody.
pub fn live_count(home: &Path, session: &str) -> usize {
    let recs = read(home);
    let idx = pgrp_index();
    recs.iter().filter(|r| r.session == session && idx.get(&r.pgid).copied().unwrap_or(false)).count()
}

/// Our own line of ancestors (`self`, parent, …) as pids.
fn ancestry() -> Vec<u32> {
    let mut out = vec![std::process::id()];
    let mut pid = std::process::id();
    for _ in 0..64 {
        let Some((_, ppid, _)) = stat_fields(pid) else { break };
        if ppid <= 1 || out.contains(&ppid) {
            break;
        }
        out.push(ppid);
        pid = ppid;
    }
    out
}

/// Would signalling `-pgid` hit ark itself (its own group, or an ancestor's)?
fn is_our_own_or_ancestor_group(pgid: u32) -> bool {
    if pgid == std::process::id() || pgid == unsafe { libc::getpgrp() } as u32 {
        return true;
    }
    ancestry().iter().any(|pid| *pid == pgid || stat_fields(*pid).is_some_and(|(_, _, pgrp)| pgrp == pgid))
}

fn log_refusal(pgid: u32, why: &str) {
    eprintln!("ark: reaper: not killing process group {pgid}: {why}");
}

/// SIGTERM the group, wait up to ~2 s, SIGKILL, wait ~1 s, and reap it when we are its parent.
///
/// Returns `true` only when the group is gone afterwards. **Refuses** (returns `false` and
/// logs) for pgid 0/1, our own process group, an ancestor's group, a missing expected start
/// time, or a start time that no longer matches the record — the last two are how a reused
/// pid (somebody else's process) is kept alive.
pub fn kill_group_at(pgid: u32, expect: Option<u64>) -> bool {
    if pgid <= 1 {
        log_refusal(pgid, "pgid 0/1 is not a process group we may signal");
        return false;
    }
    if is_our_own_or_ancestor_group(pgid) {
        log_refusal(pgid, "it is ark's own or an ancestor's process group");
        return false;
    }
    let Some(expect) = expect else {
        log_refusal(pgid, "no recorded start time (ownership unprovable)");
        return false;
    };
    match start_time(pgid) {
        Some(now) if now == expect => {}
        Some(now) => {
            log_refusal(pgid, &format!("pid reused: recorded start {expect}, running process has {now}"));
            return false;
        }
        None => return true, // nothing there any more
    }
    if !alive(pgid) {
        return true;
    }
    // SAFETY: negative pid targets the process group, as intended.
    unsafe { libc::kill(-(pgid as i32), libc::SIGTERM) };
    if wait_until_gone(pgid, Duration::from_secs(2), Duration::from_millis(20)) {
        return true;
    }
    // SAFETY: same as above, escalating.
    unsafe { libc::kill(-(pgid as i32), libc::SIGKILL) };
    wait_until_gone(pgid, Duration::from_secs(1), Duration::from_millis(10))
}

/// Poll until the group is gone, reaping the leader when it is our child (a zombie would
/// otherwise look alive to `kill(-pgid, 0)` forever).
fn wait_until_gone(pgid: u32, timeout: Duration, step: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        reap_child(pgid);
        if !alive(pgid) {
            // The leader may have died between the reap and the scan: collect the zombie now,
            // otherwise `kill(-pgid, 0)` keeps reporting the group for the rest of our life.
            for _ in 0..50 {
                if reap_child(pgid) || !Path::new(&format!("/proc/{pgid}")).exists() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(step);
    }
}

/// Reap `pgid` if it is our exited child; `true` when a child was collected.
fn reap_child(pgid: u32) -> bool {
    let mut st: libc::c_int = 0;
    // SAFETY: waitpid on our own child; WNOHANG never blocks.
    unsafe { libc::waitpid(pgid as i32, &mut st, libc::WNOHANG) == pgid as i32 }
}

/// [`kill_group_at`] for a group named by the last registry read ([`read`]), so the recorded
/// start time is checked. A pgid that was never registered is refused.
pub fn kill_group(pgid: u32) -> bool {
    kill_group_at(pgid, recorded_start(pgid))
}

/// What one sweep did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SweepReport {
    /// Registry groups still alive when the sweep started.
    pub alive: usize,
    /// Groups this sweep killed (and reaped); `false` from the killer means "kept".
    pub killed: usize,
    /// Groups deliberately left alive, with the reason.
    pub skipped: Vec<(u32, String)>,
    /// Registry lines dropped (dead processes, reused pids, malformed entries).
    pub reclaimed_lines: usize,
}

impl SweepReport {
    pub fn to_json(&self) -> Value {
        json!({
            "alive": self.alive,
            "killed": self.killed,
            "reclaimed_lines": self.reclaimed_lines,
            "skipped": self.skipped.iter().map(|(p, r)| json!({"pgid": p, "reason": r})).collect::<Vec<_>>(),
        })
    }
}

/// Is `ark_pid` still running (any state except zombie)?
fn pid_alive(pid: u32) -> bool {
    if pid <= 1 {
        return false;
    }
    stat_fields(pid).is_some_and(|(state, _, _)| state != 'Z' && state != 'X')
}

pub fn session_marker(home: &Path, session: &str) -> PathBuf {
    finished_dir(home).join(safe_name(session))
}

fn safe_name(session: &str) -> String {
    session.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).take(64).collect()
}

/// Has the session been marked finished (its turn/session ended)? Unattributed entries
/// (`session = ""`) never have a marker.
pub fn session_finished(home: &Path, session: &str) -> bool {
    !session.is_empty() && session_marker(home, session).exists()
}

#[derive(Debug, Clone, PartialEq)]
enum Action {
    /// Kill the group, then drop the line.
    Reap(String),
    /// Leave the group, drop the line (the entry can never be acted on again).
    Drop(String),
    /// Leave the group and the line.
    Keep(String),
}

fn decide(home: &Path, rec: &Record, live: &BTreeMap<u32, bool>) -> Action {
    if rec.pgid <= 1 {
        return Action::Drop("pgid 0/1 is not a process group".into());
    }
    if !live.get(&rec.pgid).copied().unwrap_or(false) {
        return Action::Drop("process group gone".into());
    }
    if !rec.reapable() {
        return Action::Keep("detached (meant to survive an ark restart)".into());
    }
    let Some(start) = rec.start else {
        return Action::Drop("no recorded start time: ownership unprovable, never killed".into());
    };
    match start_time(rec.pgid) {
        Some(now) if now == start => {}
        _ => return Action::Drop(format!("pid reused (recorded start {start} no longer matches)")),
    }
    if is_our_own_or_ancestor_group(rec.pgid) {
        return Action::Keep("ark's own or an ancestor's process group".into());
    }
    if pid_alive(rec.ark_pid) && !session_finished(home, &rec.session) {
        return Action::Keep(format!("owner ark pid {} is alive", rec.ark_pid));
    }
    if rec.ark_pid <= 1 {
        return Action::Drop("no owner ark pid recorded: ownership unprovable, never killed".into());
    }
    let why = if pid_alive(rec.ark_pid) {
        format!("session `{}` finished", rec.session)
    } else {
        format!("owner ark pid {} is gone", rec.ark_pid)
    };
    Action::Reap(why)
}

/// Sweep every registry entry of `home`; `only` restricts reaping to one session
/// ([`on_session_end`]).
fn run(home: &Path, only: Option<&str>) -> SweepReport {
    let mut rep = SweepReport::default();
    let path = registry(home);
    let Ok(text) = std::fs::read_to_string(&path) else { return rep };
    let cutoff = text.len() as u64;
    let live = pgrp_index();
    let mut keep: Vec<String> = Vec::new();
    let mut dropped = false;
    for line in text.lines() {
        if line.trim().is_empty() {
            dropped = true;
            continue;
        }
        let Some(rec) = serde_json::from_str::<Value>(line).ok().as_ref().and_then(Record::from_json) else {
            rep.reclaimed_lines += 1;
            dropped = true;
            append_log(home, &format!("drop malformed registry line: {line}"));
            continue;
        };
        if only.is_some_and(|s| rec.session != s) {
            keep.push(line.to_string());
            continue;
        }
        match decide(home, &rec, &live) {
            Action::Keep(why) => {
                rep.alive += usize::from(live.get(&rec.pgid).copied().unwrap_or(false));
                rep.skipped.push((rec.pgid, why));
                keep.push(line.to_string());
            }
            Action::Drop(why) => {
                rep.reclaimed_lines += 1;
                dropped = true;
                append_log(home, &format!("reclaim pgid={} session={} tool={}: {why}", rec.pgid, rec.session, rec.tool));
            }
            Action::Reap(why) => {
                rep.alive += 1;
                if kill_group_at(rec.pgid, rec.start) {
                    rep.killed += 1;
                    rep.reclaimed_lines += 1;
                    dropped = true;
                    append_log(home, &format!("killed pgid={} session={} tool={}: {why}", rec.pgid, rec.session, rec.tool));
                } else {
                    rep.skipped.push((rec.pgid, "refused by kill_group_at (see stderr)".into()));
                    keep.push(line.to_string());
                }
            }
        }
    }
    if dropped {
        compact(&path, &keep.join("\n"), cutoff);
    }
    if rep.killed > 0 || rep.reclaimed_lines > 0 || !rep.skipped.is_empty() {
        append_log(home, &format!("sweep: alive={} killed={} reclaimed={} skipped={}", rep.alive, rep.killed, rep.reclaimed_lines, rep.skipped.len()));
    }
    rep
}

/// Rewrite the registry with `keep`, then re-append whatever was appended while we read it
/// (a concurrent `ark-tools` append must not vanish).
fn compact(path: &Path, keep: &str, cutoff: u64) {
    let tail = tail_after(path, cutoff);
    let tmp = path.with_extension("jsonl.tmp");
    let ok = (|| -> std::io::Result<()> {
        let mut out = std::fs::OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        out.write_all(keep.as_bytes())?;
        if !keep.is_empty() && !keep.ends_with('\n') {
            out.write_all(b"\n")?;
        }
        out.write_all(&tail)?;
        out.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if ok.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Bytes appended to `path` after `cutoff` (empty when nothing was added).
fn tail_after(path: &Path, cutoff: u64) -> Vec<u8> {
    let Ok(mut f) = std::fs::File::open(path) else { return Vec::new() };
    if f.metadata().map(|m| m.len()).unwrap_or(0) <= cutoff || f.seek(SeekFrom::Start(cutoff)).is_err() {
        return Vec::new();
    }
    let mut tail = Vec::new();
    let _ = f.read_to_end(&mut tail);
    tail
}

fn append_log(home: &Path, line: &str) {
    let ts = now_ms();
    if std::fs::create_dir_all(home.join("reaper")).is_err() {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(reap_log(home)) {
        let _ = writeln!(f, "{ts} {line}");
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Reap every orphaned group in `home`; safe to call from any thread, any number of times.
pub fn sweep(home: &Path) -> SweepReport {
    run(home, None)
}

/// Mark `session` finished and reap the process groups it left behind. This is what the
/// runtime calls when a session (or its last turn) ends: an agent that ended must not leave
/// children running, and the marker lets a concurrent [`spawn_sweeper`] reach the same
/// conclusion instead of waiting for the ark pid to die.
pub fn on_session_end(home: &Path, session: &str) {
    if session.is_empty() {
        return;
    }
    if std::fs::create_dir_all(finished_dir(home)).is_ok() {
        let _ = std::fs::write(session_marker(home, session), json!({"session": session, "ts_ms": now_ms()}).to_string());
    }
    let rep = run(home, Some(session));
    append_log(home, &format!("session {session} ended: killed={} reclaimed={}", rep.killed, rep.reclaimed_lines));
}

/// Periodic sweep thread, owned by the daemon (`[limits] reap_interval_secs`, 0 = off).
/// The thread stops when the process exits; an interval of zero returns immediately.
pub fn spawn_sweeper(home: PathBuf, interval: Duration) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("ark-reaper".into())
        .spawn(move || {
            if interval.is_zero() {
                return;
            }
            loop {
                let h = home.clone();
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    sweep(&h);
                }));
                std::thread::sleep(interval);
            }
        })
        .expect("spawn the reaper thread")
}

/// Dry-run report for `ark doctor` / the CLI: what a sweep *would* do. Sends no signal.
pub fn sweep_json(home: &Path) -> Value {
    let recs = read(home);
    let live = pgrp_index();
    let mut would = Vec::new();
    let mut kept = Vec::new();
    for rec in &recs {
        match decide(home, rec, &live) {
            Action::Reap(why) => would.push(json!({"pgid": rec.pgid, "session": rec.session, "tool": rec.tool, "ark_pid": rec.ark_pid, "reason": why})),
            Action::Drop(why) => kept.push(json!({"pgid": rec.pgid, "session": rec.session, "tool": rec.tool, "drop": why})),
            Action::Keep(why) => kept.push(json!({"pgid": rec.pgid, "session": rec.session, "tool": rec.tool, "keep": why})),
        }
    }
    json!({
        "registry": registry(home).display().to_string(),
        "records": recs.len(),
        "would_reap": would,
        "kept": kept,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    /// Temp dir that removes itself (tests must not leave anything behind).
    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let p = std::env::temp_dir().join(format!("ark-reaper-{tag}-{}-{}", std::process::id(), crate::util::random_hex(6)));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Tmp(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A process group we started ourselves: `sh -c 'sleep 60'` as its own group leader.
    fn own_group() -> Child {
        Command::new("/bin/sh").arg("-c").arg("sleep 60").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).process_group(0).spawn().expect("spawn sleep")
    }

    /// Still running? (`alive` ignores zombies — a killed-but-unreaped leader would otherwise
    /// keep `kill(-pgid, 0)` answering "yes" forever.)
    fn group_alive(pgid: u32) -> bool {
        alive(pgid)
    }

    /// Kill a group this test started (never anybody else's).
    fn kill_own(child: &mut Child) {
        // SAFETY: our own child's group.
        unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        let _ = child.wait();
    }

    /// A pid that is certainly not running (the child was reaped).
    fn dead_pid() -> u32 {
        for _ in 0..32 {
            let mut c = Command::new("/bin/sh").arg("-c").arg("exit 0").spawn().unwrap();
            let pid = c.id();
            let _ = c.wait();
            if !Path::new(&format!("/proc/{pid}")).exists() {
                return pid;
            }
        }
        panic!("could not obtain a dead pid");
    }

    fn record(pgid: u32, start: Option<u64>, ark_pid: u32) -> Record {
        Record { pgid, start, session: "s-r5".into(), tool: "shell".into(), ark_pid, ts_ms: now_ms() }
    }

    #[test]
    fn sweep_kills_and_reaps_a_dead_owners_group() {
        let tmp = Tmp::new("kill");
        let mut child = own_group();
        let pgid = child.id();
        let start = start_time(pgid).expect("/proc stat of our own child");
        append(tmp.path(), &record(pgid, Some(start), dead_pid())).unwrap();
        assert!(group_alive(pgid));

        let rep = sweep(tmp.path());
        assert_eq!(rep.killed, 1, "{rep:?}");
        assert!(!group_alive(pgid), "the orphaned group is gone");
        assert_eq!(rep.reclaimed_lines, 1, "its registry line is gone: {rep:?}");
        assert!(read(tmp.path()).is_empty(), "registry compacted");
        let _ = child.wait(); // already reaped by the sweep; ignore ECHILD
        let log = std::fs::read_to_string(reap_log(tmp.path())).unwrap_or_default();
        assert!(log.contains(&format!("killed pgid={pgid}")), "{log}");
    }

    #[test]
    fn reused_pid_is_skipped_and_the_process_survives() {
        let tmp = Tmp::new("reuse");
        let mut child = own_group();
        let pgid = child.id();
        let real = start_time(pgid).unwrap();
        // Simulate PID reuse: a record whose start time cannot be this process.
        append(tmp.path(), &record(pgid, Some(real + 1), dead_pid())).unwrap();

        let rep = sweep(tmp.path());
        assert_eq!(rep.killed, 0, "{rep:?}");
        assert_eq!(rep.reclaimed_lines, 1, "the stale line is dropped: {rep:?}");
        assert!(group_alive(pgid), "somebody else's process must never be signalled");
        kill_own(&mut child);
        assert!(!group_alive(pgid));
    }

    #[test]
    fn unregistered_process_survives_a_sweep() {
        let tmp = Tmp::new("unreg");
        let mut kept = own_group();
        let mut other = own_group();
        append(tmp.path(), &record(other.id(), start_time(other.id()), dead_pid())).unwrap();
        // A record with no owner pid is unprovable: the line goes, the process stays.
        append(tmp.path(), &record(kept.id(), start_time(kept.id()), 0)).unwrap();

        let rep = sweep(tmp.path());
        assert_eq!(rep.killed, 1, "only the registered dead-owner group goes: {rep:?}");
        assert!(!group_alive(other.id()));
        assert!(group_alive(kept.id()), "a process we cannot prove is ours is untouched");
        assert_eq!(rep.reclaimed_lines, 2, "both lines are dropped: {rep:?}");
        kill_own(&mut kept);
        let _ = other.wait();
    }

    #[test]
    fn empty_or_missing_registry_is_a_noop() {
        let tmp = Tmp::new("empty");
        let rep = sweep(tmp.path());
        assert_eq!(rep, SweepReport::default(), "missing registry: nothing happens");
        assert!(!registry(tmp.path()).exists(), "no registry is not created by a sweep");

        std::fs::create_dir_all(tmp.path().join("reaper")).unwrap();
        std::fs::write(registry(tmp.path()), "").unwrap();
        assert_eq!(sweep(tmp.path()), SweepReport::default(), "empty registry: nothing happens");
        let j = sweep_json(tmp.path());
        assert_eq!(j["records"], 0, "{j}");
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let tmp = Tmp::new("malformed");
        let mut child = own_group();
        let pgid = child.id();
        let start = start_time(pgid).unwrap();
        let body = format!("not json\n{}\n{{\"pgid\":0}}\n", record(pgid, Some(start), std::process::id()).to_json());
        std::fs::create_dir_all(tmp.path().join("reaper")).unwrap();
        std::fs::write(registry(tmp.path()), body).unwrap();

        let rep = sweep(tmp.path());
        assert_eq!(rep.killed, 0, "the owner (this process) is alive: {rep:?}");
        assert_eq!(rep.reclaimed_lines, 2, "two malformed lines dropped: {rep:?}");
        assert_eq!(read(tmp.path()).len(), 1, "the good line is still there");
        assert!(group_alive(pgid));
        kill_own(&mut child);
    }

    #[test]
    fn kill_group_refuses_unsafe_pgids() {
        // 0 and 1 are never a process group we may signal.
        assert!(!kill_group(0));
        assert!(!kill_group(1));
        // Our own group and our own pid.
        // SAFETY: getpgrp only reads.
        let own = unsafe { libc::getpgrp() } as u32;
        assert!(!kill_group(own));
        assert!(!kill_group(std::process::id()));
        assert!(!kill_group_at(std::process::id(), start_time(std::process::id())));
        // A group with no recorded start time is unprovable, even if it exists.
        let mut child = own_group();
        assert!(!kill_group(child.id()), "unregistered group: no start time, no kill");
        assert!(group_alive(child.id()), "still alive");
        assert!(!kill_group_at(child.id(), None));
        assert!(group_alive(child.id()));
        kill_own(&mut child);
    }

    #[test]
    fn session_end_marks_finished_and_reaps_its_groups() {
        let tmp = Tmp::new("session");
        let mut child = own_group();
        let pgid = child.id();
        // Owner is this (live) process: only the finished marker may allow the kill.
        append(tmp.path(), &record(pgid, start_time(pgid), std::process::id())).unwrap();
        let rep = sweep(tmp.path());
        assert_eq!(rep.killed, 0, "a live owner keeps its children: {rep:?}");
        assert!(group_alive(pgid));

        on_session_end(tmp.path(), "s-r5");
        assert!(session_finished(tmp.path(), "s-r5"));
        assert!(!group_alive(pgid), "an ended session leaves no children behind");
        assert!(read(tmp.path()).is_empty(), "registry compacted");
        let _ = child.wait();
    }

    #[test]
    fn detached_groups_are_recorded_but_never_killed() {
        let tmp = Tmp::new("detached");
        let mut child = own_group();
        let pgid = child.id();
        let mut rec = record(pgid, start_time(pgid), dead_pid());
        rec.tool = "detached".into();
        append(tmp.path(), &rec).unwrap();

        let rep = sweep(tmp.path());
        assert_eq!(rep.killed, 0, "{rep:?}");
        assert!(rep.skipped.iter().any(|(p, r)| *p == pgid && r.contains("detached")), "{rep:?}");
        assert!(group_alive(pgid), "`detach` means it survives; the sweep honours that");
        assert_eq!(read(tmp.path()).len(), 1, "the line stays while it runs");
        kill_own(&mut child);
    }

    #[test]
    fn spawn_sweeper_with_zero_interval_stops_at_once() {
        let tmp = Tmp::new("thread");
        let h = spawn_sweeper(tmp.path().to_path_buf(), Duration::ZERO);
        h.join().unwrap();
    }
}
