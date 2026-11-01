//! Long-running automation: cron jobs and goals. Both persist as JSON files
//! guarded by a lock file, so the CLI and the daemon can edit them concurrently.

use crate::cron::Cron;
use crate::event::EventKind;
use crate::kernel::{EndReason, Kernel, RunOpts};
use crate::ledger::{Budget, Ledger};
use crate::util::{atomic_write, new_id, unix_now};
use ark_core::Block;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// Read-modify-write a JSON list under an exclusive file lock.
pub fn with_list<T: Serialize + DeserializeOwned, R>(path: &Path, f: impl FnOnce(&mut Vec<T>) -> R) -> Result<R, String> {
    std::fs::create_dir_all(path.parent().unwrap_or(Path::new("."))).map_err(|e| e.to_string())?;
    let lock_path = path.with_extension("lock");
    let lock = OpenOptions::new().create(true).truncate(false).write(true).open(&lock_path).map_err(|e| e.to_string())?;
    let _g = FileLock::new(&lock)?;
    let mut items: Vec<T> = match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s).map_err(|e| format!("{} is corrupt: {e}", path.display()))?,
        Ok(_) => vec![],
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
        Err(e) => return Err(e.to_string()),
    };
    let r = f(&mut items);
    let text = serde_json::to_string_pretty(&items).map_err(|e| e.to_string())?;
    atomic_write(path, text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(r)
}

pub fn read_list<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>, String> {
    match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s).map_err(|e| format!("{} is corrupt: {e}", path.display())),
        Ok(_) => Ok(vec![]),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.to_string()),
    }
}

struct FileLock<'a>(&'a File);
impl<'a> FileLock<'a> {
    fn new(f: &'a File) -> Result<Self, String> {
        // SAFETY: blocking flock on an fd we own.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(FileLock(f))
    }
}
impl Drop for FileLock<'_> {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

// ───────────────────────── cron jobs ─────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub cron: String,
    pub prompt: String,
    pub workspace: String,
    #[serde(default)]
    pub model: Option<String>,
    /// Reuse one session (keeps context) instead of a fresh one per run.
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub next_run: i64,
    #[serde(default)]
    pub last_run: Option<i64>,
    #[serde(default)]
    pub last_session: Option<String>,
    #[serde(default)]
    pub last_result: Option<String>,
    #[serde(default)]
    pub budget: Budget,
}
fn yes() -> bool {
    true
}

pub fn jobs_path(data: &Path) -> PathBuf {
    data.join("schedules.json")
}

pub fn add_job(data: &Path, cron: &str, prompt: &str, workspace: &Path, model: Option<String>, reuse: bool, offset: i32) -> Result<Job, String> {
    let c = Cron::parse(cron)?;
    if prompt.trim().is_empty() {
        return Err("empty prompt".into());
    }
    let ws = workspace.canonicalize().map_err(|e| format!("{}: {e}", workspace.display()))?;
    let next_run = c.next_after(unix_now(), offset).ok_or("that schedule never fires")?;
    let job = Job {
        id: new_id(),
        cron: cron.into(),
        prompt: prompt.into(),
        workspace: ws.to_string_lossy().into(),
        model,
        session: reuse.then(String::new),
        enabled: true,
        next_run,
        last_run: None,
        last_session: None,
        last_result: None,
        budget: Budget::default(),
    };
    with_list(&jobs_path(data), |v: &mut Vec<Job>| v.push(job.clone()))?;
    Ok(job)
}

pub fn remove_job(data: &Path, id: &str) -> Result<bool, String> {
    with_list(&jobs_path(data), |v: &mut Vec<Job>| {
        let n = v.len();
        v.retain(|j| j.id != id);
        v.len() != n
    })
}

pub fn set_job_enabled(data: &Path, id: &str, enabled: bool) -> Result<bool, String> {
    with_list(&jobs_path(data), |v: &mut Vec<Job>| match v.iter_mut().find(|j| j.id == id) {
        Some(j) => {
            j.enabled = enabled;
            true
        }
        None => false,
    })
}

/// Claim due jobs: advance `next_run` *before* running (a crash never re-fires a
/// job in a loop; a missed window fires once, not once per missed slot).
pub fn claim_due(data: &Path, now: i64, offset: i32, busy: &[String]) -> Result<Vec<Job>, String> {
    with_list(&jobs_path(data), |v: &mut Vec<Job>| {
        let mut due = Vec::new();
        for j in v.iter_mut().filter(|j| j.enabled && j.next_run <= now) {
            let next = Cron::parse(&j.cron).ok().and_then(|c| c.next_after(now, offset));
            match next {
                Some(n) => j.next_run = n,
                None => j.enabled = false,
            }
            if busy.contains(&j.id) {
                j.last_result = Some("skipped: previous run still in progress".into());
                continue;
            }
            j.last_run = Some(now);
            due.push(j.clone());
        }
        due
    })
}

/// Run one claimed job to completion; records the result.
pub fn run_job(k: &Kernel, job: &Job) -> Result<String, String> {
    let ws = PathBuf::from(&job.workspace);
    let reuse = job.session.as_deref().filter(|s| !s.is_empty() && k.store.exists(s)).map(String::from);
    let id = match reuse {
        Some(s) => s,
        None => k.create_session(&ws, job.model.as_deref(), None, Some(&format!("cron {}", job.cron))).map_err(|e| e.to_string())?,
    };
    if job.session.is_some() {
        with_list(&jobs_path(&k.paths.data), |v: &mut Vec<Job>| {
            if let Some(j) = v.iter_mut().find(|j| j.id == job.id) {
                j.session = Some(id.clone());
            }
        })?;
    }
    k.submit(&id, &job.prompt, "schedule").map_err(|e| e.to_string())?;
    let ledger = Ledger::new(if job.budget == Budget::default() { k.cfg.budget.clone() } else { job.budget.clone() });
    let r = k.run(&id, RunOpts { ledger: Some(ledger), ..Default::default() });
    let result = match &r {
        Ok(o) => o.reason.label(),
        Err(e) => format!("error: {e}"),
    };
    with_list(&jobs_path(&k.paths.data), |v: &mut Vec<Job>| {
        if let Some(j) = v.iter_mut().find(|j| j.id == job.id) {
            j.last_session = Some(id.clone());
            j.last_result = Some(result.clone());
        }
    })?;
    r.map(|_| id).map_err(|e| e.to_string())
}

// ───────────────────────── goals ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GoalStatus {
    Active,
    Paused,
    Done,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Goal {
    pub id: String,
    pub objective: String,
    pub workspace: String,
    pub session: String,
    pub status: GoalStatus,
    pub max_rounds: u32,
    pub rounds: u32,
    #[serde(default)]
    pub budget: Budget,
    #[serde(default)]
    pub summary: String,
}

pub fn goals_path(data: &Path) -> PathBuf {
    data.join("goals.json")
}

pub fn add_goal(k: &Kernel, objective: &str, workspace: &Path, max_rounds: u32, budget: Budget, model: Option<&str>) -> Result<Goal, String> {
    if objective.trim().is_empty() {
        return Err("empty objective".into());
    }
    if max_rounds == 0 {
        return Err("max_rounds must be > 0".into());
    }
    let session = k.create_session(workspace, model, None, Some(&format!("goal: {objective}"))).map_err(|e| e.to_string())?;
    let g = Goal { id: new_id(), objective: objective.into(), workspace: workspace.to_string_lossy().into(), session, status: GoalStatus::Active, max_rounds, rounds: 0, budget, summary: String::new() };
    with_list(&goals_path(&k.paths.data), |v: &mut Vec<Goal>| v.push(g.clone()))?;
    Ok(g)
}

pub fn set_goal_status(data: &Path, id: &str, status: GoalStatus) -> Result<bool, String> {
    with_list(&goals_path(data), |v: &mut Vec<Goal>| match v.iter_mut().find(|g| g.id == id) {
        Some(g) => {
            g.status = status;
            true
        }
        None => false,
    })
}

fn update_goal(data: &Path, id: &str, f: impl FnOnce(&mut Goal)) -> Result<(), String> {
    with_list(&goals_path(data), |v: &mut Vec<Goal>| {
        if let Some(g) = v.iter_mut().find(|g| g.id == id) {
            f(g)
        }
    })
}

fn goal_done_call(k: &Kernel, session: &str, from_seq: u64) -> Option<(bool, String)> {
    let events = k.store.read(session).ok()?;
    events.iter().filter(|e| e.seq >= from_seq).rev().find_map(|e| match &e.kind {
        EventKind::Message { message, .. } => message.content.iter().find_map(|b| match b {
            Block::ToolUse { name, input, .. } if name == "goal_done" => Some((input.get("achieved").and_then(|v| v.as_bool()).unwrap_or(false), input.get("summary").and_then(|v| v.as_str()).unwrap_or("").to_string())),
            _ => None,
        }),
        _ => None,
    })
}

/// Drive a goal round by round until done, failed, out of rounds/budget, or paused.
pub fn run_goal(k: &Kernel, goal_id: &str) -> Result<Goal, String> {
    let data = k.paths.data.clone();
    let mut goal = read_list::<Goal>(&goals_path(&data))?.into_iter().find(|g| g.id == goal_id).ok_or_else(|| format!("no goal {goal_id}"))?;
    if goal.status != GoalStatus::Active {
        return Err(format!("goal is {:?}, not active", goal.status));
    }
    let ledger = Ledger::new(goal.budget.clone());
    while goal.rounds < goal.max_rounds {
        // Re-read: the user may have paused / cancelled from another process.
        let current = read_list::<Goal>(&goals_path(&data))?.into_iter().find(|g| g.id == goal_id).ok_or("goal vanished")?;
        if current.status != GoalStatus::Active {
            return Ok(current);
        }
        let left = goal.max_rounds - goal.rounds;
        let prompt = if goal.rounds == 0 {
            format!("GOAL: {}\n\nWork autonomously toward this goal. Verify results with tools. When the goal is verifiably achieved — or proven impossible — call `goal_done`. You have {left} rounds.", goal.objective)
        } else {
            format!("Continue working toward the goal: {}\nRounds left: {left}. If it is achieved, verify and call `goal_done`.", goal.objective)
        };
        let from_seq = k.store.read(&goal.session).map(|e| e.len() as u64).unwrap_or(0);
        k.submit(&goal.session, &prompt, "goal").map_err(|e| e.to_string())?;
        let o = k.run(&goal.session, RunOpts { ledger: Some(ledger.clone()), goal_mode: true, ..Default::default() }).map_err(|e| e.to_string())?;
        goal.rounds += 1;
        let (status, summary) = match (&o.reason, goal_done_call(k, &goal.session, from_seq)) {
            (_, Some((true, s))) => (GoalStatus::Done, s),
            (_, Some((false, s))) => (GoalStatus::Failed, s),
            (EndReason::Interrupted, _) => (GoalStatus::Paused, "interrupted".into()),
            (EndReason::Budget(b), _) => (GoalStatus::Paused, b.clone()),
            (EndReason::Error(e), _) => (GoalStatus::Paused, format!("error: {e}")),
            (EndReason::Stuck(s), _) => (GoalStatus::Paused, format!("stuck: {s}")),
            _ if goal.rounds >= goal.max_rounds => (GoalStatus::Failed, format!("ran out of rounds; last: {}", o.text)),
            _ => (GoalStatus::Active, o.text.clone()),
        };
        goal.status = status;
        goal.summary = summary;
        let g2 = goal.clone();
        update_goal(&data, goal_id, |g| {
            g.rounds = g2.rounds;
            if g.status == GoalStatus::Active {
                g.status = g2.status;
            }
            g.summary = g2.summary.clone();
        })?;
        if status != GoalStatus::Active {
            break;
        }
    }
    read_list::<Goal>(&goals_path(&data))?.into_iter().find(|g| g.id == goal_id).ok_or_else(|| "goal vanished".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-auto-{}", crate::util::random_hex(8)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn job_lifecycle_and_claiming() {
        let d = dir();
        let j = add_job(&d, "*/5 * * * *", "check CI", &d, None, false, 0).unwrap();
        assert!(j.next_run > unix_now());
        assert!(add_job(&d, "bogus", "x", &d, None, false, 0).is_err());
        assert!(add_job(&d, "* * * * *", " ", &d, None, false, 0).is_err());
        assert!(add_job(&d, "* * * * *", "x", Path::new("/nope/x"), None, false, 0).is_err());
        // Not due yet.
        assert!(claim_due(&d, unix_now(), 0, &[]).unwrap().is_empty());
        // Far in the future: due once (catch-up fires once, not per missed slot).
        let later = unix_now() + 3600;
        let due = claim_due(&d, later, 0, &[]).unwrap();
        assert_eq!(due.len(), 1);
        assert!(claim_due(&d, later, 0, &[]).unwrap().is_empty(), "next_run advanced before running");
        // Busy jobs are skipped but rescheduled.
        let due = claim_due(&d, later + 3600, 0, std::slice::from_ref(&j.id)).unwrap();
        assert!(due.is_empty());
        let jobs: Vec<Job> = read_list(&jobs_path(&d)).unwrap();
        assert!(jobs[0].last_result.as_deref().unwrap().contains("skipped"));
        assert!(set_job_enabled(&d, &j.id, false).unwrap());
        assert!(claim_due(&d, later + 99999, 0, &[]).unwrap().is_empty(), "disabled");
        assert!(!set_job_enabled(&d, "nope", true).unwrap());
        assert!(remove_job(&d, &j.id).unwrap());
        assert!(!remove_job(&d, &j.id).unwrap());
    }

    #[test]
    fn corrupt_store_is_an_error_not_data_loss() {
        let d = dir();
        std::fs::write(jobs_path(&d), "{not json").unwrap();
        assert!(add_job(&d, "@hourly", "x", &d, None, false, 0).unwrap_err().contains("corrupt"));
        assert_eq!(std::fs::read_to_string(jobs_path(&d)).unwrap(), "{not json", "file left untouched");
    }

    #[test]
    fn concurrent_writers_do_not_lose_updates() {
        let d = dir();
        let hs: Vec<_> = (0..8)
            .map(|_| {
                let d = d.clone();
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        add_job(&d, "@hourly", "x", &d, None, false, 0).unwrap();
                    }
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        assert_eq!(read_list::<Job>(&jobs_path(&d)).unwrap().len(), 40);
    }
}
