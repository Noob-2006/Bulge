//! Background review that writes skills (Hermes `agent/background_review.py`, MIT): the part of
//! the post-turn review that is not memory.
//!
//! Upstream forks the agent after a turn with the conversation as context and the
//! `_SKILL_REVIEW_PROMPT` preference order (update the loaded skill → update an existing
//! umbrella → add a support file → create a new class-level skill). seagent's fork is deterministic:
//! [`ReviewTick`] observes the turn (`tool_settled` records what ran, `turn_end` records the
//! step sequence as a *candidate procedure* when the turn used at least `[skills.review]
//! min_steps` tools), and a `curator review` pass turns each candidate into a SKILL.md through
//! the same guarded writer the `skill` tool uses (`super::manage`), preferring the skill that was
//! loaded during that session — upstream's first preference.
//!
//! Everything here is per-workspace state in `<data>/skills/.review_state.json`: loaded skills
//! and the last steps per session (bounded), plus the candidate queue. `/refine` reads the same
//! state for the session it is typed in.

use super::settings::{Settings, Store};
use super::{invoke, manage, workshop};
use seagent_kernel::config::{Config, Paths};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::Mutex;

/// Steps kept per session, and sessions/candidates kept in the state file.
const MAX_STEPS: usize = 40;
const MAX_SESSIONS: usize = 20;
const MAX_CANDIDATES: usize = 200;

fn now() -> i64 {
    seagent_kernel::util::unix_now()
}

fn lock() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    L.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn load(st: &Store) -> Value {
    let v: Value = std::fs::read_to_string(st.review_state()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(json!({}));
    if v.is_object() {
        v
    } else {
        json!({})
    }
}

fn save(st: &Store, v: &Value) {
    let _ = std::fs::create_dir_all(&st.skills);
    let _ = seagent_kernel::util::atomic_write(&st.review_state(), serde_json::to_string_pretty(v).unwrap_or_default().as_bytes());
}

fn session_of<'a>(state: &'a Value, session: &str) -> Option<&'a Value> {
    state.get("sessions")?.as_array()?.iter().find(|v| v.get("id").and_then(Value::as_str) == Some(session))
}

/// Load-modify-store one session entry; the entry moves to the end (most recent) and the list
/// is trimmed from the front, so the state file stays bounded without relying on map ordering.
fn with_session(st: &Store, session: &str, f: impl FnOnce(&mut Value)) {
    if session.is_empty() {
        return;
    }
    let _g = lock();
    let mut state = load(st);
    let mut list: Vec<Value> = state.get("sessions").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut entry = list.iter().position(|v| v.get("id").and_then(Value::as_str) == Some(session)).map(|i| list.remove(i)).unwrap_or_else(|| json!({"id": session}));
    f(&mut entry);
    entry["at"] = json!(now());
    list.push(entry);
    if list.len() > MAX_SESSIONS {
        list.drain(..list.len() - MAX_SESSIONS);
    }
    state["sessions"] = json!(list);
    save(st, &state);
}

/// One recorded tool call of a turn.
#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub tool: String,
    pub detail: String,
    pub ok: bool,
}

impl Step {
    fn to_value(&self) -> Value {
        json!({"tool": self.tool, "detail": self.detail, "ok": self.ok})
    }
    fn from_value(v: &Value) -> Step {
        Step {
            tool: v.get("tool").and_then(Value::as_str).unwrap_or("").to_string(),
            detail: v.get("detail").and_then(Value::as_str).unwrap_or("").to_string(),
            ok: v.get("ok").and_then(Value::as_bool).unwrap_or(true),
        }
    }
    pub fn render(&self) -> String {
        match (self.tool.as_str(), self.detail.as_str()) {
            ("", "") => "step".into(),
            (t, "") => t.into(),
            ("", d) => d.into(),
            (t, d) => format!("{t}: {d}"),
        }
    }

    /// The imperative line a candidate would carry: a command becomes `Run \`cmd\``.
    pub fn imperative(&self) -> String {
        match self.tool.as_str() {
            "shell" | "execute" | "bash" | "terminal" | "exec" if !self.detail.is_empty() => format!("Run `{}`", self.detail),
            _ => self.render(),
        }
    }
}

/// The tool call's one-line detail: its command, its target, or its action+name.
pub fn step_detail(tool: &str, input: &Value) -> String {
    let s = |k: &str| input.get(k).and_then(Value::as_str).unwrap_or("").trim().to_string();
    match tool {
        "shell" | "execute" | "bash" | "terminal" | "exec" => s("command"),
        "read" | "write" | "edit" | "glob" | "grep" => {
            let path = s("path");
            if path.is_empty() {
                s("pattern")
            } else {
                path
            }
        }
        "job" => format!("{} {}", s("action"), s("command")).trim().to_string(),
        _ => match (s("action"), s("name")) {
            (a, n) if !a.is_empty() && !n.is_empty() => format!("{a} {n}"),
            (a, _) if !a.is_empty() => a,
            (_, n) => n,
        },
    }
}

/// Record a settled tool call for `session` (bounded, consecutive duplicates collapsed).
pub fn note_step(st: &Store, session: &str, tool: &str, input: &Value, is_error: bool) {
    if session.is_empty() || tool.is_empty() {
        return;
    }
    let step = Step { tool: tool.to_string(), detail: step_detail(tool, input), ok: !is_error };
    with_session(st, session, |sess| {
        let mut steps: Vec<Value> = sess.get("steps").and_then(Value::as_array).cloned().unwrap_or_default();
        if steps.last().map(Step::from_value) != Some(step.clone()) {
            steps.push(step.to_value());
        }
        if steps.len() > MAX_STEPS {
            steps.drain(..steps.len() - MAX_STEPS);
        }
        sess["steps"] = json!(steps);
    });
}

/// Record that `session` loaded `name` (upstream's "currently-loaded skill" preference).
pub fn note_loaded(st: &Store, session: Option<&str>, name: &str) {
    let Some(session) = session.filter(|s| !s.is_empty()) else { return };
    if name.is_empty() {
        return;
    }
    with_session(st, session, |sess| {
        let mut loaded: Vec<String> = sess.get("loaded").and_then(Value::as_array).cloned().unwrap_or_default().into_iter().filter_map(|v| v.as_str().map(String::from)).collect();
        loaded.retain(|n| n != name);
        loaded.insert(0, name.to_string());
        loaded.truncate(5);
        sess["loaded"] = json!(loaded);
    });
}

/// The session's recorded steps, most recent last.
pub fn steps(st: &Store, session: &str) -> Vec<Step> {
    session_of(&load(st), session).and_then(|s| s.get("steps")).and_then(Value::as_array).map(|a| a.iter().map(Step::from_value).collect()).unwrap_or_default()
}

/// The skill the session loaded last (what `/refine` refines and the review prefers).
pub fn last_loaded(st: &Store, session: &str) -> Option<String> {
    session_of(&load(st), session)?.get("loaded")?.as_array()?.first()?.as_str().map(String::from)
}

/// A recorded candidate procedure.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub id: String,
    pub session: String,
    pub workspace: String,
    pub goal: String,
    pub target: String,
    pub steps: Vec<Step>,
    pub at: i64,
    pub status: String,
}

impl Candidate {
    fn from_value(v: &Value) -> Option<Candidate> {
        Some(Candidate {
            id: v.get("id")?.as_str()?.to_string(),
            session: v.get("session").and_then(Value::as_str).unwrap_or("").to_string(),
            workspace: v.get("workspace").and_then(Value::as_str).unwrap_or("").to_string(),
            goal: v.get("goal").and_then(Value::as_str).unwrap_or("").to_string(),
            target: v.get("target").and_then(Value::as_str).unwrap_or("").to_string(),
            steps: v.get("steps").and_then(Value::as_array).map(|a| a.iter().map(Step::from_value).collect()).unwrap_or_default(),
            at: v.get("at").and_then(Value::as_i64).unwrap_or(0),
            status: v.get("status").and_then(Value::as_str).unwrap_or("pending").to_string(),
        })
    }
}

pub fn candidates(st: &Store) -> Vec<Candidate> {
    load(st).get("candidates").and_then(Value::as_array).cloned().unwrap_or_default().iter().filter_map(Candidate::from_value).collect()
}

/// The goal line of a turn: its first non-empty line, whitespace-collapsed and bounded.
pub fn goal_of(user: &str) -> String {
    let line = user.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("");
    let line = line.split_whitespace().collect::<Vec<_>>().join(" ");
    if line.chars().count() > 200 {
        line.chars().take(200).collect()
    } else {
        line
    }
}

/// Two goals are the same procedure when their normalised words match.
fn signature(goal: &str, target: &str) -> String {
    let mut words: Vec<String> = goal.to_lowercase().split(|c: char| !c.is_alphanumeric()).filter(|w| w.len() > 2).map(String::from).collect();
    words.sort();
    words.dedup();
    format!("{target}|{}", words.join(" "))
}

/// Record the turn's procedure as a candidate. `None` when the turn does not look like one:
/// review off, a failed turn, too few steps, or a goal already queued.
pub fn record_candidate(s: &Settings, st: &Store, session: &str, ws: &str, user: &str, ok: bool) -> Option<Candidate> {
    if !s.review.enabled || !ok {
        return None;
    }
    let recorded = steps(st, session);
    if recorded.len() < s.review.min_steps {
        return None;
    }
    let goal = goal_of(user);
    if goal.chars().count() < 8 {
        return None;
    }
    let target = last_loaded(st, session).filter(|n| crate::skill::valid_name(n)).unwrap_or_else(|| workshop::slug(&goal));
    if !crate::skill::valid_name(&target) {
        return None;
    }
    let sig = signature(&goal, &target);
    let _g = lock();
    let mut state = load(st);
    let mut list: Vec<Value> = state.get("candidates").and_then(Value::as_array).cloned().unwrap_or_default();
    if list.iter().filter_map(|v| v.get("sig").and_then(Value::as_str)).any(|x| x == sig) {
        return None;
    }
    let cand = json!({
        "id": format!("{}-{}", now(), seagent_kernel::util::random_hex(3)),
        "session": session, "workspace": ws, "goal": goal, "target": target,
        "steps": recorded.iter().map(Step::to_value).collect::<Vec<_>>(),
        "at": now(), "status": "pending", "sig": sig,
    });
    let out = Candidate::from_value(&cand)?;
    list.push(cand);
    if list.len() > MAX_CANDIDATES {
        list.drain(..list.len() - MAX_CANDIDATES);
    }
    state["candidates"] = json!(list);
    // One candidate is one turn's procedure: the next turn records its own steps.
    if let Some(sess) = state.get_mut("sessions").and_then(Value::as_array_mut).and_then(|a| a.iter_mut().find(|v| v.get("id").and_then(Value::as_str) == Some(session))) {
        sess["steps"] = json!([]);
    }
    save(st, &state);
    Some(out)
}

fn mark(st: &Store, ids: &[String], status: &str) {
    if ids.is_empty() {
        return;
    }
    let _g = lock();
    let mut state = load(st);
    if let Some(list) = state.get_mut("candidates").and_then(Value::as_array_mut) {
        for v in list.iter_mut() {
            if v.get("id").and_then(Value::as_str).is_some_and(|i| ids.iter().any(|x| x == i)) {
                v["status"] = json!(status);
                v["reviewed_at"] = json!(now());
            }
        }
    }
    save(st, &state);
}

/// A procedure's steps as imperative lines, successes only.
pub fn step_lines(steps: &[Step]) -> Vec<String> {
    steps.iter().filter(|s| s.ok).map(Step::imperative).collect()
}

/// The ops a candidate becomes: an update of the skill it loaded (upstream preference 1), else a
/// new class-level skill (preference 4).
pub fn ops_for(cfg: &Config, paths: &Paths, s: &Settings, c: &Candidate) -> Result<Vec<manage::Op>, String> {
    let settings = Settings { disabled: vec![], ..s.clone() };
    let ws = Path::new(if c.workspace.is_empty() { "/" } else { &c.workspace });
    let cat = invoke::catalog_loadable(cfg, paths, ws, &settings);
    let lines = step_lines(&c.steps);
    if lines.is_empty() {
        return Err("no successful step to record".into());
    }
    let own = paths.data.join("skills");
    if let Some(existing) = invoke::resolve(&cat, &c.target) {
        // The skill it loaded and ours to rewrite: refine it instead of adding a second skill.
        if existing.dir == own.join(&existing.name) {
            let current = std::fs::read_to_string(&existing.file).map_err(|e| format!("{}: {e}", existing.file.display()))?;
            let r = workshop::refine(&current, &existing.name, &c.goal, &lines)?;
            return Ok(vec![manage::Op { action: "update".into(), name: existing.name.clone(), description: None, body: None, content: Some(r.content), old_string: None, new_string: None, replace_all: false, file_path: None }]);
        }
    }
    let d = workshop::draft(&c.goal, Some(&c.target), None, &lines)?;
    Ok(vec![manage::Op { action: "create".into(), name: d.name, description: None, body: None, content: Some(d.content), old_string: None, new_string: None, replace_all: false, file_path: None }])
}

/// What a review pass did.
#[derive(Debug, Clone, Default)]
pub struct Outcome {
    pub seen: usize,
    pub written: Vec<String>,
    pub skipped: Vec<String>,
    pub lines: Vec<String>,
}

impl Outcome {
    pub fn render(&self) -> String {
        let mut out = vec![format!(
            "review: {} candidate(s), {} written{}",
            self.seen,
            self.written.len(),
            if self.skipped.is_empty() { String::new() } else { format!(", {} skipped", self.skipped.len()) }
        )];
        for l in &self.lines {
            out.push(format!("  {l}"));
        }
        for s in &self.skipped {
            out.push(format!("  skipped {s}"));
        }
        out.join("\n")
    }
}

/// `curator review`: turn pending candidates into skills (`apply`) or just list them.
pub fn review(cfg: &Config, paths: &Paths, s: &Settings, apply: bool) -> Outcome {
    let st = Store::new(paths);
    let mut out = Outcome::default();
    for c in candidates(&st).into_iter().filter(|c| c.status == "pending") {
        out.seen += 1;
        let line = format!("{} — {} ({} step(s), target `{}`)", c.id, c.goal, c.steps.len(), c.target);
        if !apply {
            out.lines.push(line);
            continue;
        }
        let ops = match ops_for(cfg, paths, s, &c) {
            Ok(o) => o,
            Err(e) => {
                out.skipped.push(format!("{}: {e}", c.id));
                continue;
            }
        };
        let ctx = manage::Ctx { cfg, paths, ws: Path::new(if c.workspace.is_empty() { "/" } else { &c.workspace }), settings: s, session: Some(c.session.as_str()) };
        match manage::run(&ctx, &ops) {
            Ok(msg) => {
                let staged = msg.contains("staged skill write");
                mark(&st, std::slice::from_ref(&c.id), if staged { "staged" } else { "written" });
                out.written.extend(ops.iter().map(|o| o.name.clone()));
                out.lines.push(format!("{} — {}", c.id, msg.lines().next().unwrap_or("")));
            }
            Err(e) => out.skipped.push(format!("{}: {e}", c.id)),
        }
    }
    if out.seen == 0 {
        out.lines.push("no candidate procedures (a turn becomes one after `[skills.review] min_steps` tool calls)".into());
    }
    out
}

/// `/refine`: one-shot refinement of the session's skill — a proposal, or the applied patch.
#[derive(Debug, Clone)]
pub struct Proposal {
    pub name: String,
    pub content: String,
    pub advisories: Vec<String>,
    pub steps: usize,
}

/// Build the proposal from the steps this session actually ran.
pub fn propose(cfg: &Config, paths: &Paths, s: &Settings, ws: &Path, session: &str, name: Option<&str>, focus: &str) -> Result<Proposal, String> {
    let st = Store::new(paths);
    let recorded = steps(&st, session);
    if recorded.is_empty() {
        return Err("nothing recorded in this session yet (`/refine` folds the steps that ran into the skill that governs them; run the work first, or name the skill with `/refine <name> <focus>`) ".trim_end().to_string());
    }
    let target = name.map(str::to_string).or_else(|| last_loaded(&st, session)).ok_or("no skill was loaded in this session: `/refine <name>` names the skill to refine")?;
    let settings = Settings { disabled: vec![], ..s.clone() };
    let cat = invoke::catalog_loadable(cfg, paths, ws, &settings);
    let sk = invoke::resolve(&cat, &target).ok_or_else(|| format!("no skill `{target}` to refine"))?;
    let current = std::fs::read_to_string(&sk.file).map_err(|e| format!("{}: {e}", sk.file.display()))?;
    let lines = step_lines(&recorded);
    let r = workshop::refine(&current, &sk.name, focus, &lines)?;
    Ok(Proposal { name: sk.name.clone(), content: r.content, advisories: r.advisories, steps: recorded.len() })
}

/// Apply a proposal through the guarded writer.
pub fn apply(cfg: &Config, paths: &Paths, s: &Settings, ws: &Path, session: &str, p: &Proposal) -> Result<String, String> {
    let ctx = manage::Ctx { cfg, paths, ws, settings: s, session: Some(session) };
    manage::run(&ctx, &[manage::Op { action: "update".into(), name: p.name.clone(), description: None, body: None, content: Some(p.content.clone()), old_string: None, new_string: None, replace_all: false, file_path: None }])
}

/// The lifecycle hook: record steps and candidate procedures as turns run.
pub struct ReviewTick {
    pub cfg: Config,
    pub paths: Paths,
    pub settings: Settings,
    pub store: Store,
}

impl ReviewTick {
    pub fn new(cfg: &Config, paths: &Paths, settings: Settings) -> ReviewTick {
        ReviewTick { cfg: cfg.clone(), paths: paths.clone(), settings, store: Store::new(paths) }
    }
}

impl seagent_kernel::lifecycle::Lifecycle for ReviewTick {
    fn name(&self) -> String {
        "skill-review".into()
    }
    fn tool_settled(&self, session: &str, tool: &str, input: &Value, is_error: bool) {
        note_step(&self.store, session, tool, input, is_error);
        // Reading a skill is what makes it "the loaded skill": the review prefers patching it.
        if tool == "skill" && input.get("action").and_then(Value::as_str).is_none_or(|a| a == "view") {
            if let Some(n) = input.get("name").and_then(Value::as_str) {
                note_loaded(&self.store, Some(session), n);
            }
        }
    }
    fn turn_end(&self, session: &str, workspace: &str, user: &str, _assistant: &str, ok: bool) {
        let Some(cand) = record_candidate(&self.settings, &self.store, session, workspace, user, ok) else { return };
        if !self.settings.review.auto_apply {
            return;
        }
        // `[skills.review] auto_apply`: write it now, off the turn's thread.
        let (cfg, paths, s, store) = (self.cfg.clone(), self.paths.clone(), self.settings.clone(), self.store.clone());
        std::thread::spawn(move || {
            if let Ok(ops) = ops_for(&cfg, &paths, &s, &cand) {
                let cws = Path::new(if cand.workspace.is_empty() { "/" } else { &cand.workspace });
                let ctx = manage::Ctx { cfg: &cfg, paths: &paths, ws: cws, settings: &s, session: Some(cand.session.as_str()) };
                if manage::run(&ctx, &ops).is_ok() {
                    mark(&store, &[cand.id], "written");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(tag: &str) -> (std::path::PathBuf, Paths, std::path::PathBuf) {
        let d = seagent_core::tmp::scratch_path(format!("seagent-review-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let paths = Paths { data: d.join("data"), config_dir: d.join("config"), runtime: d.join("run"), ..Default::default() };
        let ws = d.join("ws");
        std::fs::create_dir_all(ws.join(".seagent/skills")).unwrap();
        (d, paths, ws)
    }

    #[test]
    fn steps_loaded_skill_and_candidate_recording() {
        let (d, paths, ws) = fixture("a");
        let st = Store::new(&paths);
        let s = Settings::from_table(&toml::Table::new());
        let lc = ReviewTick::new(&Config::default(), &paths, s.clone());
        use seagent_kernel::lifecycle::Lifecycle;
        // The same command twice is one step; a failure is recorded as not ok.
        lc.tool_settled("s1", "shell", &json!({"command": "cargo test -p seagent-skills"}), false);
        lc.tool_settled("s1", "shell", &json!({"command": "cargo test -p seagent-skills"}), false);
        lc.tool_settled("s1", "read", &json!({"path": "src/lib.rs"}), false);
        lc.tool_settled("s1", "edit", &json!({"path": "src/lib.rs"}), true);
        let steps = steps(&st, "s1");
        assert_eq!(steps.len(), 3, "{steps:?}");
        assert_eq!(steps[0].render(), "shell: cargo test -p seagent-skills");
        assert!(!steps[2].ok, "a failed call stays visible rather than becoming guidance");
        // A loaded skill is remembered; the most recent one wins.
        lc.tool_settled("s1", "skill", &json!({"action": "view", "name": "deploy"}), false);
        note_loaded(&st, Some("s1"), "review");
        assert_eq!(last_loaded(&st, "s1").as_deref(), Some("review"));
        lc.tool_settled("s1", "skill", &json!({"name": "deploy"}), false);
        assert_eq!(last_loaded(&st, "s1").as_deref(), Some("deploy"), "a skill call with no action is a view");
        // Too few steps is not a procedure.
        let mut high = s.clone();
        high.review.min_steps = 99;
        assert!(record_candidate(&high, &st, "s1", &ws.display().to_string(), "Ship the staging release", true).is_none());
        let mut low = s.clone();
        low.review.min_steps = 2;
        let c = record_candidate(&low, &st, "s1", &ws.display().to_string(), "Ship the staging release\nwith the fleet API", true).unwrap();
        assert_eq!(c.goal, "Ship the staging release", "the first line is the goal");
        assert_eq!(c.target, "deploy", "the loaded skill is the target");
        assert_eq!(c.steps.len(), 5, "the two skill views are steps too");
        // The same goal is one candidate; a failed turn records nothing.
        assert!(record_candidate(&low, &st, "s1", &ws.display().to_string(), "Ship the staging release", true).is_none());
        assert!(record_candidate(&low, &st, "s1", &ws.display().to_string(), "Reindex the search shards now", false).is_none());
        note_step(&st, "s2", "shell", &json!({"command": "seagent index rebuild"}), false);
        note_step(&st, "s2", "shell", &json!({"command": "seagent index verify"}), false);
        assert!(record_candidate(&low, &st, "s2", &ws.display().to_string(), "Reindex the search shards now", true).is_some());
        // Review off means no candidates at all.
        let mut off = low.clone();
        off.review.enabled = false;
        assert!(record_candidate(&off, &st, "s3", &ws.display().to_string(), "Reindex the search shards now", true).is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn review_pass_writes_skills_and_refine_proposes_then_applies() {
        let (d, paths, ws) = fixture("b");
        let st = Store::new(&paths);
        let cfg = Config::default();
        let mut s = Settings::from_table(&toml::Table::new());
        s.review.min_steps = 2;
        // A procedure with no skill loaded: the review creates a class-level skill.
        note_step(&st, "s1", "shell", &json!({"command": "cargo test -p seagent-skills"}), false);
        note_step(&st, "s1", "shell", &json!({"command": "cargo clippy -p seagent-skills"}), false);
        record_candidate(&s, &st, "s1", &ws.display().to_string(), "Run the seagent-skills test and lint loop", true).unwrap();
        // A dry run lists, writes nothing.
        let out = review(&cfg, &paths, &s, false);
        assert_eq!(out.seen, 1, "{out:?}");
        assert!(out.lines[0].contains("Run the seagent-skills test and lint loop") && out.written.is_empty());
        assert!(!paths.data.join("skills/run-the-seagent-skills-test-and-lint-loop").exists());
        // Applying writes it through the guarded writer.
        let out = review(&cfg, &paths, &s, true);
        assert_eq!(out.written, ["run-the-seagent-skills-test-and-lint-loop"], "{out:?}");
        let md = std::fs::read_to_string(paths.data.join("skills/run-the-seagent-skills-test-and-lint-loop/SKILL.md")).unwrap();
        assert!(md.contains("## When to Use\nRun the seagent-skills test and lint loop") && md.contains("1. Run `cargo test -p seagent-skills`"), "{md}");
        assert_eq!(candidates(&st)[0].status, "written", "a written candidate leaves the queue");
        assert_eq!(review(&cfg, &paths, &s, true).seen, 0);
        // With a loaded skill, the review refines it instead of creating a second one.
        std::fs::create_dir_all(paths.data.join("skills/deploy")).unwrap();
        std::fs::write(paths.data.join("skills/deploy/SKILL.md"), "---\nname: deploy\ndescription: Ship it\n---\n\n# Deploy\n\n## When to Use\nShipping.\n\n1. run tests\n").unwrap();
        note_loaded(&st, Some("s2"), "deploy");
        note_step(&st, "s2", "shell", &json!({"command": "seagent deploy rollback --to 42"}), false);
        note_step(&st, "s2", "shell", &json!({"command": "seagent deploy status"}), false);
        record_candidate(&s, &st, "s2", &ws.display().to_string(), "Roll back a bad canary release", true).unwrap();
        let out = review(&cfg, &paths, &s, true);
        assert_eq!(out.written, ["deploy"], "{out:?}");
        let md = std::fs::read_to_string(paths.data.join("skills/deploy/SKILL.md")).unwrap();
        assert!(md.contains("## Roll back a bad canary release") && md.contains("1. Run `seagent deploy rollback --to 42`"), "{md}");
        // /refine: a proposal from this session's steps, then the applied patch.
        note_step(&st, "s2", "shell", &json!({"command": "seagent deploy logs --since 5m"}), false);
        let p = propose(&cfg, &paths, &s, &ws, "s2", None, "Reading logs").unwrap();
        assert_eq!(p.name, "deploy");
        assert!(p.content.contains("## Reading logs") && p.steps >= 1, "{}", p.content);
        assert!(!std::fs::read_to_string(paths.data.join("skills/deploy/SKILL.md")).unwrap().contains("## Reading logs"), "a proposal is not a write");
        let text = apply(&cfg, &paths, &s, &ws, "s2", &p).unwrap();
        assert!(text.contains("rewrote SKILL.md of `deploy`"), "{text}");
        assert!(std::fs::read_to_string(paths.data.join("skills/deploy/SKILL.md")).unwrap().contains("## Reading logs"));
        // A session with no recorded steps cannot refine anything.
        assert!(propose(&cfg, &paths, &s, &ws, "nobody", None, "").unwrap_err().contains("nothing recorded"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `[skills.review] auto_apply`: the turn end itself writes the skill (in the background).
    #[test]
    fn auto_apply_writes_at_turn_end() {
        let (d, paths, ws) = fixture("d");
        let st = Store::new(&paths);
        let mut s = Settings::from_table(&toml::Table::new());
        s.review.min_steps = 2;
        s.review.auto_apply = true;
        let lc = ReviewTick::new(&Config::default(), &paths, s);
        use seagent_kernel::lifecycle::Lifecycle;
        lc.tool_settled("s1", "shell", &json!({"command": "seagent backup --all"}), false);
        lc.tool_settled("s1", "shell", &json!({"command": "seagent backup verify"}), false);
        lc.turn_end("s1", &ws.display().to_string(), "Back up every workspace nightly", "", true);
        let target = paths.data.join("skills/back-up-every-workspace-nightly/SKILL.md");
        for _ in 0..100 {
            if target.is_file() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(target.is_file(), "auto_apply writes the candidate at turn end");
        // The background writer marks the candidate "written" after the skill file lands; let it
        // finish before the scratch tree is removed, or it would re-create the tree afterwards.
        for _ in 0..200 {
            if candidates(&st).iter().all(|c| c.status == "written") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(std::fs::read_to_string(&target).unwrap().contains("1. Run `seagent backup --all`"));
        // A turn that fails records nothing at all.
        let before = candidates(&st).len();
        lc.tool_settled("s2", "shell", &json!({"command": "seagent restore --last"}), false);
        lc.tool_settled("s2", "shell", &json!({"command": "seagent restore verify"}), false);
        lc.turn_end("s2", &ws.display().to_string(), "Restore the last workspace backup", "", false);
        assert_eq!(candidates(&st).len(), before, "a failed turn is not a procedure");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn state_file_is_bounded() {
        let (d, paths, _ws) = fixture("c");
        let st = Store::new(&paths);
        for i in 0..(MAX_SESSIONS + 5) {
            note_step(&st, &format!("s{i}"), "shell", &json!({"command": format!("cmd {i}")}), false);
        }
        let state = load(&st);
        assert_eq!(state["sessions"].as_array().unwrap().len(), MAX_SESSIONS, "old sessions are dropped");
        assert!(session_of(&state, &format!("s{}", MAX_SESSIONS + 4)).is_some(), "the newest survives");
        assert!(session_of(&state, "s0").is_none(), "the oldest went");
        let _ = std::fs::remove_dir_all(&d);
    }
}
