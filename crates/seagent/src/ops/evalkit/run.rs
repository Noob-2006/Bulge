//! The attempt loop: subjects × tasks × repeats → `results.jsonl`.
//!
//! Harnesses for an seagent subject:
//! - chat tasks: one call to the model (system = task system + the subject's guidelines);
//! - agent tasks, `seagent` harness (default): the full seagent kernel with its builtin tools, a fresh
//!   session per attempt in a fresh working directory, sessions kept under the run's own home;
//! - agent tasks, `mini` harness (`seagent batch swe`'s loop, [`crate::ops::miniswe`]): one
//!   `terminal` tool, locally or inside the task's container image (`seagent-test-eval-*`);
//! - desktop tasks: the OSWorld adapter ([`super::bench::osworld_attempt`]).
//!
//! External agents never run inside seagent: [`super::external`] writes their command lines and,
//! only with `--exec-external`, runs them and collects their output.

use super::external::AgentSpec;
use super::fake::{self, EvalResolver, Fake, Meter};
use super::grade::{self, CheckResult, Judge};
use super::{bench, slug, Kind, Task};
use seagent_core::{Cancel, Message, ModelRequest, Provider, SystemSegment};
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::kernel::{Kernel, Resolver};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Run a command with a timeout in its own process group; on timeout the whole group is
/// killed so nothing a task started outlives the run.
pub fn capture(mut cmd: std::process::Command, timeout: Duration) -> Result<(String, i32), String> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    cmd.process_group(0);
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| e.to_string())?;
    let pgid = child.id() as i32;
    struct Group(i32, bool);
    impl Drop for Group {
        fn drop(&mut self) {
            if !self.1 {
                unsafe {
                    libc::kill(-self.0, libc::SIGKILL);
                }
            }
        }
    }
    let mut guard = Group(pgid, false);
    let (mut so, mut se) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let ho = std::thread::spawn(move || {
        let mut v = vec![];
        let _ = so.read_to_end(&mut v);
        v
    });
    let he = std::thread::spawn(move || {
        let mut v = vec![];
        let _ = se.read_to_end(&mut v);
        v
    });
    let start = Instant::now();
    let st = loop {
        if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
            break s;
        }
        if start.elapsed() > timeout {
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
            let _ = child.wait();
            guard.1 = true;
            return Err(format!("timed out after {}s", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // the leader exited; reap anything it left in the group
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    guard.1 = true;
    let mut out = String::from_utf8_lossy(&ho.join().unwrap_or_default()).into_owned();
    out.push_str(&String::from_utf8_lossy(&he.join().unwrap_or_default()));
    Ok((out, st.code().unwrap_or(-1)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Harness {
    /// `mini` when the task names a container image, else `seagent`.
    Auto,
    Seagent,
    Mini,
}

impl Harness {
    pub fn parse(s: &str) -> Result<Harness, String> {
        match s {
            "auto" => Ok(Harness::Auto),
            "seagent" => Ok(Harness::Seagent),
            "mini" => Ok(Harness::Mini),
            o => Err(format!("unknown harness `{o}` (auto, seagent, mini)")),
        }
    }
}

#[derive(Clone)]
pub enum SubjectKind {
    Seagent {
        model: String,
        harness: Harness,
        /// Guidelines put in front of chat tasks (role evaluations).
        guidelines: Option<String>,
        /// `[role] active` for kernel attempts.
        role: Option<String>,
    },
    External {
        agent: AgentSpec,
        model: Option<String>,
    },
}

#[derive(Clone)]
pub struct Subject {
    pub label: String,
    pub kind: SubjectKind,
}

impl Subject {
    pub fn seagent(model: &str) -> Subject {
        Subject { label: format!("seagent:{model}"), kind: SubjectKind::Seagent { model: model.into(), harness: Harness::Auto, guidelines: None, role: None } }
    }
    pub fn model(&self) -> Option<&str> {
        match &self.kind {
            SubjectKind::Seagent { model, .. } => Some(model),
            SubjectKind::External { model, .. } => model.as_deref(),
        }
    }
}

/// One attempt of one subject at one task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Attempt {
    pub subject: String,
    pub task: String,
    pub suite: String,
    pub rep: u32,
    /// `done` (graded), `error` (the attempt itself failed), `pending` (an external agent's
    /// command was written, not run), `unsupported` (the task needs something this run lacks).
    pub status: String,
    pub answer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub calls: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_usd: Option<f64>,
    pub ms: u64,
    pub checks: Vec<CheckResult>,
    pub score: f64,
    pub pass: bool,
    pub judge_input_tokens: u64,
    pub judge_output_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge_cost_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub artifacts: Value,
}

impl Attempt {
    pub fn key(&self) -> (String, String, u32) {
        (self.subject.clone(), self.task.clone(), self.rep)
    }
}

/// What a harness hands back before grading.
#[derive(Default)]
pub struct Outcome {
    pub answer: String,
    pub usage: seagent_core::Usage,
    pub calls: u64,
    pub error: Option<String>,
    pub status: Option<String>,
    /// Graded already (container harnesses grade before teardown).
    pub graded: Option<(Vec<CheckResult>, f64, bool)>,
    pub artifacts: Value,
}

pub struct Runner {
    pub out: PathBuf,
    pub fake: Arc<Fake>,
    pub resolver: Arc<EvalResolver>,
    pub base_cfg: Config,
    pub judge: Option<Judge>,
    pub repeat: u32,
    pub resume: bool,
    pub exec_external: bool,
    pub container_bin: String,
    /// `model → (USD per Mtok in, out)` overrides (`--price`).
    pub prices: BTreeMap<String, (f64, f64)>,
    pub max_iterations: u32,
    pub quiet: bool,
    /// `--env-file` for desktop containers (model keys for `seagent run` inside them).
    pub container_env_file: Option<String>,
    /// Local copies of files OSWorld setup steps would download.
    pub cache_dir: Option<PathBuf>,
    /// `--tool-profile`: the tool policy applied to in-process kernel attempts (`benchmark`
    /// = few tools, for a cheap baseline). None keeps the configured profile.
    pub tool_profile: Option<String>,
    kernels: Mutex<HashMap<String, Kernel>>,
}

impl Runner {
    pub fn new(out: &Path, base_cfg: Config, real: Option<Arc<dyn Resolver>>) -> Runner {
        let fake = Fake::new();
        Runner {
            out: out.to_path_buf(),
            resolver: Arc::new(EvalResolver { fake: fake.clone(), real }),
            fake,
            base_cfg,
            judge: None,
            repeat: 1,
            resume: false,
            exec_external: false,
            container_bin: "podman".into(),
            prices: BTreeMap::new(),
            max_iterations: 30,
            quiet: true,
            container_env_file: None,
            cache_dir: None,
            tool_profile: None,
            kernels: Mutex::new(HashMap::new()),
        }
    }

    pub fn provider(&self, model: &str) -> Result<Arc<dyn Provider>, String> {
        let (pid, _) = seagent_kernel::context::split_model(model);
        if pid.is_empty() {
            return Err(format!("model must be provider/model, got `{model}`"));
        }
        self.resolver.provider(pid)
    }

    /// The judge for `--judge MODEL` (`fake/*` judges offline).
    pub fn set_judge(&mut self, model: &str) -> Result<(), String> {
        let provider = if fake::is_fake(model) { None } else { Some(self.provider(model)?) };
        self.judge = Some(Judge { model: model.into(), provider });
        Ok(())
    }

    /// USD per Mtok (in, out) for a model.
    pub fn price(&self, model: &str) -> Option<(f64, f64)> {
        if let Some(p) = self.prices.get(model) {
            return Some(*p);
        }
        if let Some(p) = self.base_cfg.price(model) {
            return Some((p.input, p.output));
        }
        if fake::is_fake(model) || std::env::var_os("SEAGENT_OFFLINE").is_some() {
            return None;
        }
        let (pid, name) = seagent_kernel::context::split_model(model);
        seagent_model::modelsdb::price_for(pid, name).map(|p| (p.input, p.output))
    }

    fn cost(&self, model: Option<&str>, i: u64, o: u64) -> Option<f64> {
        let (pi, po) = self.price(model?)?;
        Some((i as f64 * pi + o as f64 * po) / 1e6)
    }

    pub fn results_path(&self) -> PathBuf {
        self.out.join("results.jsonl")
    }

    fn previous(&self) -> HashMap<(String, String, u32), Attempt> {
        let Ok(text) = std::fs::read_to_string(self.results_path()) else { return HashMap::new() };
        text.lines().filter_map(|l| serde_json::from_str::<Attempt>(l).ok()).filter(|a| a.status == "done").map(|a| (a.key(), a)).collect()
    }

    fn workdir(&self, s: &Subject, t: &Task, rep: u32) -> PathBuf {
        self.out.join("work").join(slug(&s.label)).join(slug(&t.id)).join(format!("r{rep}"))
    }

    /// Fresh working directory with the task's files and setup commands applied.
    pub fn prepare(&self, t: &Task, dir: &Path) -> Result<(), String> {
        if dir.exists() {
            std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for (rel, body) in &t.files {
            let p = dir.join(super::safe_rel(rel)?);
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            std::fs::write(&p, body).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        for cmd in &t.setup {
            let cmd = cmd.replace("{container}", &self.container_bin);
            let mut c = std::process::Command::new("bash");
            c.arg("-c").arg(&cmd).current_dir(dir);
            let (o, code) = capture(c, Duration::from_secs(1800))?;
            if code != 0 {
                return Err(format!("setup `{cmd}` failed ({code}): {}", o.trim()));
            }
        }
        Ok(())
    }

    fn kernel(&self, s: &Subject, model: &str, role: Option<&str>) -> Result<Kernel, String> {
        let mut ks = self.kernels.lock().unwrap();
        if let Some(k) = ks.get(&s.label) {
            return Ok(k.clone());
        }
        let root = self.out.join(".home").join(slug(&s.label));
        let paths = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() };
        for d in [&paths.data, &paths.config_dir, &paths.runtime] {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let mut cfg = self.base_cfg.clone();
        cfg.model.default = model.into();
        cfg.checkpoint.enabled = false;
        cfg.role.active = role.unwrap_or("").to_string();
        if let Some(p) = &self.tool_profile {
            cfg.tools.profile = Some(p.clone());
        }
        let k = seagent_kernel::kernel::new_kernel(
            cfg,
            paths,
            self.resolver.clone(),
            seagent_tools::builtin_tools(),
            Arc::new(seagent_kernel::vault::Vault::empty()),
            Arc::new(seagent_kernel::approver::Policy { allow_privilege: false, allow_egress: false }),
        );
        ks.insert(s.label.clone(), k.clone());
        Ok(k)
    }

    fn chat(&self, t: &Task, model: &str, guidelines: Option<&str>) -> Outcome {
        let meter = match self.provider(model) {
            Ok(p) => Meter::new(p),
            Err(e) => return Outcome { error: Some(e), ..Default::default() },
        };
        let mut system = vec![];
        for (id, text) in [("guidelines", guidelines), ("task", t.system.as_deref())] {
            if let Some(x) = text.filter(|x| !x.trim().is_empty()) {
                system.push(SystemSegment { id: id.into(), text: x.to_string(), cache: false });
            }
        }
        let (_, name) = seagent_kernel::context::split_model(model);
        let req = ModelRequest { model: name.into(), system, messages: vec![Message::user(t.prompt.clone())], max_tokens: 4096, ..Default::default() };
        let cancel = Cancel::new().with_deadline(Instant::now() + Duration::from_secs(t.timeout_secs.unwrap_or(600)));
        match meter.complete(&req, &mut |_| {}, &cancel) {
            Ok(r) => {
                let (usage, calls) = meter.total();
                Outcome { answer: r.message.text(), usage, calls, ..Default::default() }
            }
            Err(e) => Outcome { error: Some(e.to_string()), usage: meter.total().0, ..Default::default() },
        }
    }

    fn kernel_attempt(&self, s: &Subject, t: &Task, model: &str, role: Option<&str>, dir: &Path) -> Outcome {
        let k = match self.kernel(s, model, role) {
            Ok(k) => k,
            Err(e) => return Outcome { error: Some(e), ..Default::default() },
        };
        let run = || -> Result<Outcome, String> {
            let id = k.create_session(dir, Some(model), None, Some(&format!("eval {}", t.id))).map_err(|e| e.to_string())?;
            let res = (|| {
                k.submit(&id, &t.prompt, "user").map_err(|e| e.to_string())?;
                let cancel = Cancel::new().with_deadline(Instant::now() + Duration::from_secs(t.timeout_secs.unwrap_or(1800)));
                let o = k.run(&id, seagent_kernel::kernel::RunOpts { cancel: Some(cancel), ..Default::default() }).map_err(|e| e.to_string())?;
                let err = match &o.reason {
                    seagent_kernel::kernel::EndReason::Error(e) => Some(e.clone()),
                    _ => None,
                };
                Ok(Outcome { answer: o.text, usage: o.usage, calls: o.turns, error: err, artifacts: json!({"end": format!("{:?}", o.reason)}), ..Default::default() })
            })();
            let _ = k.store.remove(&id);
            res
        };
        run().unwrap_or_else(|e| Outcome { error: Some(e), ..Default::default() })
    }

    fn mini_attempt(&self, s: &Subject, t: &Task, model: &str, dir: &Path) -> Outcome {
        let meter = match self.provider(model) {
            Ok(p) => Meter::new(p),
            Err(e) => return Outcome { error: Some(e), ..Default::default() },
        };
        let (_, name) = seagent_kernel::context::split_model(model);
        let in_container = t.image.is_some();
        let r = crate::ops::miniswe::Runner {
            provider: meter.clone(),
            model: name.into(),
            env_kind: if in_container { "docker".into() } else { "local".into() },
            image: t.image.clone().unwrap_or_default(),
            cwd: Some(if in_container { PathBuf::from(t.meta_str("container_workdir").unwrap_or("/app")) } else { dir.to_path_buf() }),
            docker_bin: self.container_bin.clone(),
            max_iterations: self.max_iterations,
            command_timeout: 300,
            container_name: in_container.then(|| format!("seagent-test-eval-{}-{}", slug(&t.id).to_lowercase(), seagent_kernel::util::random_hex(4))),
        };
        let mut graded = None;
        let mut artifacts = Value::Null;
        let judge = self.judge.clone();
        let res = r.run_task_then(&t.prompt, &mut |env| {
            let exec = |cmd: &str| {
                let v = env.execute(cmd, 600);
                (format!("{}{}", v["output"].as_str().unwrap_or(""), v["error"].as_str().unwrap_or("")), v["exit_code"].as_i64().unwrap_or(-1) as i32)
            };
            if let (Some(id), Some(bin)) = (env.container_id(), env.container_bin()) {
                bench::before_grade_in_container(t, bin, id);
            }
            artifacts = bench::after_attempt(t, &exec, &self.out, &s.label);
            graded = Some(grade::grade(t, "", Some(dir), Some(&exec), judge.as_ref()));
        });
        let (usage, calls) = meter.total();
        match res {
            Ok(v) => {
                let answer = v["conversations"].as_array().and_then(|c| c.iter().rev().find(|m| m["from"] == "gpt")).and_then(|m| m["value"].as_str()).unwrap_or("").to_string();
                // the final answer counts for answer checks: grade again with it when needed
                let graded = graded.map(|(c, sc, p)| {
                    if t.checks.iter().any(|c| !matches!(c, super::Check::Command { .. })) {
                        let regraded: Vec<CheckResult> = c.into_iter().zip(&t.checks).map(|(r, chk)| if matches!(chk, super::Check::Command { .. }) { r } else { grade::grade(&Task { checks: vec![chk.clone()], ..t.clone() }, &answer, Some(dir), None, judge.as_ref()).0.remove(0) }).collect();
                        let score = regraded.iter().map(|c| c.score).sum::<f64>() / regraded.len().max(1) as f64;
                        let pass = !regraded.is_empty() && regraded.iter().all(|c| c.pass);
                        (regraded, score, pass)
                    } else {
                        (c, sc, p)
                    }
                });
                Outcome { answer, usage, calls, graded, artifacts: merged(artifacts, json!({"completed": v["completed"]})), ..Default::default() }
            }
            Err(e) => Outcome { error: Some(e), usage, calls, ..Default::default() },
        }
    }

    /// Run every subject on every task `repeat` times; append each attempt to
    /// `results.jsonl` as it finishes. With `resume`, finished attempts are kept.
    pub fn run(&self, tasks: &[Task], subjects: &[Subject]) -> Result<Vec<Attempt>, String> {
        std::fs::create_dir_all(&self.out).map_err(|e| format!("{}: {e}", self.out.display()))?;
        for t in tasks {
            if let Some(f) = &t.fake {
                self.fake.register(&t.prompt, f.clone());
            }
        }
        if !self.resume {
            let _ = std::fs::remove_file(self.results_path());
        }
        self.run_more(tasks, subjects)
    }

    /// Like [`Runner::run`] but always appends to `results.jsonl` (several calls build one run).
    pub fn run_more(&self, tasks: &[Task], subjects: &[Subject]) -> Result<Vec<Attempt>, String> {
        std::fs::create_dir_all(&self.out).map_err(|e| format!("{}: {e}", self.out.display()))?;
        for t in tasks {
            if let Some(f) = &t.fake {
                self.fake.register(&t.prompt, f.clone());
            }
        }
        let prev = if self.resume { self.previous() } else { HashMap::new() };
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(self.results_path()).map_err(|e| e.to_string())?;
        let mut all = vec![];
        let total = subjects.len() * tasks.len() * self.repeat as usize;
        let mut n = 0;
        for s in subjects {
            for t in tasks {
                for rep in 1..=self.repeat {
                    n += 1;
                    if let Some(a) = prev.get(&(s.label.clone(), t.id.clone(), rep)) {
                        all.push(a.clone());
                        continue;
                    }
                    let a = self.attempt(s, t, rep);
                    if !self.quiet {
                        eprintln!("[{n}/{total}] {} {} r{rep}: {} score {:.2}{}", s.label, t.id, a.status, a.score, a.error.as_deref().map(|e| format!(" ({})", e.chars().take(120).collect::<String>())).unwrap_or_default());
                    }
                    writeln!(file, "{}", serde_json::to_string(&a).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
                    file.flush().map_err(|e| e.to_string())?;
                    all.push(a);
                }
            }
        }
        Ok(all)
    }

    pub fn attempt(&self, s: &Subject, t: &Task, rep: u32) -> Attempt {
        let start = Instant::now();
        let mut a = Attempt { subject: s.label.clone(), task: t.id.clone(), suite: t.suite.clone(), rep, ..Default::default() };
        if let Some(f) = &t.fake {
            self.fake.register(&t.prompt, f.clone());
        }
        if let Some(u) = t.meta_str("unsupported") {
            a.status = "unsupported".into();
            a.error = Some(u.into());
            return a;
        }
        let needs_dir = t.kind != Kind::Chat || matches!(s.kind, SubjectKind::External { .. });
        let dir = self.workdir(s, t, rep);
        if needs_dir {
            if let Err(e) = self.prepare(t, &dir) {
                a.status = "error".into();
                a.error = Some(e);
                a.ms = start.elapsed().as_millis() as u64;
                return a;
            }
            a.workdir = Some(dir.display().to_string());
        }
        let o = match (&s.kind, t.kind) {
            (SubjectKind::External { agent, model }, _) => super::external::attempt(self, agent, model.as_deref(), t, rep, &dir),
            (SubjectKind::Seagent { model, guidelines, .. }, Kind::Chat) => self.chat(t, model, guidelines.as_deref()),
            (SubjectKind::Seagent { model, harness, role, .. }, Kind::Agent) => match (harness, t.image.is_some()) {
                (Harness::Mini, _) | (Harness::Auto, true) => self.mini_attempt(s, t, model, &dir),
                (Harness::Seagent, true) => Outcome { status: Some("unsupported".into()), error: Some(format!("task needs container image {}; use --harness mini", t.image.as_deref().unwrap_or(""))), ..Default::default() },
                _ => self.kernel_attempt(s, t, model, role.as_deref(), &dir),
            },
            (SubjectKind::Seagent { model, .. }, Kind::Desktop) => bench::osworld_attempt(self, s, t, model, &dir),
        };
        bench::record_answer(t, &o.answer, &self.out, &s.label);
        a.answer = o.answer.chars().take(8000).collect();
        a.input_tokens = o.usage.input_tokens;
        a.output_tokens = o.usage.output_tokens;
        a.calls = o.calls;
        a.cost_usd = self.cost(s.model(), a.input_tokens, a.output_tokens);
        a.artifacts = o.artifacts;
        a.status = o.status.clone().unwrap_or_else(|| if o.error.is_some() { "error".into() } else { "done".into() });
        a.error = o.error;
        if a.status == "done" {
            let (checks, score, pass) = match o.graded {
                Some(g) => g,
                None => {
                    if t.kind != Kind::Chat && t.image.is_none() && !a.artifacts.get("graded_in_container").and_then(Value::as_bool).unwrap_or(false) {
                        let ex = grade::host_exec(&dir, 600);
                        let extra = bench::after_attempt(t, &ex, &self.out, &s.label);
                        merge(&mut a.artifacts, extra);
                        grade::grade(t, &a.answer, Some(&dir), Some(&ex), self.judge.as_ref())
                    } else {
                        grade::grade(t, &a.answer, needs_dir.then_some(dir.as_path()), None, self.judge.as_ref())
                    }
                }
            };
            for c in &checks {
                if let Some(u) = &c.judge_usage {
                    a.judge_input_tokens += u.input_tokens;
                    a.judge_output_tokens += u.output_tokens;
                }
            }
            a.judge_cost_usd = self.judge.as_ref().and_then(|j| self.cost(Some(&j.model), a.judge_input_tokens, a.judge_output_tokens)).filter(|_| a.judge_input_tokens > 0);
            a.checks = checks;
            a.score = score;
            a.pass = pass;
            if bench::needs_official_scoring(t) {
                a.status = "pending".into();
            }
        }
        a.ms = start.elapsed().as_millis() as u64;
        a
    }
}

fn merged(mut a: Value, b: Value) -> Value {
    merge(&mut a, b);
    a
}

fn merge(into: &mut Value, extra: Value) {
    match (into.as_object_mut(), extra) {
        (Some(o), Value::Object(e)) => o.extend(e),
        (None, e @ Value::Object(_)) => *into = e,
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::evalkit::{Check, FakeScript};

    fn runner(out: &Path) -> Runner {
        let mut cfg = Config::default();
        cfg.checkpoint.enabled = false;
        let mut r = Runner::new(out, cfg, None);
        r.set_judge("fake/judge").unwrap();
        r.prices.insert("fake/oracle".into(), (1.0, 2.0));
        r
    }

    #[test]
    fn capture_kills_the_whole_group_on_timeout() {
        let d = seagent_core::tmp::scratch("seagent-cap");
        let mut c = std::process::Command::new("bash");
        c.arg("-c").arg(format!("(sleep 30; touch {}/late) & sleep 30", d.display()));
        let e = capture(c, Duration::from_millis(300)).unwrap_err();
        assert!(e.contains("timed out"));
        let mut c = std::process::Command::new("bash");
        c.arg("-c").arg("echo out; echo err >&2; exit 3");
        assert_eq!(capture(c, Duration::from_secs(5)).unwrap(), ("out\nerr\n".into(), 3));
    }

    #[test]
    fn chat_and_kernel_agent_attempts_are_graded_and_costed() {
        let _l = crate::testkit::env_lock();
        let out = seagent_core::tmp::scratch("seagent-evrun");
        let r = runner(&out);
        let tasks = vec![
            Task { id: "qa".into(), prompt: "2+2?".into(), fake: Some(FakeScript { commands: vec![], answer: "FINAL ANSWER: 4".into() }), checks: vec![Check::Exact { expected: "4".into(), normalize: Some("gaia".into()) }], ..Default::default() },
            Task {
                id: "fix".into(),
                kind: Kind::Agent,
                prompt: "make the greeting file say hello".into(),
                files: [("greeting.txt".to_string(), "bye\n".to_string())].into(),
                fake: Some(FakeScript { commands: vec!["echo hello > greeting.txt".into()], answer: "done".into() }),
                checks: vec![Check::Command { cmd: "grep -q hello greeting.txt".into(), expect_exit: 0 }],
                ..Default::default()
            },
        ];
        let subs = vec![Subject::seagent("fake/oracle"), Subject::seagent("fake/blank")];
        let res = r.run(&tasks, &subs).unwrap();
        assert_eq!(res.len(), 4);
        let get = |s: &str, t: &str| res.iter().find(|a| a.subject == s && a.task == t).unwrap();
        let ok = get("seagent:fake/oracle", "fix");
        assert_eq!((ok.status.as_str(), ok.pass), ("done", true), "{ok:?}");
        assert!(ok.calls >= 1 && ok.input_tokens > 0, "{ok:?}");
        assert!(ok.cost_usd.unwrap() > 0.0);
        assert!(get("seagent:fake/oracle", "qa").pass);
        assert!(!get("seagent:fake/blank", "qa").pass && !get("seagent:fake/blank", "fix").pass);
        assert!(get("seagent:fake/blank", "qa").cost_usd.is_none());
        // resume keeps finished attempts and does not rerun them
        let mut r2 = runner(&out);
        r2.resume = true;
        let again = r2.run(&tasks, &subs).unwrap();
        assert_eq!(again.iter().map(Attempt::key).collect::<Vec<_>>(), res.iter().map(Attempt::key).collect::<Vec<_>>());
        assert_eq!(std::fs::read_to_string(r2.results_path()).unwrap().lines().count(), 4);
        // a real provider that is not configured is an attempt error, not a crash
        let a = r.attempt(&Subject::seagent("nosuch/model"), &tasks[0], 1);
        assert_eq!(a.status, "error");
        assert!(a.error.unwrap().contains("not configured"));
    }

    #[test]
    fn tool_profile_reaches_the_eval_kernel() {
        let out = seagent_core::tmp::scratch("seagent-evprofile");
        let mut r = runner(&out);
        r.tool_profile = Some("benchmark".into());
        let k = r.kernel(&Subject::seagent("fake/oracle"), "fake/oracle", None).unwrap();
        assert_eq!(k.cfg.tools.profile.as_deref(), Some("benchmark"));
    }

    #[test]
    fn mini_harness_runs_in_a_named_task_container_and_grades_before_teardown() {
        use std::os::unix::fs::PermissionsExt;
        let out = seagent_core::tmp::scratch("seagent-evmini");
        let bin = out.join("podman");
        // fake container CLI: `run` prints an id, `exec … bash -lc CMD` runs CMD on the host in
        // a sandbox dir, `rm -f` is logged
        let sand = out.join("ctr");
        std::fs::create_dir_all(&sand).unwrap();
        std::fs::write(&bin, format!("#!/bin/sh\necho \"$@\" >> {0}/log\ncase \"$1\" in run) echo cid9;; exec) shift 4; cd {1} && sh -c \"$3\";; esac\n", out.display(), sand.display())).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut r = runner(&out);
        r.container_bin = bin.display().to_string();
        let t = Task {
            id: "tb-1".into(),
            kind: Kind::Agent,
            prompt: "create done.txt".into(),
            image: Some("img:1".into()),
            fake: Some(FakeScript { commands: vec!["echo ok > done.txt".into()], answer: "finished".into() }),
            checks: vec![Check::Command { cmd: "test -f done.txt".into(), expect_exit: 0 }, Check::Contains { all: vec!["finished".into()], any: vec![], none: vec![], ignore_case: false }],
            ..Default::default()
        };
        let a = r.attempt(&Subject::seagent("fake/oracle"), &t, 1);
        assert!(a.pass, "{a:?}");
        let log = std::fs::read_to_string(out.join("log")).unwrap();
        assert!(log.contains("--name seagent-test-eval-tb-1-"), "{log}");
        assert!(log.lines().last().unwrap().starts_with("rm -f cid9"), "{log}");
    }
}
