//! The evaluation runner (pro-005/006/007/008/018/047/048, gen1-301/302): one engine for
//! every scored run seagent does.
//!
//! ```text
//! tasks (native JSONL, SWE-bench, Terminal-Bench, GAIA, OSWorld, role scenarios)
//!   × subjects (seagent × each model, external agents as commands)
//!   × repeats
//!   → attempts (answer, workdir, tokens, cost, time)
//!   → checks (exact / contains / regex / command / file / judge model)
//!   → results.jsonl + report.json + report.md
//! ```
//!
//! `seagent evals list|run` (the hermetic runtime probes in [`super::evals`]) are unchanged; the
//! scored runner lives under the same command: `seagent evals bench|roles|fetch|import|report|
//! compare|collect|agents|swe-score` (see [`cli`]).
//!
//! Honesty rules carried over from the probes: a run never reaches the network or a paid model
//! unless the user named a real model on the command line; `fake/*` models ([`fake`]) are
//! deterministic stand-ins that prove the pipeline (load → run → grade → report) end to end.

pub mod bench;
pub mod cli;
pub mod external;
pub mod fake;
pub mod grade;
pub mod report;
pub mod roles;
pub mod run;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub use cli::{dispatch_sub, BOOL_FLAGS, VALUE_FLAGS};

/// How a task is attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// One model call, no tools (scenario questions, judgement, QA).
    #[default]
    Chat,
    /// An agent with tools in a prepared working directory (or a task container).
    Agent,
    /// A desktop task inside a Bot Desktop container (OSWorld).
    Desktop,
}

/// A rubric point for the judge: what a good answer says. `keywords` drive the offline
/// `fake/judge` (any keyword present = point met); a real judge model reads `text`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub text: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default = "one")]
    pub weight: f64,
}

fn one() -> f64 {
    1.0
}

/// One scoring rule. A task passes when every check passes; its score is the weighted mean.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Check {
    /// The final answer equals `expected` (`normalize = "gaia"`: GAIA's quasi-exact match).
    Exact {
        expected: String,
        #[serde(default)]
        normalize: Option<String>,
    },
    Contains {
        #[serde(default)]
        all: Vec<String>,
        #[serde(default)]
        any: Vec<String>,
        #[serde(default)]
        none: Vec<String>,
        #[serde(default)]
        ignore_case: bool,
    },
    Regex {
        pattern: String,
    },
    /// A shell command run in the task's working directory (or its container) after the
    /// agent; passes on the expected exit status.
    Command {
        cmd: String,
        #[serde(default)]
        expect_exit: i32,
    },
    /// A file in the working directory contains `text`.
    File {
        path: String,
        text: String,
    },
    /// A judge model scores the answer against the rubric points (and the task's reference).
    Judge {
        points: Vec<Point>,
        /// Fraction of the weighted points needed to pass (default 0.6).
        #[serde(default)]
        pass_at: Option<f64>,
    },
}

impl Check {
    pub fn kind(&self) -> &'static str {
        match self {
            Check::Exact { .. } => "exact",
            Check::Contains { .. } => "contains",
            Check::Regex { .. } => "regex",
            Check::Command { .. } => "command",
            Check::File { .. } => "file",
            Check::Judge { .. } => "judge",
        }
    }
}

/// What a `fake/oracle` model does on this task: shell commands first (one tool call each, when
/// the harness offers a shell), then this answer. Ignored by every real model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FakeScript {
    #[serde(default)]
    pub commands: Vec<String>,
    #[serde(default)]
    pub answer: String,
}

/// One evaluation item in the native format (`*.jsonl`, one object per line, or a JSON array).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Task {
    pub id: String,
    #[serde(default)]
    pub suite: String,
    #[serde(default)]
    pub kind: Kind,
    pub prompt: String,
    /// Extra system prompt for this task (chat tasks).
    #[serde(default)]
    pub system: Option<String>,
    /// Files written into the fresh working directory before the attempt (`path → content`).
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    /// Shell commands run in the working directory before the attempt (clone, checkout, …).
    #[serde(default)]
    pub setup: Vec<String>,
    /// Container image the attempt runs in (`--harness mini`, Terminal-Bench, SWE-bench images).
    #[serde(default)]
    pub image: Option<String>,
    #[serde(default)]
    pub checks: Vec<Check>,
    /// Preset or pack whose guidelines a role scenario is about.
    #[serde(default)]
    pub role: Option<String>,
    /// Reference material for the judge (expert notes, first-distillation sources).
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub fake: Option<FakeScript>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
    /// Benchmark-specific data (instance ids, container workdir, evaluator specs…).
    #[serde(default)]
    pub meta: Value,
}

impl Task {
    pub fn meta_str(&self, k: &str) -> Option<&str> {
        self.meta.get(k).and_then(Value::as_str)
    }
}

/// Parse native tasks from a `.jsonl` / `.json` text. `suite` fills an empty `suite` field.
pub fn parse_tasks(text: &str, suite: &str) -> Result<Vec<Task>, String> {
    let t = text.trim_start();
    let mut tasks: Vec<Task> = if t.starts_with('[') {
        serde_json::from_str(t).map_err(|e| format!("task array: {e}"))?
    } else {
        let mut v = vec![];
        for (n, line) in text.lines().enumerate() {
            let l = line.trim();
            if l.is_empty() || l.starts_with("//") {
                continue;
            }
            v.push(serde_json::from_str::<Task>(l).map_err(|e| format!("line {}: {e}", n + 1))?);
        }
        v
    };
    for t in &mut tasks {
        if t.suite.is_empty() {
            t.suite = suite.to_string();
        }
        if t.id.trim().is_empty() {
            return Err("a task has an empty id".into());
        }
        for p in t.files.keys() {
            safe_rel(p)?;
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for t in &tasks {
        if !seen.insert(t.id.clone()) {
            return Err(format!("duplicate task id `{}`", t.id));
        }
    }
    Ok(tasks)
}

/// Native tasks from a file, or every `*.jsonl` / `*.json` in a directory (sorted).
pub fn load_native(path: &Path) -> Result<Vec<Task>, String> {
    let suite = path.file_stem().and_then(|s| s.to_str()).unwrap_or("tasks").to_string();
    if path.is_dir() {
        let mut files: Vec<PathBuf> = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?.flatten().map(|e| e.path()).filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("jsonl" | "json"))).collect();
        files.sort();
        let mut out = vec![];
        for f in files {
            let sub = f.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
            let mut v = parse_tasks(&std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?, &format!("{suite}/{sub}")).map_err(|e| format!("{}: {e}", f.display()))?;
            out.append(&mut v);
        }
        return Ok(out);
    }
    parse_tasks(&std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?, &suite).map_err(|e| format!("{}: {e}", path.display()))
}

/// A relative path that stays inside its root.
pub fn safe_rel(p: &str) -> Result<&str, String> {
    let path = Path::new(p);
    if p.is_empty() || path.is_absolute() || path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        return Err(format!("task file path `{p}` must be relative and stay inside the work directory"));
    }
    Ok(p)
}

/// `<share>/evals` (the built-in suites, agent command templates, Bot Desktop image).
pub fn share_evals() -> Option<PathBuf> {
    seagent_core::share::share_path("evals")
}

/// File-system friendly form of an id or label.
pub fn slug(s: &str) -> String {
    let v: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' { c } else { '_' }).collect();
    v.trim_matches('_').chars().take(80).collect()
}

#[cfg(test)]
pub(crate) fn repo_share() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../share")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_tasks_parse_validate_and_default_suite() {
        let t = parse_tasks("{\"id\":\"a\",\"prompt\":\"p\",\"checks\":[{\"type\":\"exact\",\"expected\":\"4\"}]}\n\n// note\n{\"id\":\"b\",\"kind\":\"agent\",\"prompt\":\"q\",\"files\":{\"x/y.txt\":\"hi\"}}\n", "s").unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!((t[0].suite.as_str(), t[0].kind, t[1].kind), ("s", Kind::Chat, Kind::Agent));
        assert_eq!(t[0].checks[0].kind(), "exact");
        assert!(parse_tasks("{\"id\":\"a\",\"prompt\":\"p\",\"files\":{\"../x\":\"\"}}", "s").unwrap_err().contains("relative"));
        assert!(parse_tasks("{\"id\":\"a\",\"prompt\":\"p\"}\n{\"id\":\"a\",\"prompt\":\"p\"}", "s").unwrap_err().contains("duplicate"));
        assert!(parse_tasks("[{\"id\":\"z\",\"prompt\":\"p\"}]", "s").unwrap().len() == 1);
    }

    #[test]
    fn shipped_suites_all_parse() {
        let root = repo_share().join("evals");
        for d in ["smoke", "devops-incidents", "roles"] {
            let t = load_native(&root.join(d)).unwrap_or_else(|e| panic!("{d}: {e}"));
            assert!(!t.is_empty(), "{d}");
        }
        // five presets × five scenario questions, every one with judge points
        let roles = load_native(&root.join("roles")).unwrap();
        assert_eq!(roles.len(), 25);
        for p in ["devops", "swdev", "secops", "data", "itsupport"] {
            assert_eq!(roles.iter().filter(|t| t.role.as_deref() == Some(p)).count(), 5, "{p}");
        }
        for t in &roles {
            assert!(t.checks.iter().any(|c| matches!(c, Check::Judge { points, .. } if points.len() >= 3 && points.iter().all(|p| !p.keywords.is_empty()))), "{}", t.id);
            assert!(t.prompt.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c)), "{} is not in Chinese", t.id);
        }
    }
}
