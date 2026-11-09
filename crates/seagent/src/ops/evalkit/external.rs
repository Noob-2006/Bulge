//! Other agents side by side (pro-008): Claude Code, Codex, OpenCode… run as **external
//! commands**. seagent does not embed or drive them; it writes the exact command line for each
//! attempt (`external/commands.sh`, one line per attempt, run in that attempt's prepared
//! working directory), and collects what they print. With `--exec-external` the runner starts
//! them itself (timeout, own process group, killed on overrun); without it the attempts stay
//! `pending` until `seagent evals collect DIR` reads the output files the commands wrote.
//!
//! Templates live in `<share>/evals/agents.toml` (or `--agents-file`): `{prompt}`, `{model}`
//! and `{workdir}` are substituted per argument, so prompts never pass through a shell.

use super::bench::shell_quote;
use super::run::{Outcome, Runner};
use super::{slug, Task};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSpec {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub bin: String,
    pub args: Vec<String>,
    /// Added when a model is chosen (`{model}` substituted).
    #[serde(default)]
    pub model_args: Vec<String>,
    /// How stdout is read: `json` (one document), `jsonl` (event stream) or `text`.
    #[serde(default = "text")]
    pub output: String,
    #[serde(default)]
    pub install: String,
    #[serde(default)]
    pub notes: String,
}

fn text() -> String {
    "text".into()
}

#[derive(Deserialize)]
struct File {
    agent: Vec<AgentSpec>,
}

pub fn load_specs(path: Option<&Path>) -> Result<Vec<AgentSpec>, String> {
    let p = match path {
        Some(p) => p.to_path_buf(),
        None => super::share_evals().map(|d| d.join("agents.toml")).ok_or("no <share>/evals/agents.toml (pass --agents-file)")?,
    };
    let f: File = toml::from_str(&std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?).map_err(|e| format!("{}: {e}", p.display()))?;
    Ok(f.agent)
}

/// `id` or `id=model`.
pub fn pick(specs: &[AgentSpec], word: &str) -> Result<(AgentSpec, Option<String>), String> {
    let (id, model) = match word.split_once('=') {
        Some((i, m)) => (i, Some(m.to_string())),
        None => (word, None),
    };
    let s = specs.iter().find(|s| s.id == id).cloned().ok_or_else(|| format!("unknown external agent `{id}` ({})", specs.iter().map(|s| s.id.as_str()).collect::<Vec<_>>().join(", ")))?;
    Ok((s, model))
}

/// argv for one attempt.
pub fn argv(spec: &AgentSpec, prompt: &str, model: Option<&str>, workdir: &Path) -> Vec<String> {
    let sub = |a: &str| a.replace("{prompt}", prompt).replace("{model}", model.unwrap_or("")).replace("{workdir}", &workdir.display().to_string());
    let mut v = vec![spec.bin.clone()];
    v.extend(spec.args.iter().map(|a| sub(a)));
    if model.is_some() {
        v.extend(spec.model_args.iter().map(|a| sub(a)));
    }
    v
}

pub fn out_file(r: &Runner, spec: &AgentSpec, t: &Task, rep: u32) -> PathBuf {
    r.out.join("external").join(slug(&spec.id)).join(format!("{}.r{rep}.out", slug(&t.id)))
}

/// Tokens / cost / final text from what an agent printed.
pub fn parse_output(kind: &str, stdout: &str) -> (String, u64, u64, Option<f64>) {
    let mut docs: Vec<Value> = vec![];
    match kind {
        "json" => {
            if let Some(v) = super::grade::extract_json(stdout) {
                docs.push(v);
            }
        }
        "jsonl" => docs.extend(stdout.lines().filter_map(|l| serde_json::from_str::<Value>(l.trim()).ok())),
        _ => {}
    }
    if docs.is_empty() {
        return (stdout.trim().to_string(), 0, 0, None);
    }
    fn walk(v: &Value, f: &mut dyn FnMut(&str, &Value)) {
        match v {
            Value::Object(o) => {
                for (k, x) in o {
                    f(k, x);
                    walk(x, f);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, f)),
            _ => {}
        }
    }
    let (mut i, mut o, mut cost) = (0u64, 0u64, None::<f64>);
    let mut answer = String::new();
    for d in &docs {
        // counters may be cumulative (event streams) or per message: keep the largest seen
        let (mut di, mut dout) = (0u64, 0u64);
        walk(d, &mut |k, x| match k {
            "input_tokens" | "prompt_tokens" => di += x.as_u64().unwrap_or(0),
            "output_tokens" | "completion_tokens" => dout += x.as_u64().unwrap_or(0),
            "total_cost_usd" | "cost_usd" => cost = x.as_f64().or(cost),
            _ => {}
        });
        i = i.max(di);
        o = o.max(dout);
        for k in ["result", "text", "message", "content"] {
            if let Some(s) = d.get(k).and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                answer = s.to_string();
                break;
            }
            if let Some(s) = d.get("item").and_then(|it| it.get(k)).and_then(Value::as_str).filter(|s| !s.trim().is_empty()) {
                answer = s.to_string();
                break;
            }
        }
    }
    if answer.is_empty() {
        answer = stdout.trim().chars().rev().take(4000).collect::<Vec<_>>().into_iter().rev().collect();
    }
    (answer, i, o, cost)
}

fn on_path(bin: &str) -> bool {
    if bin.contains('/') {
        return Path::new(bin).is_file();
    }
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

pub fn attempt(r: &Runner, spec: &AgentSpec, model: Option<&str>, t: &Task, rep: u32, dir: &Path) -> Outcome {
    let argv = argv(spec, &t.prompt, model, dir);
    let out = out_file(r, spec, t, rep);
    if let Some(p) = out.parent() {
        let _ = std::fs::create_dir_all(p);
    }
    let line = format!("(cd {} && {}) > {} 2> {}.err", shell_quote(&dir.display().to_string()), argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" "), shell_quote(&out.display().to_string()), shell_quote(&out.display().to_string()));
    let script = r.out.join("external").join("commands.sh");
    let fresh = !script.exists();
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&script) {
        if fresh {
            let _ = writeln!(f, "#!/bin/sh\n# External agents for this run (seagent evals). Review, then run; afterwards: seagent evals collect {}", shell_quote(&r.out.display().to_string()));
        }
        let _ = writeln!(f, "{line}");
    }
    if !r.exec_external {
        return Outcome { status: Some("pending".into()), artifacts: json!({"command": line, "output": out.display().to_string()}), ..Default::default() };
    }
    if !on_path(&spec.bin) {
        return Outcome { error: Some(format!("`{}` is not installed ({})", spec.bin, spec.install)), ..Default::default() };
    }
    let mut c = seagent_core::platform::layout::program_command(&argv[0]);
    seagent_core::platform::layout::msys_args(&mut c, &argv[1..]);
    c.current_dir(dir);
    match super::run::capture(c, Duration::from_secs(t.timeout_secs.unwrap_or(1800))) {
        Ok((stdout, code)) => {
            let _ = std::fs::write(&out, &stdout);
            outcome_from(spec, &stdout, code)
        }
        Err(e) => Outcome { error: Some(e), ..Default::default() },
    }
}

pub fn outcome_from(spec: &AgentSpec, stdout: &str, code: i32) -> Outcome {
    let (answer, i, o, cost) = parse_output(&spec.output, stdout);
    Outcome {
        answer,
        usage: seagent_core::Usage { input_tokens: i, output_tokens: o, ..Default::default() },
        calls: 1,
        error: (code != 0).then(|| format!("{} exited {code}", spec.bin)),
        artifacts: json!({"reported_cost_usd": cost, "exit": code}),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_templates_parse_and_substitute_without_a_shell() {
        let specs = load_specs(Some(&super::super::repo_share().join("evals/agents.toml"))).unwrap();
        for id in ["claude-code", "codex", "opencode"] {
            let (s, _) = pick(&specs, id).unwrap();
            assert!(!s.install.is_empty(), "{id}");
            let v = argv(&s, "fix 'it'; rm -rf /", Some("m1"), Path::new("/w"));
            assert!(v.contains(&"fix 'it'; rm -rf /".to_string()), "{id}: {v:?}");
            assert!(v.iter().any(|a| a.contains("m1")), "{id}");
        }
        assert!(pick(&specs, "nope").is_err());
        assert_eq!(pick(&specs, "codex=o4").unwrap().1.as_deref(), Some("o4"));
    }

    #[test]
    fn outputs_of_the_three_shapes_are_read() {
        let (a, i, o, c) = parse_output("json", "{\"type\":\"result\",\"result\":\"FINAL ANSWER: 4\",\"total_cost_usd\":0.012,\"usage\":{\"input_tokens\":100,\"output_tokens\":20}}");
        assert_eq!((a.as_str(), i, o, c), ("FINAL ANSWER: 4", 100, 20, Some(0.012)));
        let (a, i, o, _) = parse_output("jsonl", "{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\",\"text\":\"done\"}}\n{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":50,\"output_tokens\":7}}\n");
        assert_eq!((a.as_str(), i, o), ("done", 50, 7));
        assert_eq!(parse_output("text", " plain\n").0, "plain");
    }
}
