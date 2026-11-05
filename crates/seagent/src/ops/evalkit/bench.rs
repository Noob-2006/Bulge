//! Standard benchmarks as task sources: SWE-bench Lite/Verified, Terminal-Bench, GAIA, OSWorld.
//!
//! Every adapter reads a **local** copy (`seagent evals fetch <bench> --to DIR` makes one, or point
//! at any existing checkout/download), so runs work offline once the data is there. A suite is
//! named `<kind>:<path>[#key=value&…]`:
//!
//! | spec | reads | options |
//! |------|-------|---------|
//! | `swe-lite:P`, `swe-verified:P` | JSONL / JSON array / a dir of HF datasets-server pages | `ids=a,b` |
//! | `tbench:P` | a Terminal-Bench checkout (or its `tasks/`) | `category=…`, `tag=…`, `ids=…` |
//! | `gaia:P` | a GAIA download (`metadata.jsonl` under P) | `level=1`, `split=validation` |
//! | `osworld:P` | an OSWorld checkout (or `evaluation_examples/`) | `domain=os`, `index=test_small.json` |
//! | `builtin:NAME` | `<share>/evals/NAME` | |
//! | any other path | native tasks ([`super::load_native`]) | |
//!
//! Scoring: SWE-bench attempts produce `predictions-<subject>.jsonl` for the official harness
//! (`swebench.harness.run_evaluation`, Docker) and stay `pending` until `seagent evals swe-score`
//! imports its report; Terminal-Bench runs the task's own `run-tests.sh` inside the task
//! container; GAIA uses its quasi-exact match (validation) or writes a leaderboard submission
//! (test); OSWorld runs inside a Bot Desktop container and scores the evaluator functions it
//! can compute (`exact_match`, `check_include_exclude` over a command or a file) — others are
//! reported as unsupported, never guessed.

use super::grade::CheckResult;
use super::run::{Outcome, Runner, Subject};
use super::{slug, Check, Kind, Task};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Options that shape how benchmark rows become tasks.
#[derive(Debug, Clone, Default)]
pub struct LoadOpts {
    /// SWE-bench: run inside the per-instance images instead of cloning on the host.
    pub swe_images: bool,
    /// SWE-bench: directory of bare mirrors `<owner>__<repo>.git` to clone from offline.
    pub repos: Option<PathBuf>,
    /// OSWorld: the Bot Desktop image.
    pub desktop_image: Option<String>,
}

pub const DESKTOP_IMAGE: &str = "localhost/seagent-bot-desktop:latest";

fn opts_of(spec: &str) -> (&str, BTreeMap<String, String>) {
    match spec.split_once('#') {
        None => (spec, BTreeMap::new()),
        Some((p, q)) => (p, q.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect()),
    }
}

fn ids_filter(o: &BTreeMap<String, String>) -> Option<Vec<String>> {
    o.get("ids").map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
}

/// Load a suite spec into tasks.
pub fn load_suite(spec: &str, lo: &LoadOpts) -> Result<Vec<Task>, String> {
    let (kind, rest) = match spec.split_once(':') {
        Some((k, r)) if ["swe-lite", "swe-verified", "tbench", "gaia", "osworld", "builtin"].contains(&k) => (k, r),
        _ => ("native", spec),
    };
    let (path, o) = opts_of(rest);
    let p = PathBuf::from(path);
    match kind {
        "builtin" => {
            let root = super::share_evals().ok_or("no <share>/evals directory found (set SEAGENT_SHARE_DIR)")?;
            super::load_native(&root.join(super::safe_rel(path)?))
        }
        "swe-lite" | "swe-verified" => load_swe(&p, kind, &o, lo),
        "tbench" => load_tbench(&p, &o),
        "gaia" => load_gaia(&p, &o),
        "osworld" => load_osworld(&p, &o, lo),
        _ => super::load_native(&p),
    }
}

// ───────────────────────── fetch ─────────────────────────

/// (id, description, commands writing into `$DEST`, note).
pub const SOURCES: &[(&str, &str, &[&str], &str)] = &[
    (
        "swe-lite",
        "SWE-bench Lite (300 test instances, princeton-nlp/SWE-bench_Lite)",
        &["mkdir -p \"$DEST\"", "for o in 0 100 200; do curl -fsSL \"https://datasets-server.huggingface.co/rows?dataset=princeton-nlp%2FSWE-bench_Lite&config=default&split=test&offset=$o&length=100\" -o \"$DEST/page-$o.json\"; done"],
        "public; scoring also needs `pip install swebench` and Docker/Podman for the official harness",
    ),
    (
        "swe-verified",
        "SWE-bench Verified (500 test instances, princeton-nlp/SWE-bench_Verified)",
        &["mkdir -p \"$DEST\"", "for o in 0 100 200 300 400; do curl -fsSL \"https://datasets-server.huggingface.co/rows?dataset=princeton-nlp%2FSWE-bench_Verified&config=default&split=test&offset=$o&length=100\" -o \"$DEST/page-$o.json\"; done"],
        "public; same harness as Lite",
    ),
    ("tbench", "Terminal-Bench tasks (laude-institute/terminal-bench)", &["git clone --depth 1 https://github.com/laude-institute/terminal-bench \"$DEST\""], "each task builds its own container image"),
    (
        "gaia",
        "GAIA (gaia-benchmark/GAIA, gated: accept the terms on Hugging Face and export HF_TOKEN)",
        &["huggingface-cli download gaia-benchmark/GAIA --repo-type dataset --local-dir \"$DEST\""],
        "the test split has no public answers: seagent writes a leaderboard submission instead of a score",
    ),
    ("osworld", "OSWorld task definitions (xlang-ai/OSWorld evaluation_examples)", &["git clone --depth 1 https://github.com/xlang-ai/OSWorld \"$DEST\""], "tasks run in the Bot Desktop container (share/evals/osworld/Containerfile)"),
];

/// The commands that fetch `bench` into `dest` (shell, `$DEST` bound).
pub fn fetch_commands(bench: &str, dest: &Path) -> Result<Vec<String>, String> {
    let s = SOURCES.iter().find(|s| s.0 == bench).ok_or_else(|| format!("unknown benchmark `{bench}` ({})", SOURCES.iter().map(|s| s.0).collect::<Vec<_>>().join(", ")))?;
    let d = shell_quote(&dest.display().to_string());
    Ok(s.2.iter().map(|c| format!("DEST={d}; {c}")).collect())
}

pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:,@+".contains(c)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ───────────────────────── SWE-bench ─────────────────────────

pub const SWE_PROMPT: &str = "You are working in a checkout of the repository {repo} at commit {base}. Resolve the issue below by editing the source code. Do not modify or add tests unless the issue requires it; the change will be checked by the project's own test-suite. When you are done, reply with a one-paragraph summary of the change.\n\n<issue>\n{issue}\n</issue>";

fn read_rows(p: &Path) -> Result<Vec<Value>, String> {
    let mut rows = vec![];
    let files: Vec<PathBuf> = if p.is_dir() {
        let mut v: Vec<PathBuf> = std::fs::read_dir(p).map_err(|e| format!("{}: {e}", p.display()))?.flatten().map(|e| e.path()).filter(|f| matches!(f.extension().and_then(|e| e.to_str()), Some("json" | "jsonl"))).collect();
        v.sort_by_key(|f| {
            // page-100.json after page-0.json
            let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            (stem.trim_start_matches(|c: char| !c.is_ascii_digit()).parse::<u64>().unwrap_or(0), stem.to_string())
        });
        v
    } else {
        vec![p.to_path_buf()]
    };
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        let t = text.trim_start();
        if t.starts_with('{') && !t.contains("}\n{") && serde_json::from_str::<Value>(t).is_ok() {
            let v: Value = serde_json::from_str(t).unwrap_or(Value::Null);
            if let Some(r) = v["rows"].as_array() {
                // HF datasets-server page
                rows.extend(r.iter().map(|x| x.get("row").cloned().unwrap_or_else(|| x.clone())));
            } else {
                rows.push(v);
            }
        } else if t.starts_with('[') {
            rows.extend(serde_json::from_str::<Vec<Value>>(t).map_err(|e| format!("{}: {e}", f.display()))?);
        } else {
            for (i, l) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
                rows.push(serde_json::from_str(l).map_err(|e| format!("{}:{}: {e}", f.display(), i + 1))?);
            }
        }
    }
    Ok(rows)
}

/// The official per-instance image name.
pub fn swe_image(instance: &str) -> String {
    format!("docker.io/swebench/sweb.eval.x86_64.{}:latest", instance.replace("__", "_1776_").to_lowercase())
}

fn load_swe(p: &Path, kind: &str, o: &BTreeMap<String, String>, lo: &LoadOpts) -> Result<Vec<Task>, String> {
    let dataset = if kind == "swe-lite" { "princeton-nlp/SWE-bench_Lite" } else { "princeton-nlp/SWE-bench_Verified" };
    let only = ids_filter(o);
    let mut out = vec![];
    for r in read_rows(p)? {
        let id = r["instance_id"].as_str().ok_or("SWE-bench row without instance_id")?.to_string();
        if only.as_ref().is_some_and(|v| !v.contains(&id)) {
            continue;
        }
        let repo = r["repo"].as_str().unwrap_or("").to_string();
        let base = r["base_commit"].as_str().unwrap_or("").to_string();
        let prompt = SWE_PROMPT.replace("{repo}", &repo).replace("{base}", &base).replace("{issue}", r["problem_statement"].as_str().unwrap_or(""));
        let mut t = Task { id: id.clone(), suite: kind.into(), kind: Kind::Agent, prompt, timeout_secs: Some(3600), ..Default::default() };
        if lo.swe_images {
            t.image = Some(swe_image(&id));
        } else {
            let src = match &lo.repos {
                Some(d) => d.join(format!("{}.git", repo.replace('/', "__"))).display().to_string(),
                None => format!("https://github.com/{repo}.git"),
            };
            t.setup = vec![format!("git clone --quiet {} . && git checkout --quiet {}", shell_quote(&src), shell_quote(&base))];
        }
        t.meta = json!({
            "swe": true, "official": "swebench", "dataset": dataset, "repo": repo, "base_commit": base,
            "container_workdir": "/testbed", "FAIL_TO_PASS": r["FAIL_TO_PASS"], "PASS_TO_PASS": r["PASS_TO_PASS"], "version": r["version"],
        });
        out.push(t);
    }
    Ok(out)
}

// ───────────────────────── Terminal-Bench ─────────────────────────

/// Top-level `key:` values of a task.yaml (scalars, quoted strings, `|`/`>` blocks, `- item`
/// lists). Enough for Terminal-Bench's flat task files; not a general YAML parser.
pub fn yaml_top(text: &str) -> BTreeMap<String, Value> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = BTreeMap::new();
    let mut i = 0;
    while i < lines.len() {
        let l = lines[i];
        i += 1;
        if l.starts_with([' ', '\t', '#', '-']) || l.trim().is_empty() {
            continue;
        }
        let Some((k, v)) = l.split_once(':') else { continue };
        let v = v.trim();
        let block: Vec<&str> = {
            let mut b = vec![];
            while i < lines.len() && (lines[i].starts_with([' ', '\t']) || lines[i].trim().is_empty()) {
                b.push(lines[i]);
                i += 1;
            }
            while b.last().is_some_and(|x| x.trim().is_empty()) {
                b.pop();
            }
            b
        };
        let val = if v.starts_with('|') || v.starts_with('>') {
            let indent = block.iter().filter(|x| !x.trim().is_empty()).map(|x| x.len() - x.trim_start().len()).min().unwrap_or(0);
            let body: Vec<String> = block.iter().map(|x| if x.len() >= indent { x[indent..].to_string() } else { String::new() }).collect();
            let s = if v.starts_with('>') { body.join(" ") } else { body.join("\n") };
            json!(if v.ends_with('-') { s } else { s + "\n" })
        } else if v.is_empty() && block.iter().any(|x| x.trim_start().starts_with("- ")) {
            json!(block.iter().filter_map(|x| x.trim_start().strip_prefix("- ")).map(|x| x.trim().trim_matches(['"', '\'']).to_string()).collect::<Vec<_>>())
        } else if (v.starts_with('"') && v.ends_with('"') && v.len() >= 2) || (v.starts_with('\'') && v.ends_with('\'') && v.len() >= 2) {
            json!(v[1..v.len() - 1].replace("\\n", "\n"))
        } else if let Some(list) = v.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            json!(list.split(',').map(|x| x.trim().trim_matches(['"', '\'']).to_string()).filter(|x| !x.is_empty()).collect::<Vec<_>>())
        } else {
            json!(v)
        };
        out.insert(k.trim().to_string(), val);
    }
    out
}

fn compose_services(text: &str) -> usize {
    let mut on = false;
    let mut n = 0;
    for l in text.lines() {
        if !l.starts_with([' ', '\t']) && !l.trim().is_empty() {
            on = l.trim_end() == "services:";
            continue;
        }
        if on && l.starts_with("  ") && !l.starts_with("   ") && l.trim_end().ends_with(':') {
            n += 1;
        }
    }
    n
}

fn load_tbench(p: &Path, o: &BTreeMap<String, String>) -> Result<Vec<Task>, String> {
    let root = if p.join("tasks").is_dir() { p.join("tasks") } else { p.to_path_buf() };
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(&root).map_err(|e| format!("{}: {e}", root.display()))?.flatten().map(|e| e.path()).filter(|d| d.join("task.yaml").is_file()).collect();
    dirs.sort();
    let only = ids_filter(o);
    let mut out = vec![];
    for d in dirs {
        let name = d.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        if only.as_ref().is_some_and(|v| !v.contains(&name)) {
            continue;
        }
        let y = yaml_top(&std::fs::read_to_string(d.join("task.yaml")).map_err(|e| e.to_string())?);
        let category = y.get("category").and_then(Value::as_str).unwrap_or("").to_string();
        let tags: Vec<String> = y.get("tags").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
        if o.get("category").is_some_and(|c| c != &category) || o.get("tag").is_some_and(|t| !tags.contains(t)) {
            continue;
        }
        let instruction = y.get("instruction").and_then(Value::as_str).or_else(|| y.get("descriptions").and_then(Value::as_str)).unwrap_or("").trim().to_string();
        let dockerfile = std::fs::read_to_string(d.join("Dockerfile")).unwrap_or_default();
        let workdir = dockerfile.lines().rev().find_map(|l| l.trim().strip_prefix("WORKDIR ")).unwrap_or("/app").trim().to_string();
        let image = format!("localhost/seagent-tbench-{}:latest", slug(&name).to_lowercase());
        let mut meta = json!({"tbench_dir": d.display().to_string(), "category": category, "tags": tags, "container_workdir": workdir});
        if let Ok(c) = std::fs::read_to_string(d.join("docker-compose.yaml")) {
            if compose_services(&c) > 1 {
                meta["unsupported"] = json!("multi-container docker-compose task (run it with the official `tb run` harness)");
            }
        }
        if dockerfile.is_empty() {
            meta["unsupported"] = json!("task has no Dockerfile");
        }
        out.push(Task {
            id: format!("tb-{name}"),
            suite: "tbench".into(),
            kind: Kind::Agent,
            prompt: instruction,
            setup: vec![format!("{{container}} build -q -t {image} -f {} {}", shell_quote(&d.join("Dockerfile").display().to_string()), shell_quote(&d.display().to_string()))],
            image: Some(image),
            checks: vec![Check::Command { cmd: format!("cd {} && TEST_DIR=/tests bash /tests/run-tests.sh", shell_quote(&workdir)), expect_exit: 0 }],
            timeout_secs: y.get("max_agent_timeout_sec").and_then(|v| v.as_str().and_then(|s| s.parse().ok()).or(v.as_u64())),
            meta,
            ..Default::default()
        });
    }
    Ok(out)
}

/// Terminal-Bench: copy the task's tests into the live container before its checks run.
pub fn before_grade_in_container(t: &Task, bin: &str, cid: &str) {
    let Some(dir) = t.meta_str("tbench_dir") else { return };
    let d = Path::new(dir);
    let cp = |from: &Path, to: &str| {
        let mut c = std::process::Command::new(bin);
        c.args(["cp", &from.display().to_string(), &format!("{cid}:{to}")]);
        let _ = super::run::capture(c, Duration::from_secs(120));
    };
    if d.join("tests").is_dir() {
        cp(&d.join("tests"), "/tests");
    }
    if d.join("run-tests.sh").is_file() {
        cp(&d.join("run-tests.sh"), "/tests/run-tests.sh");
    }
}

// ───────────────────────── GAIA ─────────────────────────

pub const GAIA_PROMPT: &str = "You are a general AI assistant. I will ask you a question. Report your thoughts, and finish your answer with the following template: FINAL ANSWER: [YOUR FINAL ANSWER]. YOUR FINAL ANSWER should be a number OR as few words as possible OR a comma separated list of numbers and/or strings. If you are asked for a number, don't use comma to write your number neither use units such as $ or percent sign unless specified otherwise. If you are asked for a string, don't use articles, neither abbreviations (e.g. for cities), and write the digits in plain text unless specified otherwise. If you are asked for a comma separated list, apply the above rules depending of whether the element to be put in the list is a number or a string.\n\n";

fn find_metadata(p: &Path, split: &str) -> Option<PathBuf> {
    if p.is_file() {
        return Some(p.to_path_buf());
    }
    [p.join("metadata.jsonl"), p.join(split).join("metadata.jsonl"), p.join("2023").join(split).join("metadata.jsonl")].into_iter().find(|c| c.is_file())
}

fn load_gaia(p: &Path, o: &BTreeMap<String, String>) -> Result<Vec<Task>, String> {
    let split = o.get("split").map(String::as_str).unwrap_or("validation");
    let meta_path = find_metadata(p, split).ok_or_else(|| format!("no GAIA metadata.jsonl under {} (split {split})", p.display()))?;
    let base = meta_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let mut out = vec![];
    for r in read_rows(&meta_path)? {
        let level = r["Level"].as_u64().map(|l| l.to_string()).or_else(|| r["Level"].as_str().map(String::from)).unwrap_or_default();
        if o.get("level").is_some_and(|l| l != &level) {
            continue;
        }
        let id = r["task_id"].as_str().ok_or("GAIA row without task_id")?.to_string();
        let answer = r["Final answer"].as_str().unwrap_or("?").to_string();
        let file = r["file_name"].as_str().unwrap_or("").to_string();
        let mut prompt = format!("{GAIA_PROMPT}{}", r["Question"].as_str().unwrap_or(""));
        let mut setup = vec![];
        if !file.is_empty() {
            prompt.push_str(&format!("\n\nThe attached file is ./{file} in the current directory."));
            setup.push(format!("cp {} .", shell_quote(&base.join(&file).display().to_string())));
        }
        let scored = answer != "?" && !answer.is_empty();
        out.push(Task {
            id: format!("gaia-{id}"),
            suite: format!("gaia-l{level}"),
            kind: Kind::Agent,
            prompt,
            setup,
            checks: if scored { vec![Check::Exact { expected: answer, normalize: Some("gaia".into()) }] } else { vec![] },
            meta: json!({"gaia_task_id": id, "level": level, "official": if scored { Value::Null } else { json!("gaia-leaderboard") }}),
            ..Default::default()
        });
    }
    Ok(out)
}

// ───────────────────────── OSWorld ─────────────────────────

const OS_SUPPORTED_FUNCS: &[&str] = &["exact_match", "check_include_exclude"];
const OS_SUPPORTED_CONFIG: &[&str] = &["execute", "command", "launch", "sleep", "open", "download", "activate_window"];

fn osworld_unsupported(ex: &Value) -> Option<String> {
    let funcs: Vec<Value> = match &ex["evaluator"]["func"] {
        Value::Array(a) => a.clone(),
        v => vec![v.clone()],
    };
    let results: Vec<Value> = match &ex["evaluator"]["result"] {
        Value::Array(a) => a.clone(),
        v => vec![v.clone()],
    };
    for f in &funcs {
        let f = f.as_str().unwrap_or("");
        if !OS_SUPPORTED_FUNCS.contains(&f) {
            return Some(format!("evaluator `{f}` is not computed by seagent (supported: {})", OS_SUPPORTED_FUNCS.join(", ")));
        }
    }
    for r in &results {
        let ty = r["type"].as_str().unwrap_or("");
        if !["vm_command_line", "vm_file"].contains(&ty) {
            return Some(format!("evaluator result type `{ty}` is not supported (vm_command_line, vm_file)"));
        }
    }
    for c in ex["config"].as_array().cloned().unwrap_or_default() {
        let ty = c["type"].as_str().unwrap_or("");
        if !OS_SUPPORTED_CONFIG.contains(&ty) {
            return Some(format!("setup step `{ty}` is not supported"));
        }
    }
    None
}

fn load_osworld(p: &Path, o: &BTreeMap<String, String>, lo: &LoadOpts) -> Result<Vec<Task>, String> {
    let root = if p.join("evaluation_examples").is_dir() { p.join("evaluation_examples") } else { p.to_path_buf() };
    let index_name = o.get("index").map(String::as_str).unwrap_or("test_all.json");
    let index: Value = serde_json::from_str(&std::fs::read_to_string(root.join(index_name)).map_err(|e| format!("{}: {e}", root.join(index_name).display()))?).map_err(|e| e.to_string())?;
    let only = ids_filter(o);
    let mut out = vec![];
    for (domain, ids) in index.as_object().cloned().unwrap_or_default() {
        if o.get("domain").is_some_and(|d| d != &domain) {
            continue;
        }
        for id in ids.as_array().cloned().unwrap_or_default().iter().filter_map(Value::as_str) {
            if only.as_ref().is_some_and(|v| !v.iter().any(|x| x == id)) {
                continue;
            }
            let f = root.join("examples").join(&domain).join(format!("{id}.json"));
            let ex: Value = serde_json::from_str(&std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?).map_err(|e| format!("{}: {e}", f.display()))?;
            let mut meta = json!({"domain": domain, "config": ex["config"], "evaluator": ex["evaluator"], "osworld_json": f.display().to_string()});
            if let Some(u) = osworld_unsupported(&ex) {
                meta["unsupported"] = json!(u);
            }
            out.push(Task {
                id: format!("os-{domain}-{}", id.chars().take(8).collect::<String>()),
                suite: format!("osworld/{domain}"),
                kind: Kind::Desktop,
                prompt: ex["instruction"].as_str().unwrap_or("").to_string(),
                image: Some(lo.desktop_image.clone().unwrap_or_else(|| DESKTOP_IMAGE.into())),
                meta,
                ..Default::default()
            });
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

/// Removes the desktop container whatever happens.
struct Ctr {
    bin: String,
    name: String,
}

impl Drop for Ctr {
    fn drop(&mut self) {
        let mut c = std::process::Command::new(&self.bin);
        c.args(["rm", "-f", &self.name]);
        let _ = super::run::capture(c, Duration::from_secs(60));
    }
}

impl Ctr {
    fn exec(&self, script: &str, timeout: u64) -> (String, i32) {
        let wrapped = format!("set -a; [ -f /seagent/bot-desktop/env ] && . /seagent/bot-desktop/env; set +a; {script}");
        let mut c = std::process::Command::new(&self.bin);
        c.args(["exec", &self.name, "bash", "-lc", &wrapped]);
        super::run::capture(c, Duration::from_secs(timeout)).unwrap_or_else(|e| (e, -1))
    }
}

fn str_or_join(v: &Value) -> String {
    match v {
        Value::Array(a) => a.iter().map(|x| shell_quote(x.as_str().unwrap_or(""))).collect::<Vec<_>>().join(" "),
        v => v.as_str().unwrap_or("").to_string(),
    }
}

/// One OSWorld task in a fresh Bot Desktop container `seagent-test-eval-osworld-*`.
pub fn osworld_attempt(r: &Runner, s: &Subject, t: &Task, model: &str, dir: &Path) -> Outcome {
    if let Some(u) = t.meta_str("unsupported") {
        return Outcome { status: Some("unsupported".into()), error: Some(u.into()), ..Default::default() };
    }
    let name = format!("seagent-test-eval-osworld-{}-{}", slug(&t.id).to_lowercase(), seagent_kernel::util::random_hex(4));
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "/usr/local/bin/seagent".into());
    let mut run = std::process::Command::new(&r.container_bin);
    run.args(["run", "-d", "--rm", "--name", &name, "-e", "SEAGENT_HOME=/seagent", "-v", &format!("{exe}:/usr/local/bin/seagent:ro")]);
    if let Some(envf) = r.container_env_file.as_deref() {
        run.args(["--env-file", envf]);
    }
    run.args([t.image.as_deref().unwrap_or(DESKTOP_IMAGE), "sleep", "infinity"]);
    match super::run::capture(run, Duration::from_secs(600)) {
        Ok((_, 0)) => {}
        Ok((o, c)) => return Outcome { error: Some(format!("container start failed ({c}): {}", o.trim())), ..Default::default() },
        Err(e) => return Outcome { error: Some(e), ..Default::default() },
    }
    let ctr = Ctr { bin: r.container_bin.clone(), name: name.clone() };
    let (o, c) = ctr.exec("seagent screen start", 180);
    if c != 0 {
        return Outcome { error: Some(format!("Bot Desktop did not start in {name}: {}", o.trim())), ..Default::default() };
    }
    // task setup
    for step in t.meta["config"].as_array().cloned().unwrap_or_default() {
        let p = &step["parameters"];
        let (out, code) = match step["type"].as_str().unwrap_or("") {
            "execute" | "command" => ctr.exec(&str_or_join(&p["command"]), 300),
            "launch" => ctr.exec(&format!("setsid nohup {} >/dev/null 2>&1 &", str_or_join(&p["command"])), 60),
            "sleep" => {
                std::thread::sleep(Duration::from_secs_f64(p["seconds"].as_f64().unwrap_or(1.0).min(60.0)));
                (String::new(), 0)
            }
            "open" => ctr.exec(&format!("setsid nohup xdg-open {} >/dev/null 2>&1 &", shell_quote(p["path"].as_str().unwrap_or(""))), 60),
            "activate_window" => ctr.exec(&format!("wmctrl -a {} || true", shell_quote(p["window_name"].as_str().unwrap_or(""))), 30),
            "download" => {
                let mut res = (String::new(), 0);
                for f in p["files"].as_array().cloned().unwrap_or_default() {
                    let url = f["url"].as_str().unwrap_or("");
                    let dest = f["path"].as_str().unwrap_or("");
                    let base = url.rsplit('/').next().unwrap_or("");
                    let cached = r.cache_dir.as_ref().map(|d| d.join(base)).filter(|p| p.is_file());
                    res = match cached {
                        Some(file) => {
                            let mut c = std::process::Command::new(&r.container_bin);
                            c.args(["cp", &file.display().to_string(), &format!("{name}:{dest}")]);
                            super::run::capture(c, Duration::from_secs(120)).unwrap_or_else(|e| (e, -1))
                        }
                        None if std::env::var_os("SEAGENT_OFFLINE").is_some() => return Outcome { status: Some("unsupported".into()), error: Some(format!("offline and {base} is not in the OSWorld file cache")), ..Default::default() },
                        None => ctr.exec(&format!("curl -fsSL -o {} {}", shell_quote(dest), shell_quote(url)), 600),
                    };
                    if res.1 != 0 {
                        break;
                    }
                }
                res
            }
            o => (format!("unsupported step {o}"), 1),
        };
        if code != 0 {
            return Outcome { error: Some(format!("setup step {} failed: {}", step["type"], out.trim())), ..Default::default() };
        }
    }
    // the agent
    let mut usage = seagent_core::Usage::default();
    let answer = if super::fake::is_fake(model) {
        // the stand-in "acts" by running its scripted commands on the desktop
        for cmd in t.fake.as_ref().map(|f| f.commands.clone()).unwrap_or_default() {
            let _ = ctr.exec(&cmd, 300);
        }
        t.fake.as_ref().map(|f| f.answer.clone()).unwrap_or_default()
    } else {
        let mut c = std::process::Command::new(&r.container_bin);
        c.args(["exec", "-e", "SEAGENT_HOME=/seagent", &name, "seagent", "run", "--yes", "--model", model, "--", &t.prompt]);
        usage.estimated = true;
        match super::run::capture(c, Duration::from_secs(t.timeout_secs.unwrap_or(1800))) {
            Ok((o, _)) => o,
            Err(e) => return Outcome { error: Some(e), ..Default::default() },
        }
    };
    let _ = (s, dir);
    // evaluation
    let ev = &t.meta["evaluator"];
    let funcs: Vec<Value> = match &ev["func"] {
        Value::Array(a) => a.clone(),
        v => vec![v.clone()],
    };
    let pick = |v: &Value, i: usize| match v {
        Value::Array(a) => a.get(i).cloned().unwrap_or(Value::Null),
        v => v.clone(),
    };
    let mut checks = vec![];
    for (i, f) in funcs.iter().enumerate() {
        let f = f.as_str().unwrap_or("");
        let res = pick(&ev["result"], i);
        let exp = pick(&ev["expected"], i);
        let got = match res["type"].as_str().unwrap_or("") {
            "vm_command_line" => ctr.exec(&str_or_join(&res["command"]), 120).0,
            "vm_file" => ctr.exec(&format!("cat {}", shell_quote(res["path"].as_str().unwrap_or(""))), 60).0,
            _ => String::new(),
        };
        let rules = &exp["rules"];
        let pass = match f {
            "exact_match" => got.trim() == rules["expected"].as_str().unwrap_or("").trim(),
            "check_include_exclude" => {
                let inc = rules["include"].as_array().cloned().unwrap_or_default();
                let exc = rules["exclude"].as_array().cloned().unwrap_or_default();
                inc.iter().all(|x| got.contains(x.as_str().unwrap_or("\u{0}"))) && !exc.iter().any(|x| got.contains(x.as_str().unwrap_or("\u{0}")))
            }
            _ => false,
        };
        checks.push(CheckResult { kind: format!("osworld:{f}"), pass, score: if pass { 1.0 } else { 0.0 }, detail: format!("result `{}`", got.trim().chars().take(200).collect::<String>()), judge_usage: None });
    }
    let conj = ev["conj"].as_str().unwrap_or("and");
    let pass = if conj == "or" { checks.iter().any(|c| c.pass) } else { !checks.is_empty() && checks.iter().all(|c| c.pass) };
    let score = if pass { 1.0 } else { 0.0 };
    drop(ctr);
    Outcome { answer, usage, calls: 1, graded: Some((checks, score, pass)), artifacts: json!({"container": name, "graded_in_container": true}), ..Default::default() }
}

// ───────────────────────── after an attempt ─────────────────────────

/// Benchmark work that needs the live attempt (patch extraction for SWE-bench).
pub fn after_attempt(t: &Task, exec: &dyn Fn(&str) -> (String, i32), out: &Path, label: &str) -> Value {
    if t.meta["swe"].as_bool() != Some(true) {
        return Value::Null;
    }
    let base = t.meta_str("base_commit").unwrap_or("HEAD");
    let (patch, code) = exec(&format!("git add -A >/dev/null 2>&1; git -c core.fileMode=false diff --no-color --cached {}", shell_quote(base)));
    if code != 0 {
        return json!({"patch_error": patch.chars().take(400).collect::<String>()});
    }
    let dir = out.join("swe");
    let _ = std::fs::create_dir_all(&dir);
    let preds = dir.join(format!("predictions-{}.jsonl", slug(label)));
    let row = json!({"instance_id": t.id, "model_name_or_path": slug(label), "model_patch": patch});
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&preds) {
        let _ = writeln!(f, "{row}");
    }
    json!({"patch_bytes": patch.len(), "predictions": preds.display().to_string()})
}

/// GAIA test split: keep the answer for a leaderboard submission.
pub fn record_answer(t: &Task, answer: &str, out: &Path, label: &str) {
    if t.meta_str("official") != Some("gaia-leaderboard") {
        return;
    }
    let dir = out.join("gaia");
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join(format!("submission-{}.jsonl", slug(label)))) {
        let _ = writeln!(f, "{}", json!({"task_id": t.meta_str("gaia_task_id").unwrap_or(&t.id), "model_answer": super::grade::final_answer(answer), "reasoning_trace": ""}));
    }
}

/// Scored outside seagent (official SWE-bench harness, GAIA leaderboard).
pub fn needs_official_scoring(t: &Task) -> bool {
    t.meta_str("official").is_some()
}

/// The official SWE-bench harness command for each predictions file of a run.
pub fn swe_commands(out: &Path) -> Vec<String> {
    let dir = out.join("swe");
    let results = std::fs::read_to_string(out.join("results.jsonl")).unwrap_or_default();
    if !results.contains("\"suite\":\"swe-lite\"") && !results.contains("\"suite\":\"swe-verified\"") {
        // patches of local SWE-style tasks are kept, but there is nothing for the official harness
        return vec![];
    }
    let Ok(rd) = std::fs::read_dir(&dir) else { return vec![] };
    let mut files: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("predictions-"))).collect();
    files.sort();
    let mut v = vec![];
    for f in files {
        let first: Value = std::fs::read_to_string(&f).ok().and_then(|t| t.lines().next().and_then(|l| serde_json::from_str(l).ok())).unwrap_or(Value::Null);
        let model = first["model_name_or_path"].as_str().unwrap_or("seagent").to_string();
        let ds = if results.contains("\"suite\":\"swe-verified\"") { "princeton-nlp/SWE-bench_Verified" } else { "princeton-nlp/SWE-bench_Lite" };
        let run_id = format!("seagent-{model}");
        v.push(format!("python -m swebench.harness.run_evaluation --dataset_name {ds} --predictions_path {} --max_workers 4 --run_id {run_id}", shell_quote(&f.display().to_string())));
        v.push(format!("seagent evals swe-score {} --report {model}.{run_id}.json", shell_quote(&out.display().to_string())));
    }
    v
}

/// Import an official SWE-bench report (`resolved_ids`) into a run's pending attempts.
pub fn swe_score(out: &Path, report: &Value) -> Result<(usize, usize), String> {
    let resolved: Vec<&str> = report["resolved_ids"].as_array().ok_or("report has no resolved_ids (is this a swebench run_evaluation report?)")?.iter().filter_map(Value::as_str).collect();
    let path = out.join("results.jsonl");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (mut n, mut ok) = (0, 0);
    let mut rows = vec![];
    for l in text.lines() {
        let mut a: super::run::Attempt = serde_json::from_str(l).map_err(|e| e.to_string())?;
        if a.status == "pending" && a.suite.starts_with("swe-") {
            let pass = resolved.contains(&a.task.as_str());
            a.status = "done".into();
            a.pass = pass;
            a.score = if pass { 1.0 } else { 0.0 };
            a.checks = vec![CheckResult { kind: "swebench".into(), pass, score: a.score, detail: if pass { "resolved".into() } else { "not resolved".into() }, judge_usage: None }];
            n += 1;
            ok += pass as usize;
        }
        rows.push(serde_json::to_string(&a).map_err(|e| e.to_string())?);
    }
    std::fs::write(&path, rows.join("\n") + "\n").map_err(|e| e.to_string())?;
    Ok((n, ok))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(p: &Path, body: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    #[test]
    fn yaml_top_reads_terminal_bench_task_files() {
        let y = yaml_top("instruction: |-\n  Fix the server.\n\n  Then restart it.\nauthor_email: a@b\ncategory: system-administration\ntags:\n  - nginx\n  - \"logs\"\nmax_agent_timeout_sec: 360\nparser_name: pytest\nother: [a, 'b']\n");
        assert_eq!(y["instruction"], "Fix the server.\n\nThen restart it.");
        assert_eq!(y["category"], "system-administration");
        assert_eq!(y["tags"], json!(["nginx", "logs"]));
        assert_eq!(y["max_agent_timeout_sec"], "360");
        assert_eq!(y["other"], json!(["a", "b"]));
        assert_eq!(compose_services("services:\n  client:\n    build: .\n  db:\n    image: x\n"), 2);
    }

    #[test]
    fn adapters_load_local_copies_offline() {
        let d = seagent_core::tmp::scratch("seagent-bench");
        // SWE-bench: a datasets-server page and a JSONL file
        w(&d.join("swe/page-0.json"), &json!({"rows": [{"row": {"instance_id": "astropy__astropy-12907", "repo": "astropy/astropy", "base_commit": "abc", "problem_statement": "bug", "FAIL_TO_PASS": "[\"t1\"]", "PASS_TO_PASS": "[]"}}]}).to_string());
        w(&d.join("swe/page-100.json"), &json!({"rows": [{"row": {"instance_id": "django__django-1", "repo": "django/django", "base_commit": "def", "problem_statement": "p"}}]}).to_string());
        let t = load_suite(&format!("swe-lite:{}", d.join("swe").display()), &LoadOpts::default()).unwrap();
        assert_eq!(t.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), ["astropy__astropy-12907", "django__django-1"]);
        assert!(t[0].setup[0].contains("https://github.com/astropy/astropy.git") && t[0].prompt.contains("<issue>\nbug"));
        assert!(needs_official_scoring(&t[0]));
        let t = load_suite(&format!("swe-verified:{}#ids=django__django-1", d.join("swe").display()), &LoadOpts { swe_images: true, ..Default::default() }).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].image.as_deref(), Some("docker.io/swebench/sweb.eval.x86_64.django_1776_django-1:latest"));
        // Terminal-Bench
        let tb = d.join("tb/tasks");
        w(&tb.join("hello-world/task.yaml"), "instruction: |\n  Create hello.txt containing hi.\ncategory: file-operations\ntags: [easy]\nmax_agent_timeout_sec: 120\n");
        w(&tb.join("hello-world/Dockerfile"), "FROM ubuntu\nWORKDIR /app\n");
        w(&tb.join("hello-world/run-tests.sh"), "test -f hello.txt\n");
        w(&tb.join("two/task.yaml"), "instruction: x\ncategory: system-administration\n");
        w(&tb.join("two/Dockerfile"), "FROM x\n");
        w(&tb.join("two/docker-compose.yaml"), "services:\n  client:\n    build: .\n  db:\n    image: pg\n");
        let t = load_suite(&format!("tbench:{}", d.join("tb").display()), &LoadOpts::default()).unwrap();
        assert_eq!(t.len(), 2);
        assert_eq!((t[0].id.as_str(), t[0].prompt.as_str(), t[0].timeout_secs), ("tb-hello-world", "Create hello.txt containing hi.", Some(120)));
        assert!(t[0].setup[0].starts_with("{container} build -q -t localhost/seagent-tbench-hello-world:latest"));
        assert!(t[1].meta["unsupported"].as_str().unwrap().contains("multi-container"));
        assert_eq!(load_suite(&format!("tbench:{}#category=system-administration", d.join("tb").display()), &LoadOpts::default()).unwrap().len(), 1);
        // GAIA
        w(&d.join("gaia/2023/validation/metadata.jsonl"), "{\"task_id\":\"t1\",\"Question\":\"How many?\",\"Level\":1,\"Final answer\":\"3\",\"file_name\":\"\"}\n{\"task_id\":\"t2\",\"Question\":\"See file\",\"Level\":2,\"Final answer\":\"x\",\"file_name\":\"a.xlsx\"}\n");
        w(&d.join("gaia/2023/test/metadata.jsonl"), "{\"task_id\":\"t9\",\"Question\":\"?\",\"Level\":1,\"Final answer\":\"?\",\"file_name\":\"\"}\n");
        let g = load_suite(&format!("gaia:{}#level=2", d.join("gaia").display()), &LoadOpts::default()).unwrap();
        assert_eq!(g.len(), 1);
        assert!(g[0].setup[0].contains("a.xlsx") && g[0].prompt.contains("FINAL ANSWER"));
        let g = load_suite(&format!("gaia:{}#split=test", d.join("gaia").display()), &LoadOpts::default()).unwrap();
        assert!(g[0].checks.is_empty() && needs_official_scoring(&g[0]));
        // OSWorld
        let os = d.join("osw/evaluation_examples");
        w(&os.join("test_small.json"), "{\"os\": [\"abcd1234-0000\", \"ffff0000-1111\"]}");
        w(&os.join("examples/os/abcd1234-0000.json"), &json!({"id": "abcd1234-0000", "instruction": "Create ~/done", "config": [{"type": "execute", "parameters": {"command": ["mkdir", "-p", "/root"]}}], "evaluator": {"func": "check_include_exclude", "result": {"type": "vm_command_line", "command": "ls ~"}, "expected": {"type": "rule", "rules": {"include": ["done"], "exclude": []}}}}).to_string());
        w(&os.join("examples/os/ffff0000-1111.json"), &json!({"id": "ffff0000-1111", "instruction": "x", "config": [], "evaluator": {"func": "compare_table", "result": {"type": "vm_file"}, "expected": {}}}).to_string());
        let o = load_suite(&format!("osworld:{}#index=test_small.json", d.join("osw").display()), &LoadOpts::default()).unwrap();
        assert_eq!(o.len(), 2);
        assert_eq!((o[0].kind, o[0].image.as_deref()), (Kind::Desktop, Some(DESKTOP_IMAGE)));
        assert!(o[0].meta.get("unsupported").is_none());
        assert!(o[1].meta["unsupported"].as_str().unwrap().contains("compare_table"));
        // fetch is a list of commands into the chosen path; unknown benchmarks are errors
        let c = fetch_commands("swe-lite", Path::new("/data/my sets/swe")).unwrap();
        assert!(c[1].starts_with("DEST='/data/my sets/swe'; for o in") && c[1].contains("SWE-bench_Lite"));
        assert!(fetch_commands("nope", Path::new("/x")).is_err());
    }

    #[test]
    fn swe_patch_predictions_and_official_report_import() {
        let out = seagent_core::tmp::scratch("seagent-swe");
        let repo = out.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        let ex = super::super::grade::host_exec(&repo, 30);
        assert_eq!(ex("git init -q && git -c user.email=a@b -c user.name=a commit -q --allow-empty -m base && echo x > f.py").1, 0);
        let base = ex("git rev-parse HEAD").0.trim().to_string();
        let t = Task { id: "o__r-1".into(), suite: "swe-lite".into(), meta: json!({"swe": true, "official": "swebench", "base_commit": base}), ..Default::default() };
        let art = after_attempt(&t, &ex, &out, "seagent:fake/oracle");
        assert!(art["patch_bytes"].as_u64().unwrap() > 0, "{art}");
        let preds = std::fs::read_to_string(out.join("swe/predictions-seagent_fake_oracle.jsonl")).unwrap();
        assert!(preds.contains("\"instance_id\":\"o__r-1\"") && preds.contains("+x"));
        assert!(swe_commands(&out).is_empty(), "no SWE-bench attempt in the run yet");
        let a = super::super::run::Attempt { subject: "seagent:fake/oracle".into(), task: "o__r-1".into(), suite: "swe-lite".into(), rep: 1, status: "pending".into(), ..Default::default() };
        std::fs::write(out.join("results.jsonl"), serde_json::to_string(&a).unwrap() + "\n").unwrap();
        let cmds = swe_commands(&out);
        assert!(cmds[0].contains("swebench.harness.run_evaluation") && cmds[0].contains("SWE-bench_Lite") && cmds[1].contains("seagent evals swe-score"));
        assert_eq!(swe_score(&out, &json!({"resolved_ids": ["o__r-1"]})).unwrap(), (1, 1));
        let back: super::super::run::Attempt = serde_json::from_str(std::fs::read_to_string(out.join("results.jsonl")).unwrap().trim()).unwrap();
        assert!(back.pass && back.status == "done");
    }

    #[test]
    fn osworld_runs_in_a_named_bot_desktop_container_with_a_fake_runtime() {
        use std::os::unix::fs::PermissionsExt;
        let out = seagent_core::tmp::scratch("seagent-osw");
        let sand = out.join("desk");
        std::fs::create_dir_all(&sand).unwrap();
        let bin = out.join("podman");
        // `exec NAME bash -lc SCRIPT` runs SCRIPT with HOME=sandbox; everything is logged
        std::fs::write(&bin, format!("#!/bin/sh\necho \"$@\" >> {0}/log\ncase \"$1\" in run) echo cid;; exec) shift 3; HOME={1} sh -c \"$2\";; esac\nexit 0\n", out.display(), sand.display())).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut r = Runner::new(&out, seagent_kernel::config::Config::default(), None);
        r.container_bin = bin.display().to_string();
        let ev = json!({"func": "check_include_exclude", "result": {"type": "vm_command_line", "command": "ls ~"}, "expected": {"type": "rule", "rules": {"include": ["done"], "exclude": ["bad"]}}});
        let mut t = Task { id: "os-x".into(), kind: Kind::Desktop, prompt: "make done".into(), image: Some("img".into()), meta: json!({"config": [{"type": "execute", "parameters": {"command": "true"}}], "evaluator": ev}), ..Default::default() };
        t.fake = Some(super::super::FakeScript { commands: vec!["touch ~/done".into()], answer: "ok".into() });
        let a = r.attempt(&Subject::seagent("fake/oracle"), &t, 1);
        assert!(a.pass, "{a:?}");
        let log = std::fs::read_to_string(out.join("log")).unwrap();
        assert!(log.contains("run -d --rm --name seagent-test-eval-osworld-os-x-"), "{log}");
        assert!(log.contains("seagent screen start"));
        assert!(log.lines().last().unwrap().starts_with("rm -f seagent-test-eval-osworld-os-x-"), "{log}");
        // unsupported evaluators are reported, never scored
        t.meta["unsupported"] = json!("evaluator `compare_table` is not computed by seagent");
        let a = r.attempt(&Subject::seagent("fake/oracle"), &t, 1);
        assert_eq!(a.status, "unsupported");
    }
}
