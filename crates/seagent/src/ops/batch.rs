//! Batch data generation (Hermes `batch_runner.py`, `toolset_distributions.py`), plus the
//! `seagent batch swe` (`mini_swe_runner.py`, see [`super::miniswe`]) and `seagent batch compress`
//! (`trajectory_compressor.py`, see [`super::trajcomp`]) entry points.
//!
//! `seagent batch run <dataset.jsonl> --run-name N` runs the agent over every `{"prompt": …}` row:
//! batches of `--batch-size` prompts go to a pool of `--workers` threads; each prompt gets a
//! fresh session whose tools are sampled from a toolset distribution, then its ShareGPT
//! trajectory (system/human/gpt/tool, `<tool_call>`/`<tool_response>`) is appended (fsynced) to
//! `batch_N.jsonl` with per-tool count/success/failure stats. `checkpoint.json` is rewritten
//! after every batch; `--resume` skips prompts already present in batch files (content match).
//! Afterwards every `batch_*.jsonl` is merged into `trajectories.jsonl` (dropping hallucinated
//! tool names, invalid JSON and no-reasoning tombstones) and `statistics.json` is written.
//! Output goes to `data/<run-name>` under the current directory (as upstream) or `--out DIR`.

use crate::args::Args;
use crate::R;
use seagent_kernel::event::EventKind;
use seagent_kernel::kernel::{EndReason, Kernel, RunOpts};
use seagent_kernel::trajectory as tj;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const COMMANDS: &[&str] = &["batch"];
pub const VALUE_FLAGS: &[&str] = &["run-name", "batch-size", "distribution", "workers", "max-turns", "max-samples", "system-prompt", "task", "prompts", "image", "max-iterations", "command-timeout", "target-max-tokens", "summary-target-tokens", "summary-model", "sample-percent", "seed", "protect-last", "concurrency", "compress-config"];
pub const BOOL_FLAGS: &[&str] = &["resume", "dry-run", "keep-unreasoned"];

// ───────────────────────── toolset distributions ─────────────────────────

/// One sampling distribution: (name, description, [(toolset entry, % chance)]). An entry may be a
/// "+"-grouped compound that rolls once for all members.
pub type Distribution = (&'static str, &'static str, &'static [(&'static str, u32)]);

pub const DISTRIBUTIONS: &[Distribution] = &[
    ("default", "All available tools, all the time", &[("web", 100), ("vision", 100), ("image_gen", 100), ("terminal", 100), ("file", 100), ("browser", 100)]),
    ("image_gen", "Heavy focus on image generation with vision and web support", &[("image_gen", 90), ("vision", 90), ("web", 55), ("terminal", 45)]),
    ("research", "Web research with vision analysis and reasoning", &[("web", 90), ("browser", 70), ("vision", 50), ("terminal", 10)]),
    ("science", "Scientific research with web, terminal, file, and browser capabilities", &[("web", 94), ("terminal", 94), ("file", 94), ("vision", 65), ("browser", 50), ("image_gen", 15)]),
    ("development", "Terminal, file tools, and reasoning with occasional web lookup", &[("terminal", 80), ("file", 80), ("web", 30), ("vision", 10)]),
    ("safe", "All tools except terminal for safety", &[("web", 80), ("browser", 70), ("vision", 60), ("image_gen", 60)]),
    ("balanced", "Equal probability of all toolsets", &[("web", 50), ("vision", 50), ("image_gen", 50), ("terminal", 50), ("file", 50), ("browser", 50)]),
    ("minimal", "Only web tools for basic research", &[("web", 100)]),
    ("terminal_only", "Terminal and file tools for code execution tasks", &[("terminal", 100), ("file", 100)]),
    ("terminal_web", "Terminal and file tools with web search for documentation lookup", &[("terminal", 100), ("file", 100), ("web", 100)]),
    ("creative", "Image generation and vision analysis focus", &[("image_gen", 90), ("vision", 90), ("web", 30)]),
    ("reasoning", "Heavy research/reasoning distribution with minimal other tools", &[("web", 90), ("file", 60), ("terminal", 20)]),
    ("browser_use", "Full browser-based web interaction with search, vision, and page control", &[("browser", 100), ("web", 80), ("vision", 70)]),
    ("browser_only", "Only browser automation tools for pure web interaction tasks", &[("browser", 100)]),
    ("browser_tasks", "Browser-focused distribution with web_search for finding URLs (Google blocks direct browser searches)", &[("browser+search", 97), ("vision", 12), ("terminal", 15)]),
    ("terminal_tasks", "Terminal-focused distribution with high terminal/file availability, occasional other tools", &[("terminal", 97), ("file", 97), ("web", 97), ("browser", 75), ("vision", 50), ("image_gen", 10)]),
    ("mixed_tasks", "Mixed distribution with high browser, terminal, and file availability for complex tasks", &[("browser", 92), ("terminal", 92), ("file", 92), ("web", 35), ("vision", 15), ("image_gen", 15)]),
];

/// Hermes toolset names that are not kernel toolsets, mapped to seagent tool names.
const EXTRA_TOOLSETS: &[(&str, &[&str])] = &[
    ("vision", &["vision_analyze"]),
    ("image_gen", &["image_generate"]),
    ("browser", &["browser", "browser_navigate", "browser_snapshot", "browser_click", "browser_type", "browser_scroll", "browser_back", "browser_press", "browser_console", "browser_vision", "browser_dialog"]),
    ("search", &["web_search"]),
];

pub fn toolset_tools(name: &str) -> Option<Vec<String>> {
    seagent_kernel::subagents::TOOLSETS.iter().chain(EXTRA_TOOLSETS).find(|(n, _)| *n == name).map(|(_, t)| t.iter().map(|s| s.to_string()).collect())
}

pub fn distribution(name: &str) -> Option<&'static Distribution> {
    DISTRIBUTIONS.iter().find(|d| d.0 == name)
}

/// Small seedable PRNG (splitmix64) for toolset sampling.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: Option<u64>) -> Rng {
        Rng(seed.unwrap_or_else(|| u64::from_le_bytes(seagent_net::crypto::random_bytes(8).try_into().unwrap_or([7; 8]))))
    }
    pub fn next_f64(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        ((z ^ (z >> 31)) >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Sample toolset names; each entry is included independently with its % chance; a
/// compound entry rolls once. Falls back to the highest-probability entry when nothing rolled.
pub fn sample(name: &str, rng: &mut Rng) -> Result<(Vec<String>, Vec<String>), String> {
    sample_with(name, || rng.next_f64())
}

/// The sampling algorithm with an injectable roll, so the fallback path is testable.
fn sample_with(name: &str, mut roll: impl FnMut() -> f64) -> Result<(Vec<String>, Vec<String>), String> {
    let d = distribution(name).ok_or_else(|| format!("Unknown distribution: {name}"))?;
    let (mut out, mut warn) = (vec![], vec![]);
    for (entry, p) in d.2 {
        let members: Vec<&str> = entry.split('+').map(str::trim).collect();
        let bad: Vec<&str> = members.iter().copied().filter(|m| toolset_tools(m).is_none()).collect();
        if !bad.is_empty() {
            warn.push(format!("Toolset '{}' in distribution '{name}' is not valid", bad.join("+")));
        } else if roll() * 100.0 < *p as f64 {
            out.extend(members.iter().map(|s| s.to_string()));
        }
    }
    if out.is_empty() {
        // Python's max() keeps the first entry on a tie (e.g. terminal_only's 100/100).
        if let Some((e, _)) = d.2.iter().reduce(|a, b| if b.1 > a.1 { b } else { a }) {
            let members: Vec<String> = e.split('+').map(|s| s.trim().to_string()).collect();
            if members.iter().all(|m| toolset_tools(m).is_some()) {
                out = members;
            }
        }
    }
    Ok((out, warn))
}

pub fn distribution_info(name: &str) -> Result<String, String> {
    let d = distribution(name).ok_or_else(|| format!("Unknown distribution: {name}"))?;
    let mut ts: Vec<_> = d.2.to_vec();
    ts.sort_by_key(|x| std::cmp::Reverse(x.1));
    Ok(format!("Distribution: {}\n  Description: {}\n  Toolsets:\n{}", d.0, d.1, ts.iter().map(|(t, p)| format!("    • {t:15} : {p:3}% chance")).collect::<Vec<_>>().join("\n")))
}

// ───────────────────────── stats ─────────────────────────

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ToolStat {
    pub count: u64,
    pub success: u64,
    pub failure: u64,
}

fn stat_json(s: &ToolStat) -> Value {
    json!({"count": s.count, "success": s.success, "failure": s.failure})
}

/// Judge a tool response: JSON with a non-null `error` / `success: false` fails; non-JSON fails
/// only when empty or starting with `Error:`. Non-zero exit codes are not failures.
pub fn tool_call_succeeded(content: &str) -> bool {
    match serde_json::from_str::<Value>(content) {
        Ok(Value::Object(o)) => {
            if o.get("error").is_some_and(|e| !e.is_null()) {
                return false;
            }
            if o.get("content").and_then(|c| c.get("error")).is_some_and(|e| !e.is_null()) {
                return false;
            }
            o.get("success") != Some(&Value::Bool(false))
        }
        Ok(_) => true,
        Err(_) => !content.is_empty() && !content.trim().to_lowercase().starts_with("error:"),
    }
}

pub fn tool_stats(flats: &[tj::Flat]) -> BTreeMap<String, ToolStat> {
    let mut stats: BTreeMap<String, ToolStat> = BTreeMap::new();
    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    for f in flats {
        if f.role == "assistant" {
            for (id, name, _) in &f.tool_calls {
                stats.entry(name.clone()).or_default().count += 1;
                ids.insert(id.clone(), name.clone());
            }
        } else if f.role == "tool" {
            if let Some(n) = ids.get(&f.tool_call_id) {
                let s = stats.entry(n.clone()).or_default();
                if !f.is_error && tool_call_succeeded(&f.content) {
                    s.success += 1;
                } else {
                    s.failure += 1;
                }
            }
        }
    }
    stats
}

/// (total assistant turns, turns with reasoning).
pub fn reasoning_stats(flats: &[tj::Flat]) -> (u64, u64) {
    let a: Vec<_> = flats.iter().filter(|f| f.role == "assistant").collect();
    (a.len() as u64, a.iter().filter(|f| f.content.contains("<REASONING_SCRATCHPAD>") || !f.reasoning.trim().is_empty()).count() as u64)
}

fn normalize(stats: &BTreeMap<String, ToolStat>, all: &BTreeSet<String>) -> (Value, Value) {
    let mut s = serde_json::Map::new();
    let mut e = serde_json::Map::new();
    for t in all.iter().chain(stats.keys()) {
        let st = stats.get(t).copied().unwrap_or_default();
        s.insert(t.clone(), stat_json(&st));
        e.insert(t.clone(), json!(st.failure));
    }
    (Value::Object(s), Value::Object(e))
}

fn now_iso() -> String {
    tj::iso_ms(seagent_kernel::event::now_ms()).trim_end_matches('Z').to_string()
}

/// Human prompt text from a dataset/trajectory entry (flat `prompt`, ShareGPT or chat).
pub fn entry_prompt_text(e: &Value) -> String {
    let t = e.get("prompt").and_then(|p| p.as_str()).unwrap_or("").trim();
    if !t.is_empty() {
        return t.into();
    }
    for key in ["conversations", "messages"] {
        for m in e.get(key).and_then(|v| v.as_array()).into_iter().flatten() {
            let role = m.get("role").or_else(|| m.get("from")).and_then(|r| r.as_str()).unwrap_or("");
            if role == "user" || role == "human" {
                let t = m.get("content").or_else(|| m.get("value")).and_then(|v| v.as_str()).unwrap_or("").trim();
                if !t.is_empty() {
                    return t.into();
                }
            }
        }
    }
    String::new()
}

// ───────────────────────── runner ─────────────────────────

#[derive(Clone)]
pub struct RunCfg {
    pub run_name: String,
    pub distribution: String,
    pub batch_size: usize,
    pub workers: usize,
    pub max_samples: Option<usize>,
    pub model: Option<String>,
    pub seed: Option<u64>,
    /// Keep samples whose assistant turns carry no reasoning (upstream always discards them).
    pub keep_unreasoned: bool,
    pub verbose: bool,
}

pub struct PromptResult {
    pub ok: bool,
    /// Position of the prompt in the input file (kept with the result for callers that merge rows).
    #[allow(dead_code)]
    pub index: usize,
    pub error: Option<String>,
    pub row: Option<Value>,
    pub stats: BTreeMap<String, ToolStat>,
    pub reasoning: (u64, u64),
    /// Whether the sample was dropped for carrying no reasoning (the tombstones are logged directly).
    #[allow(dead_code)]
    pub discarded: bool,
}

fn append_jsonl(p: &Path, row: &Value) -> Result<(), String> {
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    f.write_all((row.to_string() + "\n").as_bytes()).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}

pub fn process_prompt(k: &Kernel, ws: &Path, index: usize, entry: &Value, batch: usize, cfg: &RunCfg, rng: &mut Rng) -> PromptResult {
    let fail = |e: String| PromptResult { ok: false, index, error: Some(e), row: None, stats: BTreeMap::new(), reasoning: (0, 0), discarded: false };
    if let Some(img) = entry.get("image").or_else(|| entry.get("docker_image")).and_then(|v| v.as_str()) {
        // seagent runs batch prompts in the local workspace; a row that asks for a container must not
        // silently run on the host.
        return fail(format!("per-prompt container image {img} requested, but `seagent batch run` executes locally; use `seagent batch swe --env docker --image {img}`"));
    }
    let prompt = entry.get("prompt").and_then(|p| p.as_str()).unwrap_or("").to_string();
    let (sets, warn) = match sample(&cfg.distribution, rng) {
        Ok(x) => x,
        Err(e) => return fail(e),
    };
    for w in warn {
        eprintln!("warning: {w}");
    }
    let allow: Vec<String> = sets.iter().flat_map(|s| toolset_tools(s).unwrap_or_default()).collect();
    let ws = entry.get("cwd").and_then(|c| c.as_str()).map(PathBuf::from).unwrap_or_else(|| ws.to_path_buf());
    let run = || -> Result<PromptResult, String> {
        let id = k.create_session(&ws, cfg.model.as_deref(), None, Some(&format!("batch {} #{index}", cfg.run_name))).map_err(|e| e.to_string())?;
        let res = (|| {
            k.record(&id, EventKind::Tools { allow: Some(allow.clone()), deny: vec![] }).map_err(|e| e.to_string())?;
            // A dataset prompt is the user turn itself; a "batch" source would be prefixed
            // with "[from batch] " and leak that marker into exported training conversations.
            k.submit(&id, &prompt, "user").map_err(|e| e.to_string())?;
            let out = k.run(&id, RunOpts::default()).map_err(|e| e.to_string())?;
            let events = k.store.read(&id).map_err(|e| e.to_string())?;
            let flats = tj::flatten(&events);
            let specs: Vec<_> = k.specs().into_iter().filter(|s| allow.contains(&s.name)).collect();
            let conv = tj::sharegpt(&flats, &tj::tools_for_system_message(&specs));
            let stats = tool_stats(&flats);
            let reasoning = reasoning_stats(&flats);
            let model = seagent_kernel::projection::project(&events).model;
            Ok(PromptResult {
                ok: true,
                index,
                error: None,
                row: Some(json!({
                    "prompt_index": index, "conversations": conv,
                    "metadata": {"batch_num": batch, "timestamp": now_iso(), "model": model},
                    "completed": tj::completed(&events), "partial": matches!(out.reason, EndReason::MaxSteps),
                    "api_calls": reasoning.0, "toolsets_used": sets,
                })),
                stats,
                reasoning,
                discarded: false,
            })
        })();
        let _ = k.store.remove(&id);
        res
    };
    run().unwrap_or_else(fail)
}

pub struct Summary {
    pub processed: usize,
    pub kept: usize,
    pub discarded: usize,
    pub failed: usize,
    pub stats: BTreeMap<String, ToolStat>,
    pub out: PathBuf,
}

pub fn load_dataset(p: &Path) -> Result<Vec<Value>, String> {
    let text = std::fs::read_to_string(p).map_err(|_| format!("Dataset file not found: {}", p.display()))?;
    let mut v = vec![];
    for (n, l) in text.lines().enumerate() {
        let l = l.trim();
        if l.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(l) {
            Ok(e) if e.get("prompt").is_some() => v.push(e),
            Ok(_) => eprintln!("warning: line {} missing 'prompt' field, skipping", n + 1),
            Err(e) => eprintln!("warning: invalid JSON on line {}: {e}", n + 1),
        }
    }
    if v.is_empty() {
        return Err(format!("No valid entries found in dataset file: {}", p.display()));
    }
    Ok(v)
}

fn completed_by_content(out: &Path) -> HashSet<String> {
    let mut done = HashSet::new();
    for f in batch_files(out) {
        for l in std::fs::read_to_string(&f).unwrap_or_default().lines() {
            if let Ok(e) = serde_json::from_str::<Value>(l.trim()) {
                if e.is_object() && e.get("failed") != Some(&Value::Bool(true)) {
                    let t = entry_prompt_text(&e);
                    if !t.is_empty() {
                        done.insert(t);
                    }
                }
            }
        }
    }
    done
}

fn batch_files(out: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(out).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("batch_") && n.ends_with(".jsonl"))).collect();
    v.sort();
    v
}

/// Merge every `batch_*.jsonl` into `trajectories.jsonl`; returns (kept, files).
pub fn combine(out: &Path, all_tools: &BTreeSet<String>) -> Result<(usize, usize), String> {
    let files = batch_files(out);
    let mut body = String::new();
    let mut kept = 0;
    for f in &files {
        for l in std::fs::read_to_string(f).unwrap_or_default().lines() {
            let Ok(d) = serde_json::from_str::<Value>(l) else {
                eprintln!("   filtering invalid JSON entry ({})", f.display());
                continue;
            };
            if !d.is_object() || d.get("discarded").is_some_and(|x| !x.is_null() && x != &Value::Bool(false)) {
                continue;
            }
            if let Some(bad) = d.get("tool_stats").and_then(|t| t.as_object()).and_then(|t| t.keys().find(|k| !all_tools.contains(*k))) {
                eprintln!("   filtering corrupted entry ({}): invalid tool '{}'", f.display(), bad.chars().take(50).collect::<String>());
                continue;
            }
            body.push_str(l);
            body.push('\n');
            kept += 1;
        }
    }
    std::fs::write(out.join("trajectories.jsonl"), body).map_err(|e| e.to_string())?;
    Ok((kept, files.len()))
}

pub fn run_batch(k: &Kernel, ws: &Path, dataset: &Path, out: &Path, cfg: &RunCfg, resume: bool) -> Result<Summary, String> {
    if distribution(&cfg.distribution).is_none() {
        return Err(format!("Unknown distribution: {}. Available: {}", cfg.distribution, DISTRIBUTIONS.iter().map(|d| d.0).collect::<Vec<_>>().join(", ")));
    }
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut data = load_dataset(dataset)?;
    if let Some(m) = cfg.max_samples.filter(|m| *m < data.len()) {
        eprintln!("truncated dataset from {} to {m} samples (--max-samples)", data.len());
        data.truncate(m);
    }
    let mut todo: Vec<(usize, Value)> = data.iter().cloned().enumerate().collect();
    if resume {
        let done = completed_by_content(out);
        let before = todo.len();
        todo.retain(|(_, e)| !done.contains(&entry_prompt_text(e)));
        eprintln!("resume: {} already completed, {} to run", before - todo.len(), todo.len());
    }
    let ck_path = out.join("checkpoint.json");
    let mut ck: Value = std::fs::read_to_string(&ck_path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    if ck.get("run_name").and_then(|r| r.as_str()) != Some(&cfg.run_name) {
        ck = json!({"run_name": cfg.run_name, "completed_prompts": [], "batch_stats": {}, "last_updated": null});
    }
    let done_idx: BTreeSet<usize> = ck["completed_prompts"].as_array().map(|a| a.iter().filter_map(|x| x.as_u64().map(|v| v as usize)).collect()).unwrap_or_default();
    let batches: Vec<(usize, Vec<(usize, Value)>)> = todo.chunks(cfg.batch_size.max(1)).map(|c| c.to_vec()).enumerate().collect();
    let total_batches = batches.len();
    let all_tools: BTreeSet<String> = k.specs().into_iter().map(|s| s.name).collect();
    let queue = Arc::new(Mutex::new(batches));
    let shared = Arc::new(Mutex::new((ck, done_idx, BTreeMap::<String, ToolStat>::new(), (0u64, 0u64), [0usize; 3])));
    let start = std::time::Instant::now();
    std::thread::scope(|s| {
        for w in 0..cfg.workers.max(1) {
            let (queue, shared, all_tools, ck_path) = (queue.clone(), shared.clone(), &all_tools, &ck_path);
            let mut rng = Rng::new(cfg.seed.map(|x| x.wrapping_add(w as u64)));
            s.spawn(move || loop {
                let Some((bn, items)) = queue.lock().unwrap().pop() else { break };
                let file = out.join(format!("batch_{bn}.jsonl"));
                let skip = shared.lock().unwrap().1.clone();
                let (mut processed, mut discarded, mut completed) = (0, 0, vec![]);
                let mut bstats: BTreeMap<String, ToolStat> = BTreeMap::new();
                let mut breason = (0u64, 0u64);
                let mut failed = 0;
                for (idx, e) in items.iter().filter(|(i, _)| !skip.contains(i)) {
                    processed += 1;
                    let r = process_prompt(k, ws, *idx, e, bn, cfg, &mut rng);
                    // Upstream discards a no-reasoning sample *before* merging tool/reasoning
                    // stats (batch_runner.py:337-376), so statistics.json never counts it.
                    let drop_row = r.ok && r.reasoning.1 == 0 && !cfg.keep_unreasoned;
                    if !drop_row {
                        for (t, st) in &r.stats {
                            let a = bstats.entry(t.clone()).or_default();
                            a.count += st.count;
                            a.success += st.success;
                            a.failure += st.failure;
                        }
                        breason.0 += r.reasoning.0;
                        breason.1 += r.reasoning.1;
                    }
                    match r.row {
                        Some(mut row) if r.ok => {
                            if r.reasoning.1 == 0 && !cfg.keep_unreasoned {
                                eprintln!("   prompt {idx} discarded (no reasoning in any turn)");
                                discarded += 1;
                                let _ = append_jsonl(&file, &json!({"prompt_index": idx, "discarded": "no_reasoning", "prompt": entry_prompt_text(e)}));
                            } else {
                                let (st, errs) = normalize(&r.stats, all_tools);
                                row["tool_stats"] = st;
                                row["tool_error_counts"] = errs;
                                if let Err(err) = append_jsonl(&file, &row) {
                                    eprintln!("   prompt {idx}: {err}");
                                    failed += 1;
                                    continue;
                                }
                                if cfg.verbose {
                                    eprintln!("   prompt {idx} completed");
                                }
                            }
                            completed.push(*idx);
                        }
                        _ => {
                            failed += 1;
                            eprintln!("   prompt {idx} failed (will retry on resume): {}", r.error.unwrap_or_default());
                        }
                    }
                }
                let mut g = shared.lock().unwrap();
                g.1.extend(completed.iter().copied());
                for (t, st) in bstats {
                    let a = g.2.entry(t).or_default();
                    a.count += st.count;
                    a.success += st.success;
                    a.failure += st.failure;
                }
                g.3 .0 += breason.0;
                g.3 .1 += breason.1;
                g.4[0] += processed;
                g.4[1] += discarded;
                g.4[2] += failed;
                let sorted: Vec<usize> = g.1.iter().copied().collect();
                g.0["completed_prompts"] = json!(sorted);
                g.0["batch_stats"][bn.to_string()] = json!({"processed": processed, "skipped": items.len() - processed, "discarded_no_reasoning": discarded});
                g.0["last_updated"] = json!(now_iso());
                let _ = seagent_kernel::util::atomic_write(ck_path, serde_json::to_string_pretty(&g.0).unwrap_or_default().as_bytes());
            });
        }
    });
    let (_, _, stats, reason, counts) = Arc::try_unwrap(shared).map_err(|_| "worker still running")?.into_inner().unwrap();
    let (kept, nfiles) = combine(out, &all_tools)?;
    let mut tool_statistics = serde_json::Map::new();
    for (t, s) in &stats {
        let calls = s.success + s.failure;
        let rate = |n: u64| if calls > 0 { (n as f64 / calls as f64 * 10000.0).round() / 100.0 } else { 0.0 };
        tool_statistics.insert(t.clone(), json!({"count": s.count, "success": s.success, "failure": s.failure, "success_rate": rate(s.success), "failure_rate": rate(s.failure)}));
    }
    let final_stats = json!({
        "run_name": cfg.run_name, "distribution": cfg.distribution, "total_prompts": data.len(), "total_batches": total_batches,
        "batch_size": cfg.batch_size, "model": cfg.model.clone().unwrap_or_else(|| k.cfg.model.default.clone()), "completed_at": now_iso(),
        "duration_seconds": (start.elapsed().as_secs_f64() * 100.0).round() / 100.0, "tool_statistics": tool_statistics,
        "reasoning_statistics": {"total_assistant_turns": reason.0, "turns_with_reasoning": reason.1, "turns_without_reasoning": reason.0 - reason.1},
        "discarded_no_reasoning": counts[1],
    });
    std::fs::write(out.join("statistics.json"), serde_json::to_string_pretty(&final_stats).unwrap_or_default()).map_err(|e| e.to_string())?;
    let _ = nfiles;
    Ok(Summary { processed: counts[0], kept, discarded: counts[1], failed: counts[2], stats, out: out.to_path_buf() })
}

fn summary_text(s: &Summary) -> String {
    let mut o = format!("BATCH PROCESSING COMPLETE\n  prompts processed this run: {}\n  trajectories in merged file: {}\n  discarded (no reasoning): {}\n  failed (retry with --resume): {}\n\nTool usage:\n", s.processed, s.kept, s.discarded, s.failed);
    if s.stats.is_empty() {
        o += "  no tool calls were made during this run\n";
    }
    let mut v: Vec<_> = s.stats.iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1.count));
    for (t, st) in v {
        let calls = st.success + st.failure;
        o += &format!("  {t:<25} {:<8} ok {:<6} fail {:<6} {:.1}%\n", st.count, st.success, st.failure, if calls > 0 { st.success as f64 / calls as f64 * 100.0 } else { 0.0 });
    }
    o + &format!("\nResults: {} (trajectories.jsonl, batch_*.jsonl, statistics.json, checkpoint.json)", s.out.display())
}

const USAGE: &str = "usage: seagent batch run <dataset.jsonl> --run-name NAME [--batch-size 10] [--distribution default] [--workers 4] [--max-turns 10] [--max-samples N] [--system-prompt TEXT] [--resume] [--keep-unreasoned] [--out DIR] [-m MODEL] [--yes]
       seagent batch distributions [NAME]
       seagent batch swe (--task TEXT | --prompts FILE) [--out FILE] [--env local|docker] [--image IMG] [--cwd DIR] [--max-iterations 15] [--command-timeout 60] [-m MODEL]
       seagent batch compress <file.jsonl|dir> [--out PATH] [--target-max-tokens 15250] [--summary-target-tokens 750] [--summary-model M] [--protect-last 4] [--sample-percent P] [--seed 42] [--concurrency 8] [--compress-config FILE] [--dry-run]";

/// Subcommand routing for `seagent batch`, kept as a pure function so it can be tested without
/// building an agent (the `run`/`swe`/`compress` paths need a provider).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sub {
    Distributions,
    Run,
    Swe,
    Compress,
    Usage,
}

pub fn sub(a: &Args) -> Sub {
    match a.pos(0) {
        Some("distributions" | "dist") => Sub::Distributions,
        Some("run") => Sub::Run,
        Some("swe") => Sub::Swe,
        Some("compress") => Sub::Compress,
        _ => Sub::Usage,
    }
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "batch" {
        return None;
    }
    Some((|| -> R {
        match sub(a) {
            Sub::Distributions => {
                match a.pos(1) {
                    Some(n) => println!("{}", distribution_info(n)?),
                    None => {
                        for d in DISTRIBUTIONS {
                            println!("{:<15} {}", d.0, d.1);
                        }
                    }
                }
                Ok(0)
            }
            Sub::Run => {
                let dataset = PathBuf::from(a.need(1, "dataset.jsonl")?);
                let run_name = a.val("run-name").ok_or("--run-name is required")?.to_string();
                // Per-prompt step cap and the ephemeral system prompt go through config overrides
                // so they never reach the saved trajectories.
                let mut sets = vec![format!("runner.max_steps_per_turn={}", a.num::<u64>("max-turns")?.unwrap_or(10))];
                if let Some(sp) = a.val("system-prompt") {
                    sets.push(format!("identity={}", toml::Value::from(sp)));
                }
                let mut args = vec![];
                for s in sets {
                    args.push("--set".to_string());
                    args.push(s);
                }
                for f in ["model", "workspace"] {
                    if let Some(v) = a.val(f) {
                        args.push(format!("--{f}"));
                        args.push(v.to_string());
                    }
                }
                for f in ["yes", "quiet"] {
                    if a.flag(f) {
                        args.push(format!("--{f}"));
                    }
                }
                let ba = Args::parse(&args).map_err(crate::Fail::Usage)?;
                let c = crate::build_agent(&ba, crate::approver_for(&ba, false), false)?;
                let cfg = RunCfg {
                    run_name: run_name.clone(),
                    distribution: a.val("distribution").unwrap_or("default").into(),
                    batch_size: a.num::<usize>("batch-size")?.unwrap_or(10),
                    workers: a.num::<usize>("workers")?.unwrap_or(4),
                    max_samples: a.num::<usize>("max-samples")?,
                    model: a.val("model").map(String::from),
                    seed: a.num::<u64>("seed")?,
                    keep_unreasoned: a.flag("keep-unreasoned"),
                    verbose: a.flag("verbose"),
                };
                let out = a.val("out").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("data").join(&run_name));
                let s = run_batch(&c.k, &c.workspace, &dataset, &out, &cfg, a.flag("resume"))?;
                println!("{}", summary_text(&s));
                Ok(if s.failed > 0 { 1 } else { 0 })
            }
            Sub::Swe => super::miniswe::cli(a),
            Sub::Compress => super::trajcomp::cli(a),
            Sub::Usage => crate::usage(USAGE),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::kit;

    #[test]
    fn distributions_sample_and_fallback() {
        assert_eq!(DISTRIBUTIONS.len(), 17);
        let mut r = Rng::new(Some(1));
        let (s, w) = sample("terminal_only", &mut r).unwrap();
        assert_eq!((s, w.len()), (vec!["terminal".to_string(), "file".to_string()], 0));
        // compound entry rolls once for both members
        for _ in 0..50 {
            let (s, _) = sample("browser_tasks", &mut r).unwrap();
            assert_eq!(s.contains(&"browser".to_string()), s.contains(&"search".to_string()));
            assert!(!s.is_empty());
        }
        assert!(sample("nope", &mut r).is_err());
        assert!(distribution_info("research").unwrap().contains("web             :  90% chance"));
        assert_eq!(toolset_tools("file").unwrap()[0], "read");
        assert_eq!(toolset_tools("vision").unwrap(), vec!["vision_analyze"]);
    }

    /// Lock the upstream table (toolset_distributions.py:18-46) so a typo in a percentage or a
    /// dropped entry is caught, and exercise the documented fallback path.
    #[test]
    fn dispatch_routes_batch_subcommands() {
        let p = |v: &[&str]| Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
        assert_eq!(COMMANDS, &["batch"]);
        for (argv, want) in [
            (vec!["run", "d.jsonl"], Sub::Run),
            (vec!["swe", "--task", "x"], Sub::Swe),
            (vec!["compress", "in.jsonl"], Sub::Compress),
            (vec!["distributions"], Sub::Distributions),
            (vec!["dist"], Sub::Distributions),
            (vec![], Sub::Usage),
            (vec!["bogus"], Sub::Usage),
        ] {
            assert_eq!(sub(&p(&argv)), want, "{argv:?}");
        }
        // `seagent batch …` is ours (Args arrive without the command itself, as main.rs does)
        assert!(dispatch("batch", &p(&["run", "d.jsonl"]), &[]).is_some());
        assert!(dispatch("evals", &p(&["list"]), &[]).is_none());
        // compress validates its input before building anything
        let e = dispatch("batch", &p(&["compress"]), &[]).unwrap().unwrap_err().to_string();
        assert!(e.contains("input"), "{e}");
        let e = dispatch("batch", &p(&["bogus"]), &[]).unwrap().unwrap_err().to_string();
        assert!(e.contains("seagent batch run <dataset.jsonl>"), "{e}");
    }

    #[test]
    fn distributions_match_upstream_table_and_fallback() {
        let names: Vec<&str> = DISTRIBUTIONS.iter().map(|d| d.0).collect();
        assert_eq!(
            names,
            vec![
                "default", "image_gen", "research", "science", "development", "safe", "balanced", "minimal", "terminal_only", "terminal_web",
                "creative", "reasoning", "browser_use", "browser_only", "browser_tasks", "terminal_tasks", "mixed_tasks"
            ]
        );
        let table = |n: &str| distribution(n).unwrap().2;
        assert_eq!(table("default"), [("web", 100), ("vision", 100), ("image_gen", 100), ("terminal", 100), ("file", 100), ("browser", 100)]);
        assert_eq!(table("creative"), [("image_gen", 90), ("vision", 90), ("web", 30)]);
        assert_eq!(table("browser_tasks"), [("browser+search", 97), ("vision", 12), ("terminal", 15)]);
        assert_eq!(table("terminal_tasks"), [("terminal", 97), ("file", 97), ("web", 97), ("browser", 75), ("vision", 50), ("image_gen", 10)]);
        assert_eq!(table("mixed_tasks"), [("browser", 92), ("terminal", 92), ("file", 92), ("web", 35), ("vision", 15), ("image_gen", 15)]);
        for (name, desc, entries) in DISTRIBUTIONS {
            assert!(!desc.is_empty(), "{name}");
            assert!(!entries.is_empty(), "{name}");
            for (e, p) in *entries {
                assert!((1..=100).contains(p), "{name}/{e} = {p}");
                for m in e.split('+') {
                    assert!(toolset_tools(m).is_some(), "{name}: unknown toolset {m}");
                }
            }
        }
        // nothing rolled → highest-probability entry, first one wins on a tie (Python max())
        let (s, _) = sample_with("terminal_only", || 1.0).unwrap();
        assert_eq!(s, vec!["terminal".to_string()]);
        let (s, _) = sample_with("mixed_tasks", || 1.0).unwrap();
        assert_eq!(s, vec!["browser".to_string()]);
        // a roll of 0 selects every entry, in table order, once each
        let (s, _) = sample_with("terminal_only", || 0.0).unwrap();
        assert_eq!(s, vec!["terminal".to_string(), "file".to_string()]);
        // percentages are honoured: a 50% entry lands ~half the time over 400 seeded draws
        let mut r = Rng::new(Some(9));
        let hits = (0..400).filter(|_| sample("balanced", &mut r).unwrap().0.contains(&"terminal".to_string())).count();
        assert!((140..260).contains(&hits), "terminal hit {hits}/400 at 50%");
    }

    #[test]
    fn success_judging_matches_upstream() {
        assert!(tool_call_succeeded("{\"output\": \"x\", \"exit_code\": 1}"));
        assert!(!tool_call_succeeded("{\"error\": \"boom\"}"));
        assert!(!tool_call_succeeded("{\"content\": {\"error\": \"x\"}}"));
        assert!(!tool_call_succeeded("{\"success\": false}"));
        assert!(tool_call_succeeded("{\"error\": null}"));
        assert!(!tool_call_succeeded("Error: no such file"));
        assert!(!tool_call_succeeded(""));
        assert!(tool_call_succeeded("contains error: later"));
    }

    #[test]
    fn batch_run_checkpoint_resume_and_merge() {
        let kt = kit();
        let dir = kt.ws.join("out");
        let ds = kt.ws.join("ds.jsonl");
        std::fs::write(&ds, "{\"prompt\": \"one\"}\n\nnot json\n{\"nope\": 1}\n{\"prompt\": \"two\"}\n{\"prompt\": \"three\", \"image\": \"python:3\"}\n").unwrap();
        let cfg = RunCfg { run_name: "t".into(), distribution: "terminal_only".into(), batch_size: 1, workers: 2, max_samples: None, model: None, seed: Some(3), keep_unreasoned: true, verbose: false };
        let s = run_batch(&kt.k, &kt.ws, &ds, &dir, &cfg, false).unwrap();
        assert_eq!((s.processed, s.kept, s.failed), (3, 2, 1));
        let merged = std::fs::read_to_string(dir.join("trajectories.jsonl")).unwrap();
        let rows: Vec<Value> = merged.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!(rows.len(), 2);
        let r0 = &rows[0];
        assert_eq!(r0["conversations"][0]["from"], "system");
        assert!(r0["conversations"][1]["value"].as_str().unwrap() == "one" || r0["conversations"][1]["value"].as_str().unwrap() == "two", "{r0}");
        assert_eq!(r0["toolsets_used"], json!(["terminal", "file"]));
        assert!(r0["tool_stats"].as_object().unwrap().contains_key("read"));
        assert_eq!(r0["completed"], true);
        let ck: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("checkpoint.json")).unwrap()).unwrap();
        assert_eq!(ck["completed_prompts"], json!([0, 1]));
        let st: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("statistics.json")).unwrap()).unwrap();
        assert_eq!(st["total_prompts"], 3);
        // the no-reasoning echo samples are discarded by default (tombstones)
        let dir2 = kt.ws.join("out2");
        let cfg2 = RunCfg { keep_unreasoned: false, run_name: "t2".into(), ..cfg.clone() };
        let s = run_batch(&kt.k, &kt.ws, &ds, &dir2, &cfg2, false).unwrap();
        assert_eq!((s.kept, s.discarded), (0, 2));
        // discarded samples contribute nothing to statistics.json (upstream merges stats after
        // the discard branch), even though their tool calls happened
        let st2: Value = serde_json::from_str(&std::fs::read_to_string(dir2.join("statistics.json")).unwrap()).unwrap();
        assert_eq!(st2["discarded_no_reasoning"], 2);
        assert!(st2["tool_statistics"].as_object().unwrap().is_empty(), "{st2}");
        assert_eq!(st2["reasoning_statistics"]["total_assistant_turns"], 0, "{st2}");
        // resume skips completed (tombstoned) prompts by content; only the failed one is retried
        let s = run_batch(&kt.k, &kt.ws, &ds, &dir2, &cfg2, true).unwrap();
        assert_eq!((s.processed, s.failed), (1, 1));
        // corrupted entries (hallucinated tools) are filtered on merge
        std::fs::write(dir.join("batch_9.jsonl"), "{\"prompt_index\": 7, \"tool_stats\": {\"made_up_tool\": {}}}\n{bad\n").unwrap();
        let tools: BTreeSet<String> = kt.k.specs().into_iter().map(|s| s.name).collect();
        assert_eq!(combine(&dir, &tools).unwrap(), (2, 3));
        // sessions are not kept
        assert!(kt.k.store.list().is_empty());
    }
}
