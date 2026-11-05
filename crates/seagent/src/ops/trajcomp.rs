//! `seagent batch compress` (Hermes `trajectory_compressor.py`): post-process ShareGPT trajectories
//! into a token budget. The head (first system, human, gpt and tool turn) and the last N turns
//! are protected; from the middle only as many turns as needed are summarized (never splitting a
//! `<tool_call>`/`<tool_response>` pair) and replaced with one human `[CONTEXT SUMMARY]:` turn.
//! Token counts use seagent's estimate (chars / 4 — upstream's own fallback when no Hugging Face
//! tokenizer is available). Summaries come from any configured model (`--summary-model`), with
//! retries and a fixed fallback summary; per-file outputs plus `compression_metrics.json`.

use crate::args::Args;
use crate::R;
use seagent_core::{Block, Cancel, Message, ModelRequest, Provider, StopReason};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const SUMMARY_FALLBACK: &str = "[CONTEXT SUMMARY]: [Summary generation failed - previous turns contained tool calls and responses that have been compressed to save context space.]";

#[derive(Debug, Clone)]
pub struct CompressCfg {
    pub target_max_tokens: usize,
    pub summary_target_tokens: usize,
    pub protect_first_system: bool,
    pub protect_first_human: bool,
    pub protect_first_gpt: bool,
    pub protect_first_tool: bool,
    pub protect_last_n_turns: usize,
    pub summarization_model: String,
    pub temperature: f32,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub add_summary_notice: bool,
    pub summary_notice_text: String,
    pub output_suffix: String,
    pub max_concurrent_requests: usize,
    pub metrics_per_trajectory: bool,
    pub metrics_output_file: String,
}

impl Default for CompressCfg {
    fn default() -> Self {
        CompressCfg {
            target_max_tokens: 15250,
            summary_target_tokens: 750,
            protect_first_system: true,
            protect_first_human: true,
            protect_first_gpt: true,
            protect_first_tool: true,
            protect_last_n_turns: 4,
            summarization_model: String::new(),
            temperature: 0.3,
            max_retries: 3,
            retry_delay_ms: 2000,
            add_summary_notice: true,
            summary_notice_text: "\n\nSome of your previous tool responses may be summarized to preserve context.".into(),
            output_suffix: "_compressed".into(),
            max_concurrent_requests: 8,
            metrics_per_trajectory: true,
            metrics_output_file: "compression_metrics.json".into(),
        }
    }
}

impl CompressCfg {
    /// Sections as upstream's YAML (`compression`, `protected_turns`, `summarization`, `output`,
    /// `processing`, `metrics`), written as TOML.
    pub fn from_toml(t: &toml::Table) -> CompressCfg {
        let mut c = CompressCfg::default();
        let g = |s: &str, k: &str| t.get(s).and_then(|x| x.get(k)).cloned();
        let int = |s: &str, k: &str, d: usize| g(s, k).and_then(|v| v.as_integer()).map(|v| v as usize).unwrap_or(d);
        let bo = |s: &str, k: &str, d: bool| g(s, k).and_then(|v| v.as_bool()).unwrap_or(d);
        let st = |s: &str, k: &str, d: &str| g(s, k).and_then(|v| v.as_str().map(String::from)).unwrap_or_else(|| d.to_string());
        c.target_max_tokens = int("compression", "target_max_tokens", c.target_max_tokens);
        c.summary_target_tokens = int("compression", "summary_target_tokens", c.summary_target_tokens);
        c.protect_first_system = bo("protected_turns", "first_system", true);
        c.protect_first_human = bo("protected_turns", "first_human", true);
        c.protect_first_gpt = bo("protected_turns", "first_gpt", true);
        c.protect_first_tool = bo("protected_turns", "first_tool", true);
        c.protect_last_n_turns = int("protected_turns", "last_n_turns", 4);
        c.summarization_model = st("summarization", "model", "");
        c.temperature = g("summarization", "temperature").and_then(|v| v.as_float()).map(|f| f as f32).unwrap_or(0.3);
        c.max_retries = int("summarization", "max_retries", 3) as u32;
        c.retry_delay_ms = int("summarization", "retry_delay", 2) as u64 * 1000;
        c.add_summary_notice = bo("output", "add_summary_notice", true);
        c.summary_notice_text = st("output", "summary_notice_text", &c.summary_notice_text.clone());
        c.output_suffix = st("output", "output_suffix", "_compressed");
        c.max_concurrent_requests = int("processing", "max_concurrent_requests", 8);
        c.metrics_per_trajectory = bo("metrics", "per_trajectory", true);
        c.metrics_output_file = st("metrics", "output_file", "compression_metrics.json");
        c
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Metrics {
    pub original_tokens: usize,
    pub compressed_tokens: usize,
    pub original_turns: usize,
    pub compressed_turns: usize,
    pub start: i64,
    pub end: i64,
    pub was_compressed: bool,
    pub still_over_limit: bool,
    pub skipped_under_target: bool,
    pub api_calls: u32,
    pub errors: u32,
}

impl Metrics {
    pub fn to_json(&self) -> Value {
        json!({
            "original_tokens": self.original_tokens, "compressed_tokens": self.compressed_tokens,
            "tokens_saved": self.original_tokens as i64 - self.compressed_tokens as i64,
            "compression_ratio": ((self.compressed_tokens as f64 / self.original_tokens.max(1) as f64) * 10000.0).round() / 10000.0,
            "original_turns": self.original_turns, "compressed_turns": self.compressed_turns,
            "turns_removed": self.original_turns as i64 - self.compressed_turns as i64,
            "compression_region": {"start_idx": self.start, "end_idx": self.end, "turns_count": if self.start >= 0 { self.end - self.start } else { 0 }},
            "was_compressed": self.was_compressed, "still_over_limit": self.still_over_limit, "skipped_under_target": self.skipped_under_target,
            "summarization_api_calls": self.api_calls, "summarization_errors": self.errors,
        })
    }
}

/// Upstream falls back to `len(text) // 4` — Python characters, not UTF-8 bytes, so a CJK
/// trajectory is not over-counted 3× (which would compress far later than configured).
pub fn count_tokens(s: &str) -> usize {
    s.chars().count() / 4
}

fn turn_tokens(t: &[Value]) -> Vec<usize> {
    t.iter().map(|x| count_tokens(x.get("value").and_then(|v| v.as_str()).unwrap_or(""))).collect()
}

fn from(t: &Value) -> &str {
    t.get("from").and_then(|v| v.as_str()).unwrap_or("")
}

/// (compressible start, compressible end).
pub fn protected_bounds(t: &[Value], c: &CompressCfg) -> (usize, usize) {
    let n = t.len();
    let mut prot = std::collections::BTreeSet::new();
    for (role, on) in [("system", c.protect_first_system), ("human", c.protect_first_human), ("gpt", c.protect_first_gpt), ("tool", c.protect_first_tool)] {
        if let Some(i) = t.iter().position(|x| from(x) == role).filter(|_| on) {
            prot.insert(i);
        }
    }
    prot.extend(n.saturating_sub(c.protect_last_n_turns)..n);
    let head = prot.iter().filter(|i| **i < n / 2).max().map(|m| m + 1).unwrap_or(0);
    let tail = prot.iter().filter(|i| **i >= n / 2).min().copied().unwrap_or(n);
    (head, tail)
}

/// Move a boundary off `tool` turns (which always follow their gpt turn); forward preferred.
pub fn snap(t: &[Value], idx: usize, min: usize, max: usize) -> usize {
    let clean = |i: usize| i >= t.len() || from(&t[i]) != "tool";
    let mut f = idx;
    while f < max && !clean(f) {
        f += 1;
    }
    if clean(f) {
        return f;
    }
    let mut b = idx;
    while b > min && !clean(b) {
        b -= 1;
    }
    b
}

pub fn plan(t: &[Value], c: &CompressCfg, m: &mut Metrics) -> Option<(usize, usize)> {
    let tt = turn_tokens(t);
    let total: usize = tt.iter().sum();
    m.original_turns = t.len();
    m.compressed_turns = t.len();
    m.original_tokens = total;
    m.compressed_tokens = total;
    m.start = -1;
    m.end = -1;
    if total <= c.target_max_tokens {
        m.skipped_under_target = true;
        return None;
    }
    m.still_over_limit = true;
    let (s0, end) = protected_bounds(t, c);
    let start = snap(t, s0, s0, end);
    if start >= end {
        return None;
    }
    let need = total - c.target_max_tokens + c.summary_target_tokens;
    let (mut acc, mut until) = (0, start);
    for (i, tok) in tt.iter().enumerate().take(end).skip(start) {
        acc += tok;
        until = i + 1;
        if acc >= need {
            break;
        }
    }
    if acc < need && until < end {
        until = end;
    }
    let until = snap(t, until, start, end);
    if until <= start || tt[start..until].iter().sum::<usize>() <= c.summary_target_tokens {
        return None;
    }
    m.start = start as i64;
    m.end = until as i64;
    Some((start, until))
}

fn elide_middle(s: &str, head: usize, tail: usize) -> String {
    let ch: Vec<char> = s.chars().collect();
    if ch.len() <= head + tail {
        return s.into();
    }
    format!("{}\n…[{} of {} chars omitted]…\n{}", ch[..head].iter().collect::<String>(), ch.len() - head - tail, ch.len(), ch[ch.len() - tail..].iter().collect::<String>())
}

pub fn summary_input(t: &[Value], s: usize, e: usize) -> String {
    (s..e).map(|i| {
        let v = t[i].get("value").and_then(|x| x.as_str()).unwrap_or("");
        let v = if v.chars().count() > 3000 { elide_middle(v, 1500, 500) } else { v.to_string() };
        format!("[Turn {i} - {}]:\n{v}", from(&t[i]).to_uppercase())
    }).collect::<Vec<_>>().join("\n\n")
}

pub fn summary_prompt(content: &str, target: usize) -> String {
    format!("Summarize the following agent conversation turns concisely. This summary will replace these turns in the conversation history.\n\nWrite the summary from a neutral perspective describing what the assistant did and learned. Include:\n1. What actions the assistant took (tool calls, searches, file operations)\n2. Key information or results obtained\n3. Any important decisions or findings\n4. Relevant data, file names, values, or outputs\n\nKeep the summary factual and informative. Target approximately {target} tokens.\n\n---\nTURNS TO SUMMARIZE:\n{content}\n---\n\nWrite only the summary, starting with \"[CONTEXT SUMMARY]:\" prefix.")
}

pub struct Compressor {
    pub cfg: CompressCfg,
    pub provider: Arc<dyn Provider>,
    pub model: String,
}

impl Compressor {
    fn summarize(&self, content: &str, m: &mut Metrics) -> String {
        let prompt = summary_prompt(content, self.cfg.summary_target_tokens);
        for attempt in 0..self.cfg.max_retries.max(1) {
            m.api_calls += 1;
            let req = ModelRequest { model: self.model.clone(), messages: vec![Message::user(prompt.clone())], max_tokens: (self.cfg.summary_target_tokens * 2) as u32, temperature: Some(self.cfg.temperature), ..Default::default() };
            let res = self.provider.complete(&req, &mut |_| {}, &Cancel::new()).map_err(|e| e.to_string()).and_then(|r| {
                if r.stop == StopReason::MaxTokens {
                    return Err("trajectory summarization hit the output token cap (finish_reason=length); summary is incomplete".into());
                }
                let text: String = r.message.content.iter().filter_map(|b| if let Block::Text { text } = b { Some(text.as_str()) } else { None }).collect::<String>().trim().to_string();
                Ok(if text.starts_with("[CONTEXT SUMMARY]:") { text } else if text.is_empty() { "[CONTEXT SUMMARY]:".into() } else { format!("[CONTEXT SUMMARY]: {text}") })
            });
            match res {
                Ok(s) => return s,
                Err(e) => {
                    m.errors += 1;
                    eprintln!("summarization attempt {} failed: {e}", attempt + 1);
                    if attempt + 1 < self.cfg.max_retries {
                        std::thread::sleep(std::time::Duration::from_millis((self.cfg.retry_delay_ms * (attempt as u64 + 1)).min(30_000)));
                    }
                }
            }
        }
        SUMMARY_FALLBACK.into()
    }

    pub fn compress(&self, t: &[Value]) -> (Vec<Value>, Metrics) {
        let mut m = Metrics::default();
        let Some((s, u)) = plan(t, &self.cfg, &mut m) else { return (t.to_vec(), m) };
        let summary = self.summarize(&summary_input(t, s, u), &mut m);
        let mut out: Vec<Value> = t[..s].iter().cloned().map(|mut x| {
            if from(&x) == "system" && self.cfg.add_summary_notice {
                let v = x["value"].as_str().unwrap_or("").to_string() + &self.cfg.summary_notice_text;
                x["value"] = json!(v);
            }
            x
        }).collect();
        out.push(json!({"from": "human", "value": summary}));
        out.extend(t[u..].iter().cloned());
        m.compressed_turns = out.len();
        m.compressed_tokens = turn_tokens(&out).iter().sum();
        m.was_compressed = true;
        m.still_over_limit = m.compressed_tokens > self.cfg.target_max_tokens;
        (out, m)
    }

    pub fn process_entry(&self, e: &Value) -> (Value, Metrics) {
        let Some(conv) = e.get("conversations").and_then(|c| c.as_array()) else { return (e.clone(), Metrics::default()) };
        let (c, m) = self.compress(conv);
        let mut r = e.clone();
        r["conversations"] = Value::Array(c);
        if self.cfg.metrics_per_trajectory && m.was_compressed {
            r["compression_metrics"] = m.to_json();
        }
        (r, m)
    }

    /// Compress entries concurrently (bounded by `max_concurrent_requests`), keeping order.
    pub fn process_all(&self, entries: &[Value]) -> (Vec<Value>, Vec<Metrics>) {
        let n = self.cfg.max_concurrent_requests.max(1);
        let next = Mutex::new(0usize);
        let results: Mutex<Vec<Option<(Value, Metrics)>>> = Mutex::new(vec![None; entries.len()]);
        std::thread::scope(|s| {
            for _ in 0..n.min(entries.len().max(1)) {
                s.spawn(|| loop {
                    let i = {
                        let mut g = next.lock().unwrap();
                        let i = *g;
                        *g += 1;
                        i
                    };
                    if i >= entries.len() {
                        break;
                    }
                    let r = self.process_entry(&entries[i]);
                    results.lock().unwrap()[i] = Some(r);
                });
            }
        });
        results.into_inner().unwrap().into_iter().flatten().unzip()
    }
}

pub fn aggregate(ms: &[Metrics], start: &str, secs: f64) -> Value {
    let comp: Vec<&Metrics> = ms.iter().filter(|m| m.was_compressed).collect();
    let before: usize = ms.iter().map(|m| m.original_tokens).sum();
    let after: usize = ms.iter().map(|m| m.compressed_tokens).sum();
    let tb: usize = ms.iter().map(|m| m.original_turns).sum();
    let ta: usize = ms.iter().map(|m| m.compressed_turns).sum();
    let calls: u32 = ms.iter().map(|m| m.api_calls).sum();
    let errs: u32 = ms.iter().map(|m| m.errors).sum();
    let r4 = |x: f64| (x * 10000.0).round() / 10000.0;
    let mean = |v: Vec<f64>, d: f64| if v.is_empty() { d } else { v.iter().sum::<f64>() / v.len() as f64 };
    json!({
        "summary": {"total_trajectories": ms.len(), "trajectories_compressed": comp.len(), "trajectories_skipped_under_target": ms.iter().filter(|m| m.skipped_under_target).count(), "trajectories_still_over_limit": ms.iter().filter(|m| m.still_over_limit).count(), "trajectories_failed": 0, "compression_rate": r4(comp.len() as f64 / ms.len().max(1) as f64)},
        "tokens": {"total_before": before, "total_after": after, "total_saved": before as i64 - after as i64, "overall_compression_ratio": r4(after as f64 / before.max(1) as f64)},
        "turns": {"total_before": tb, "total_after": ta, "total_removed": tb as i64 - ta as i64},
        "averages": {"avg_compression_ratio": r4(mean(comp.iter().map(|m| m.compressed_tokens as f64 / m.original_tokens.max(1) as f64).collect(), 1.0)), "avg_tokens_saved_per_compressed": (mean(comp.iter().map(|m| (m.original_tokens - m.compressed_tokens) as f64).collect(), 0.0) * 10.0).round() / 10.0, "avg_turns_removed_per_compressed": (mean(comp.iter().map(|m| (m.original_turns - m.compressed_turns) as f64).collect(), 0.0) * 100.0).round() / 100.0},
        "summarization": {"total_api_calls": calls, "total_errors": errs, "success_rate": r4(1.0 - errs as f64 / calls.max(1) as f64)},
        "processing": {"start_time": start, "end_time": seagent_kernel::trajectory::iso_ms(seagent_kernel::event::now_ms()), "duration_seconds": (secs * 100.0).round() / 100.0},
    })
}

fn load_jsonl(p: &Path) -> Vec<Value> {
    std::fs::read_to_string(p).unwrap_or_default().lines().filter(|l| !l.trim().is_empty()).filter_map(|l| serde_json::from_str(l).map_err(|e| eprintln!("skipping invalid JSON in {}: {e}", p.display())).ok()).collect()
}

fn write_jsonl(p: &Path, v: &[Value]) -> Result<(), String> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    std::fs::write(p, v.iter().map(|x| x.to_string() + "\n").collect::<String>()).map_err(|e| format!("{}: {e}", p.display()))
}

/// Deterministic sample of `pct`% of entries (seeded), keeping their order. The size is
/// floor(len*pct/100) like upstream `random.sample(entries, max(1, int(len*pct/100)))`.
pub fn sample(v: Vec<Value>, pct: f64, seed: u64) -> Vec<Value> {
    let k = ((v.len() as f64 * pct / 100.0).floor() as usize).max(1).min(v.len());
    let mut rng = super::batch::Rng::new(Some(seed));
    let mut idx: Vec<usize> = (0..v.len()).collect();
    for i in (1..idx.len()).rev() {
        let j = (rng.next_f64() * (i + 1) as f64) as usize;
        idx.swap(i, j);
    }
    let mut pick: Vec<usize> = idx.into_iter().take(k).collect();
    pick.sort();
    pick.into_iter().map(|i| v[i].clone()).collect()
}

/// Compress a file or every `*.jsonl` in a directory. Returns (output path, aggregate metrics).
pub fn run(c: &Compressor, input: &Path, output: Option<&Path>, sample_pct: Option<f64>, seed: u64, dry_run: bool) -> Result<(PathBuf, Value), String> {
    if !input.exists() {
        return Err(format!("Input not found: {}", input.display()));
    }
    if let Some(p) = sample_pct {
        if p <= 0.0 || p > 100.0 {
            return Err(format!("sample_percent must be between 1 and 100, got {p}"));
        }
    }
    let start = seagent_kernel::trajectory::iso_ms(seagent_kernel::event::now_ms());
    let t0 = std::time::Instant::now();
    let files: Vec<PathBuf> = if input.is_file() {
        vec![input.to_path_buf()]
    } else {
        let mut v: Vec<PathBuf> = std::fs::read_dir(input).map_err(|e| e.to_string())?.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "jsonl")).collect();
        v.sort();
        v
    };
    let out = output.map(Path::to_path_buf).unwrap_or_else(|| {
        let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("out");
        if input.is_file() { input.with_file_name(format!("{stem}{}.jsonl", c.cfg.output_suffix)) } else { input.with_file_name(format!("{stem}{}", c.cfg.output_suffix)) }
    });
    let mut all = vec![];
    let mut per_file = vec![];
    for f in &files {
        let mut v = load_jsonl(f);
        if let Some(p) = sample_pct {
            v = sample(v, p, seed);
        }
        per_file.push((f.clone(), v));
    }
    if dry_run {
        let mut ms = vec![];
        for (_, v) in &per_file {
            for e in v {
                let mut m = Metrics::default();
                if let Some(conv) = e.get("conversations").and_then(|c| c.as_array()) {
                    // Dry run: predict the outcome of the plan instead of reporting “0 compressed”
                    // for a trajectory that would clearly be rewritten.
                    if let Some((s, u)) = plan(conv, &c.cfg, &mut m) {
                        let region: usize = turn_tokens(&conv[s..u]).iter().sum();
                        m.was_compressed = true;
                        m.compressed_turns = conv.len() - (u - s) + 1;
                        m.compressed_tokens = m.original_tokens - region + c.cfg.summary_target_tokens;
                        m.still_over_limit = m.compressed_tokens > c.cfg.target_max_tokens;
                    }
                }
                ms.push(m);
            }
        }
        return Ok((out, aggregate(&ms, &start, t0.elapsed().as_secs_f64())));
    }
    for (f, v) in per_file {
        let (res, ms) = c.process_all(&v);
        let dest = if input.is_file() { out.clone() } else { out.join(f.file_name().unwrap_or_default()) };
        write_jsonl(&dest, &res)?;
        all.extend(ms);
    }
    let agg = aggregate(&all, &start, t0.elapsed().as_secs_f64());
    let mpath = if input.is_file() { out.with_file_name(&c.cfg.metrics_output_file) } else { out.join(&c.cfg.metrics_output_file) };
    std::fs::write(&mpath, serde_json::to_string_pretty(&agg).unwrap_or_default()).map_err(|e| e.to_string())?;
    Ok((out, agg))
}

pub fn cli(a: &Args) -> R {
    let input = PathBuf::from(a.need(1, "input")?);
    let mut cfg = match a.val("compress-config") {
        Some(p) => CompressCfg::from_toml(&std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?.parse::<toml::Table>().map_err(|e| format!("{p}: {e}"))?),
        None => CompressCfg::default(),
    };
    if let Some(v) = a.num::<usize>("target-max-tokens")? {
        cfg.target_max_tokens = v;
    }
    if let Some(v) = a.num::<usize>("summary-target-tokens")? {
        cfg.summary_target_tokens = v;
    }
    if let Some(v) = a.num::<usize>("protect-last")? {
        cfg.protect_last_n_turns = v;
    }
    if let Some(v) = a.num::<usize>("concurrency")? {
        cfg.max_concurrent_requests = v;
    }
    if let Some(m) = a.val("summary-model") {
        cfg.summarization_model = m.into();
    }
    let c = crate::build_agent(&Args::default(), crate::approver_for(&Args::default(), false), false)?;
    let model = if cfg.summarization_model.is_empty() { c.k.cfg.model.default.clone() } else { cfg.summarization_model.clone() };
    let (pid, name) = seagent_kernel::context::split_model(&model);
    let comp = Compressor { provider: c.k.resolver.provider(pid)?, model: name.into(), cfg };
    let (out, agg) = run(&comp, &input, a.val("out").map(Path::new), a.num::<f64>("sample-percent")?, a.num::<u64>("seed")?.unwrap_or(42), a.flag("dry-run"))?;
    let s = &agg["summary"];
    let t = &agg["tokens"];
    println!("{} trajectories: {} compressed, {} under target, {} still over limit\ntokens {} → {} (ratio {})\n{}", s["total_trajectories"], s["trajectories_compressed"], s["trajectories_skipped_under_target"], s["trajectories_still_over_limit"], t["total_before"], t["total_after"], t["overall_compression_ratio"], if a.flag("dry-run") { format!("dry run: would write {}", out.display()) } else { format!("written to {}", out.display()) });
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::*;

    struct Sum(Mutex<u32>);
    impl Provider for Sum {
        fn id(&self) -> &str {
            "s"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 1000, max_output: 100, tools: false, vision: false, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            let mut n = self.0.lock().unwrap();
            *n += 1;
            assert!(req.messages[0].text().contains("TURNS TO SUMMARIZE"));
            if *n == 1 {
                return Err(ProviderError::new(ProviderErrorKind::Network, "flaky"));
            }
            Ok(ModelResponse { message: Message::assistant("did things"), stop: StopReason::EndTurn, usage: Usage::default(), model: "s".into() })
        }
    }

    fn turn(f: &str, n: usize) -> Value {
        json!({"from": f, "value": "x".repeat(n * 4)})
    }

    fn traj() -> Vec<Value> {
        let mut t = vec![turn("system", 10), turn("human", 10), turn("gpt", 10), turn("tool", 10)];
        for _ in 0..6 {
            t.push(turn("gpt", 100));
            t.push(turn("tool", 100));
        }
        t.extend([turn("gpt", 10), turn("human", 10), turn("gpt", 10), turn("gpt", 10)]);
        t
    }

    fn cfg() -> CompressCfg {
        CompressCfg { target_max_tokens: 700, summary_target_tokens: 50, retry_delay_ms: 1, ..Default::default() }
    }

    #[test]
    fn plan_protects_head_tail_and_tool_pairs() {
        let t = traj();
        let mut m = Metrics::default();
        let (s, u) = plan(&t, &cfg(), &mut m).unwrap();
        assert_eq!(s, 4); // after first system/human/gpt/tool
        assert_eq!(from(&t[u]), "gpt"); // never starts the kept tail on a tool turn
        assert!(u <= t.len() - 4);
        // 1280 tokens, need 1280-700+50 = 630 → 7 turns (700), snapped off the tool turn
        assert_eq!(u, 12);
        let mut m = Metrics::default();
        assert!(plan(&t, &CompressCfg { target_max_tokens: 100_000, ..cfg() }, &mut m).is_none());
        assert!(m.skipped_under_target);
        assert_eq!(snap(&t, 5, 4, 16), 6);
    }

    #[test]
    fn compress_with_retry_notice_and_metrics() {
        let sum = Arc::new(Sum(Mutex::new(0)));
        let c = Compressor { cfg: cfg(), provider: sum.clone(), model: "m".into() };
        let e = json!({"conversations": traj(), "model": "x"});
        let (r, m) = c.process_entry(&e);
        assert!(m.was_compressed && !m.still_over_limit);
        assert_eq!((m.api_calls, m.errors), (2, 1));
        let conv = r["conversations"].as_array().unwrap();
        assert_eq!(conv[4], json!({"from": "human", "value": "[CONTEXT SUMMARY]: did things"}));
        assert!(conv[0]["value"].as_str().unwrap().ends_with("may be summarized to preserve context."));
        assert_eq!(conv.len(), traj().len() - 8 + 1);
        assert_eq!(r["compression_metrics"]["compression_region"]["turns_count"], 8);
        // directory mode with metrics file + sampling
        let d = seagent_core::tmp::scratch_path(format!("seagent-tc-{}", seagent_kernel::util::random_hex(6)));
        std::fs::create_dir_all(d.join("in")).unwrap();
        std::fs::write(d.join("in/a.jsonl"), format!("{e}\n{}\n", json!({"conversations": [turn("human", 1)]}))).unwrap();
        let (out, agg) = run(&c, &d.join("in"), None, None, 42, false).unwrap();
        assert_eq!(out, d.join("in_compressed"));
        assert_eq!(agg["summary"]["trajectories_compressed"], 1);
        assert_eq!(agg["summary"]["trajectories_skipped_under_target"], 1);
        assert!(out.join("compression_metrics.json").exists());
        assert_eq!(std::fs::read_to_string(out.join("a.jsonl")).unwrap().lines().count(), 2);
        assert_eq!(sample((0..10).map(|i| json!(i)).collect(), 30.0, 1).len(), 3);
        // floor(15*30/100) = 4 (upstream), not round() = 5
        assert_eq!(sample((0..15).map(|i| json!(i)).collect(), 30.0, 1).len(), 4);
        assert_eq!(sample((0..100).map(|i| json!(i)).collect(), 1.0, 7).len(), 1);
        assert!(run(&c, &d.join("in"), None, Some(0.0), 1, false).is_err());
        // --dry-run predicts what would happen and never calls the model
        let calls = *sum.0.lock().unwrap();
        let (dout, dagg) = run(&c, &d.join("in"), None, None, 42, true).unwrap();
        assert_eq!(dout, d.join("in_compressed"));
        assert_eq!(*sum.0.lock().unwrap(), calls, "dry run must not call the provider");
        assert_eq!(dagg["summary"]["trajectories_compressed"], 1, "{dagg}");
        assert_eq!(dagg["summary"]["trajectories_skipped_under_target"], 1);
        assert_eq!(dagg["summary"]["trajectories_still_over_limit"], 0);
        assert!(dagg["tokens"]["total_after"].as_u64().unwrap() < dagg["tokens"]["total_before"].as_u64().unwrap());
    }

    #[test]
    fn token_count_is_char_based_like_upstream() {
        // upstream: len(text)//4 on the Python string → characters, not UTF-8 bytes
        assert_eq!(count_tokens("abcdefgh"), 2);
        assert_eq!(count_tokens("中文軌跡測試八個字"), 2);
        assert_eq!(count_tokens(""), 0);
        // 4 CJK chars are 12 bytes; byte counting would say 3, upstream says 1
        assert_eq!(count_tokens("測試測試"), 1);
    }

    #[test]
    fn fallback_after_retries() {
        struct Bad;
        impl Provider for Bad {
            fn id(&self) -> &str {
                "b"
            }
            fn caps(&self, _: &str) -> ModelCaps {
                ModelCaps { context_window: 1, max_output: 1, tools: false, vision: false, explicit_cache: false }
            }
            fn complete(&self, _: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
                Ok(ModelResponse { message: Message::assistant("cut"), stop: StopReason::MaxTokens, usage: Usage::default(), model: "b".into() })
            }
        }
        let c = Compressor { cfg: cfg(), provider: Arc::new(Bad), model: "m".into() };
        let (out, m) = c.compress(&traj());
        assert_eq!(out[4]["value"], SUMMARY_FALLBACK);
        assert_eq!((m.api_calls, m.errors), (3, 3));
    }
}
