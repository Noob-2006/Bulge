//! Scores, tokens and cost: `report.json` (machine-readable) and `report.md` (for people),
//! built from `results.jsonl`, plus `compare` for two runs side by side.

use super::run::Attempt;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

fn r3(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0 + 0.0
}

pub fn read_results(out: &Path) -> Result<Vec<Attempt>, String> {
    let p = out.join("results.jsonl");
    let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    text.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).map_err(|e| format!("{}: {e}", p.display()))).collect()
}

/// Aggregate attempts per subject, per task and per suite.
pub fn summarize(attempts: &[Attempt]) -> Value {
    let subjects: Vec<String> = {
        let mut seen = vec![];
        for a in attempts {
            if !seen.contains(&a.subject) {
                seen.push(a.subject.clone());
            }
        }
        seen
    };
    let tasks: BTreeSet<(String, String)> = attempts.iter().map(|a| (a.suite.clone(), a.task.clone())).collect();
    let mut srows = vec![];
    for s in &subjects {
        let mine: Vec<&Attempt> = attempts.iter().filter(|a| &a.subject == s).collect();
        let done: Vec<&&Attempt> = mine.iter().filter(|a| a.status == "done").collect();
        let count = |st: &str| mine.iter().filter(|a| a.status == st).count();
        let passed = done.iter().filter(|a| a.pass).count();
        let costs: Vec<f64> = mine.iter().filter_map(|a| a.cost_usd).collect();
        let jcosts: Vec<f64> = mine.iter().filter_map(|a| a.judge_cost_usd).collect();
        // repeat statistics per task
        let mut by_task: BTreeMap<&str, Vec<bool>> = BTreeMap::new();
        for a in &done {
            by_task.entry(a.task.as_str()).or_default().push(a.pass);
        }
        let any = by_task.values().filter(|v| v.iter().any(|p| *p)).count();
        let all = by_task.values().filter(|v| v.iter().all(|p| *p)).count();
        let agree = by_task.values().filter(|v| v.iter().all(|p| *p) || v.iter().all(|p| !*p)).count();
        let n_tasks = by_task.len().max(1);
        srows.push(json!({
            "subject": s,
            "attempts": mine.len(), "done": done.len(), "pending": count("pending"), "errors": count("error"), "unsupported": count("unsupported"),
            "passed": passed,
            "pass_rate": if done.is_empty() { Value::Null } else { json!(r3(passed as f64 / done.len() as f64)) },
            "mean_score": if done.is_empty() { Value::Null } else { json!(r3(done.iter().map(|a| a.score).sum::<f64>() / done.len() as f64)) },
            "pass_at_k": if by_task.is_empty() { Value::Null } else { json!(r3(any as f64 / n_tasks as f64)) },
            "pass_all_k": if by_task.is_empty() { Value::Null } else { json!(r3(all as f64 / n_tasks as f64)) },
            "consistency": if by_task.is_empty() { Value::Null } else { json!(r3(agree as f64 / n_tasks as f64)) },
            "input_tokens": mine.iter().map(|a| a.input_tokens).sum::<u64>(),
            "output_tokens": mine.iter().map(|a| a.output_tokens).sum::<u64>(),
            "cost_usd": if costs.is_empty() { Value::Null } else { json!((costs.iter().sum::<f64>() * 1e6).round() / 1e6) },
            "judge_input_tokens": mine.iter().map(|a| a.judge_input_tokens).sum::<u64>(),
            "judge_output_tokens": mine.iter().map(|a| a.judge_output_tokens).sum::<u64>(),
            "judge_cost_usd": if jcosts.is_empty() { Value::Null } else { json!(jcosts.iter().sum::<f64>()) },
            "mean_ms": if mine.is_empty() { 0 } else { mine.iter().map(|a| a.ms).sum::<u64>() / mine.len() as u64 },
        }));
    }
    let mut trows = vec![];
    for (suite, task) in &tasks {
        let mut cells = serde_json::Map::new();
        for s in &subjects {
            let v: Vec<&Attempt> = attempts.iter().filter(|a| &a.subject == s && &a.task == task).collect();
            if v.is_empty() {
                continue;
            }
            let done: Vec<&&Attempt> = v.iter().filter(|a| a.status == "done").collect();
            cells.insert(
                s.clone(),
                json!({
                    "runs": v.len(), "passed": done.iter().filter(|a| a.pass).count(),
                    "mean_score": if done.is_empty() { Value::Null } else { json!(r3(done.iter().map(|a| a.score).sum::<f64>() / done.len() as f64)) },
                    "status": v.iter().map(|a| a.status.clone()).collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>().join("/"),
                }),
            );
        }
        trows.push(json!({"suite": suite, "task": task, "by_subject": cells}));
    }
    let suites: BTreeSet<&str> = tasks.iter().map(|(s, _)| s.as_str()).collect();
    let mut by_suite = vec![];
    for su in suites {
        let mut cells = serde_json::Map::new();
        for s in &subjects {
            let done: Vec<&Attempt> = attempts.iter().filter(|a| &a.subject == s && a.suite == su && a.status == "done").collect();
            if !done.is_empty() {
                cells.insert(s.clone(), json!(r3(done.iter().filter(|a| a.pass).count() as f64 / done.len() as f64)));
            }
        }
        by_suite.push(json!({"suite": su, "pass_rate": cells}));
    }
    json!({"subjects": srows, "tasks": trows, "suites": by_suite})
}

fn cell(v: &Value) -> String {
    match v {
        Value::Null => "–".into(),
        Value::Number(n) => n.as_f64().map(|f| if f.fract() == 0.0 && f.abs() < 1e15 { format!("{}", f as i64) } else { format!("{f:.3}") }).unwrap_or_default(),
        Value::String(s) => s.clone(),
        o => o.to_string(),
    }
}

fn pct(v: &Value) -> String {
    v.as_f64().map(|f| format!("{:.1}%", f * 100.0)).unwrap_or_else(|| "–".into())
}

fn usd(v: &Value) -> String {
    v.as_f64().map(|f| format!("${f:.4}")).unwrap_or_else(|| "–".into())
}

/// Markdown report. `meta` is the run manifest (suites, judge, repeat…).
pub fn render_md(summary: &Value, meta: &Value) -> String {
    let mut s = String::from("# seagent evals report\n\n");
    for (k, label) in [("suites", "Suites"), ("judge", "Judge"), ("repeat", "Repeats"), ("started", "Started")] {
        if let Some(v) = meta.get(k).filter(|v| !v.is_null()) {
            s.push_str(&format!("- {label}: {}\n", match v {
                Value::Array(a) => a.iter().map(cell).collect::<Vec<_>>().join(", "),
                o => cell(o),
            }));
        }
    }
    s.push_str("\n## Subjects\n\n| subject | done | pass rate | mean score | pass@k | pass^k | consistency | tokens in | tokens out | cost | judge cost | pending | errors | unsupported | mean time |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for r in summary["subjects"].as_array().cloned().unwrap_or_default() {
        s.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:.1}s |\n",
            cell(&r["subject"]), cell(&r["done"]), pct(&r["pass_rate"]), cell(&r["mean_score"]), pct(&r["pass_at_k"]), pct(&r["pass_all_k"]), pct(&r["consistency"]),
            cell(&r["input_tokens"]), cell(&r["output_tokens"]), usd(&r["cost_usd"]), usd(&r["judge_cost_usd"]), cell(&r["pending"]), cell(&r["errors"]), cell(&r["unsupported"]),
            r["mean_ms"].as_f64().unwrap_or(0.0) / 1000.0
        ));
    }
    let subjects: Vec<String> = summary["subjects"].as_array().cloned().unwrap_or_default().iter().filter_map(|r| r["subject"].as_str().map(String::from)).collect();
    if summary["suites"].as_array().is_some_and(|a| a.len() > 1) {
        s.push_str(&format!("\n## By suite (pass rate)\n\n| suite | {} |\n|---|{}\n", subjects.join(" | "), "---|".repeat(subjects.len())));
        for r in summary["suites"].as_array().cloned().unwrap_or_default() {
            s.push_str(&format!("| {} | {} |\n", cell(&r["suite"]), subjects.iter().map(|x| pct(&r["pass_rate"][x])).collect::<Vec<_>>().join(" | ")));
        }
    }
    s.push_str(&format!("\n## Tasks (passed / runs, mean score)\n\n| task | {} |\n|---|{}\n", subjects.join(" | "), "---|".repeat(subjects.len())));
    for r in summary["tasks"].as_array().cloned().unwrap_or_default() {
        let cells: Vec<String> = subjects
            .iter()
            .map(|x| {
                let c = &r["by_subject"][x];
                if c.is_null() {
                    "–".into()
                } else if c["mean_score"].is_null() {
                    cell(&c["status"])
                } else {
                    format!("{}/{} ({})", cell(&c["passed"]), cell(&c["runs"]), cell(&c["mean_score"]))
                }
            })
            .collect();
        s.push_str(&format!("| {} | {} |\n", cell(&r["task"]), cells.join(" | ")));
    }
    s
}

/// Write `report.json` and `report.md` for a run directory.
pub fn write(out: &Path, meta: &Value, extra_md: Option<&str>) -> Result<(PathBuf, PathBuf), String> {
    let attempts = read_results(out)?;
    let summary = summarize(&attempts);
    let json_path = out.join("report.json");
    let md_path = out.join("report.md");
    let mut md = render_md(&summary, meta);
    if let Some(x) = extra_md {
        md.push('\n');
        md.push_str(x);
    }
    let mut doc = json!({"meta": meta, "summary": summary});
    if let Ok(t) = std::fs::read_to_string(out.join("roles.json")) {
        if let Ok(v) = serde_json::from_str::<Value>(&t) {
            doc["roles"] = v;
        }
    }
    std::fs::write(&json_path, serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::write(&md_path, md).map_err(|e| e.to_string())?;
    Ok((json_path, md_path))
}

/// Two runs side by side: subjects present in either, with pass rate, score and cost deltas.
pub fn compare(a: &Value, b: &Value, la: &str, lb: &str) -> String {
    let rows = |v: &Value| -> BTreeMap<String, Value> { v["summary"]["subjects"].as_array().cloned().unwrap_or_default().into_iter().filter_map(|r| r["subject"].as_str().map(|s| (s.to_string(), r.clone()))).collect() };
    let (ra, rb) = (rows(a), rows(b));
    let names: BTreeSet<&String> = ra.keys().chain(rb.keys()).collect();
    let mut s = format!("# seagent evals compare\n\nA = {la}\nB = {lb}\n\n| subject | pass rate A | pass rate B | Δ | score A | score B | cost A | cost B |\n|---|---|---|---|---|---|---|---|\n");
    for n in names {
        let (x, y) = (ra.get(n).cloned().unwrap_or(Value::Null), rb.get(n).cloned().unwrap_or(Value::Null));
        let d = match (x["pass_rate"].as_f64(), y["pass_rate"].as_f64()) {
            (Some(p), Some(q)) => format!("{:+.1} pt", (q - p) * 100.0),
            _ => "–".into(),
        };
        s.push_str(&format!("| {n} | {} | {} | {d} | {} | {} | {} | {} |\n", pct(&x["pass_rate"]), pct(&y["pass_rate"]), cell(&x["mean_score"]), cell(&y["mean_score"]), usd(&x["cost_usd"]), usd(&y["cost_usd"])));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str, t: &str, rep: u32, pass: bool, status: &str) -> Attempt {
        Attempt { subject: s.into(), task: t.into(), suite: "x".into(), rep, status: status.into(), pass, score: if pass { 1.0 } else { 0.25 }, input_tokens: 10, output_tokens: 5, cost_usd: Some(0.5), ms: 1000, ..Default::default() }
    }

    #[test]
    fn summary_counts_repeats_tokens_and_cost() {
        let v = vec![at("A", "t1", 1, true, "done"), at("A", "t1", 2, false, "done"), at("A", "t2", 1, true, "done"), at("A", "t2", 2, true, "done"), at("B", "t1", 1, false, "pending"), at("B", "t2", 1, false, "error")];
        let s = summarize(&v);
        let a = &s["subjects"][0];
        assert_eq!((a["passed"].as_u64(), a["pass_rate"].as_f64(), a["pass_at_k"].as_f64(), a["pass_all_k"].as_f64(), a["consistency"].as_f64()), (Some(3), Some(0.75), Some(1.0), Some(0.5), Some(0.5)));
        assert_eq!((a["input_tokens"].as_u64(), a["cost_usd"].as_f64()), (Some(40), Some(2.0)));
        let b = &s["subjects"][1];
        assert_eq!((b["pending"].as_u64(), b["errors"].as_u64(), b["pass_rate"].is_null()), (Some(1), Some(1), true));
        let md = render_md(&s, &json!({"suites": ["builtin:smoke"], "judge": "fake/judge", "repeat": 2}));
        assert!(md.contains("| A | 4 | 75.0% |") && md.contains("| t1 | 1/2 (0.625) | pending |"), "{md}");
        let c = compare(&json!({"summary": s}), &json!({"summary": summarize(&[at("A", "t1", 1, true, "done")])}), "old", "new");
        assert!(c.contains("| A | 75.0% | 100.0% | +25.0 pt |"), "{c}");
    }
}
