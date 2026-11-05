//! Role scenario evaluation (BATCH-next 7-4-1, pro-047) and rule-by-rule ablation (7-4-2,
//! pro-048).
//!
//! Each preset role has scenario questions in `<share>/evals/roles/<preset>.jsonl` (Traditional
//! Chinese, five per preset, judge rubric points per question). For every model the same
//! questions are answered twice: **with** the role's guidelines in the system prompt (the L0
//! core plus the assembled L1/L2 segment, exactly what `seagent role use` gives a session) and
//! **without** (a neutral system prompt). The judge model scores both against the rubric and
//! the question's reference notes — optionally extended with the first-distillation sources
//! (`--provenance DIR`, the internal per-pack provenance files).
//!
//! Ablation: for each guideline line, the questions are answered again with that line removed.
//! When the score does not drop by more than `--threshold` (default 0), the line is a deletion
//! candidate: it costs tokens without changing behaviour on these scenarios.

use super::fake::role_rules;
use super::run::{Runner, Subject, SubjectKind};
use super::Task;
use seagent_kernel::config::Config;
use seagent_kernel::roles;
use serde_json::{json, Value};
use std::path::Path;

pub const PRESETS: &[&str] = &["devops", "swdev", "secops", "data", "itsupport"];

pub const NEUTRAL: &str = "You are a helpful assistant. Answer in Traditional Chinese.";

/// The guidelines a role puts in front of the model, and its rule lines (ablation units).
pub fn guidelines(cfg: &Config, id: &str) -> Result<(String, Vec<String>), String> {
    let cat = roles::Catalog::for_config(cfg);
    let role = roles::resolve(cfg, &cat, id)?;
    let mut text = roles::core_text(cfg).unwrap_or_default();
    if !text.is_empty() {
        text.push_str("\n\n");
    }
    text.push_str(&role.segment_text());
    let rules = role_rules(&role.segment_text());
    let pack_rules: Vec<String> = role.packs.iter().flat_map(|p| p.body.lines().filter_map(|l| l.trim_start().strip_prefix("- ").map(|r| r.trim().to_string()))).collect();
    // ablate only what the packs say (not the generated "ask before"/"reserved acts" lines)
    Ok((text, rules.into_iter().filter(|r| pack_rules.contains(r)).collect()))
}

/// `text` with the first line `- {rule}` removed.
pub fn without_rule(text: &str, rule: &str) -> String {
    let target = format!("- {rule}");
    let mut gone = false;
    text.lines()
        .filter(|l| {
            if !gone && l.trim() == target {
                gone = true;
                return false;
            }
            true
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Scenario questions for a preset (from `dir/<preset>.jsonl`).
pub fn questions(dir: &Path, preset: &str) -> Result<Vec<Task>, String> {
    let p = dir.join(format!("{preset}.jsonl"));
    let mut v = super::parse_tasks(&std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?, &format!("roles/{preset}"))?;
    v.retain(|t| t.role.as_deref().is_none_or(|r| r == preset));
    Ok(v)
}

/// Add the first-distillation sources of the role's packs to each question's reference.
pub fn add_provenance(tasks: &mut [Task], cfg: &Config, preset: &str, prov: &Path) {
    let cat = roles::Catalog::for_config(cfg);
    let Ok(role) = roles::resolve(cfg, &cat, preset) else { return };
    let mut lines = vec![];
    for p in role.l2() {
        let Ok(text) = std::fs::read_to_string(prov.join(format!("{}.json", p.slug))) else { continue };
        let Ok(v) = serde_json::from_str::<Value>(&text) else { continue };
        for rec in v.as_array().cloned().unwrap_or_default() {
            let methods: Vec<String> = rec["from"].as_array().cloned().unwrap_or_default().iter().map(|f| format!("{} ({})", f["method"].as_str().unwrap_or(""), f["sources"].as_array().map(|s| s.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("; ")).unwrap_or_default())).collect();
            lines.push(format!("- {} ← {}", rec["rule"].as_str().unwrap_or(""), methods.join(" | ")));
        }
    }
    if lines.is_empty() {
        return;
    }
    let extra = format!("First-distillation sources (methods of exemplary practitioners behind the guidelines):\n{}", lines.join("\n"));
    for t in tasks {
        t.reference = Some(match &t.reference {
            Some(r) => format!("{r}\n\n{extra}"),
            None => extra.clone(),
        });
    }
}

fn mean_score(attempts: &[super::run::Attempt], label: &str) -> Option<f64> {
    let v: Vec<f64> = attempts.iter().filter(|a| a.subject == label && a.status == "done").map(|a| a.score).collect();
    (!v.is_empty()).then(|| (v.iter().sum::<f64>() + 0.0) / v.len() as f64)
}

fn subject(model: &str, tag: &str, g: Option<String>) -> Subject {
    Subject { label: format!("seagent:{model} {tag}"), kind: SubjectKind::Seagent { model: model.into(), harness: super::run::Harness::Auto, guidelines: g, role: None } }
}

/// One with/without comparison: a model, a set of guidelines and how to run it.
pub struct Compare<'a> {
    pub model: &'a str,
    /// Label of the guidelines (preset id or pack slug).
    pub name: &'a str,
    pub text: &'a str,
    /// Ablation units (rule lines of `text`).
    pub rules: &'a [String],
    /// `both`, `with` or `without`.
    pub mode: &'a str,
    /// A rule whose removal drops the score by no more than this is a deletion candidate.
    pub threshold: f64,
    /// Where ablation runs go (None = no ablation).
    pub ablation_root: Option<&'a Path>,
}

/// With / without (and optional ablation) for one set of guidelines over `tasks`.
/// Returns the per-guidelines JSON block; attempts go to `r`'s results.
pub fn compare_guidelines(r: &Runner, tasks: &[Task], c: &Compare) -> Result<Value, String> {
    let (model, name, text, rules, mode, threshold, ablation_root) = (c.model, c.name, c.text, c.rules, c.mode, c.threshold, c.ablation_root);
    let with = subject(model, &format!("+{name}"), Some(text.to_string()));
    let without = subject(model, &format!("-{name}"), Some(NEUTRAL.to_string()));
    let mut subs = vec![];
    if mode != "without" {
        subs.push(with.clone());
    }
    if mode != "with" {
        subs.push(without.clone());
    }
    let res = r.run_more(tasks, &subs)?;
    let (sw, so) = (mean_score(&res, &with.label), mean_score(&res, &without.label));
    let mut block = json!({
        "guidelines": name, "model": model, "questions": tasks.len(),
        "with": sw, "without": so,
        "delta": match (sw, so) { (Some(a), Some(b)) => json!(a - b), _ => Value::Null },
        "guideline_tokens": (text.chars().count() as u64).div_ceil(4),
    });
    if let (Some(root), Some(full)) = (ablation_root, sw) {
        let mut ar = Runner::new(&root.join(super::slug(&format!("{model}-{name}"))), r.base_cfg.clone(), None);
        ar.resolver = r.resolver.clone();
        ar.fake = r.fake.clone();
        ar.judge = r.judge.clone();
        ar.repeat = r.repeat;
        ar.prices = r.prices.clone();
        let _ = std::fs::remove_file(ar.results_path());
        let mut rows = vec![];
        for (i, rule) in rules.iter().enumerate() {
            let s = subject(model, &format!("+{name} -rule{}", i + 1), Some(without_rule(text, rule)));
            let got = ar.run_more(tasks, std::slice::from_ref(&s))?;
            let score = mean_score(&got, &s.label);
            let delta = score.map(|x| full - x);
            rows.push(json!({
                "rule_index": i + 1, "rule": rule, "score": score, "drop": delta,
                "verdict": match delta { Some(d) if d > threshold => "keep", Some(_) => "delete-candidate", None => "error" },
            }));
        }
        block["ablation"] = json!({"baseline": full, "threshold": threshold, "rules": rows});
    }
    Ok(block)
}

/// Markdown for the `roles.json` blocks.
pub fn render_md(blocks: &[Value]) -> String {
    let f = |v: &Value| v.as_f64().map(|x| format!("{x:.3}")).unwrap_or_else(|| "–".into());
    let mut s = String::from("## Role scenarios: with vs without guidelines\n\n| guidelines | model | questions | with | without | Δ | guideline tokens |\n|---|---|---|---|---|---|---|\n");
    for b in blocks {
        s.push_str(&format!("| {} | {} | {} | {} | {} | {} | {} |\n", b["guidelines"].as_str().unwrap_or(""), b["model"].as_str().unwrap_or(""), b["questions"], f(&b["with"]), f(&b["without"]), f(&b["delta"]), b["guideline_tokens"]));
    }
    for b in blocks.iter().filter(|b| b.get("ablation").is_some()) {
        let a = &b["ablation"];
        s.push_str(&format!("\n### Ablation: {} on {} (baseline {}, threshold {})\n\n| # | rule | score without it | drop | verdict |\n|---|---|---|---|---|\n", b["guidelines"].as_str().unwrap_or(""), b["model"].as_str().unwrap_or(""), f(&a["baseline"]), f(&a["threshold"])));
        for r in a["rules"].as_array().cloned().unwrap_or_default() {
            s.push_str(&format!("| {} | {} | {} | {} | {} |\n", r["rule_index"], r["rule"].as_str().unwrap_or("").replace('|', "\\|"), f(&r["score"]), f(&r["drop"]), r["verdict"].as_str().unwrap_or("")));
        }
    }
    s
}

/// Whether a task carries judge points.
#[cfg(test)]
fn has_judge(t: &Task) -> bool {
    t.checks.iter().any(|c| matches!(c, super::Check::Judge { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> Config {
        let mut c = Config::default();
        c.role.dir = super::super::repo_share().join("roles").display().to_string();
        c
    }

    #[test]
    fn with_beats_without_and_ablation_finds_rules_that_do_not_matter() {
        let out = seagent_core::tmp::scratch("seagent-roles");
        let c = cfg();
        let mut r = Runner::new(&out, c.clone(), None);
        r.set_judge("fake/judge").unwrap();
        let (text, rules) = guidelines(&c, "devops").unwrap();
        assert!(text.contains("# Professional conduct") && text.contains("[role:devops]"));
        assert!(rules.len() >= 8, "{rules:?}");
        let qs = questions(&super::super::repo_share().join("evals/roles"), "devops").unwrap();
        assert_eq!(qs.len(), 5);
        assert!(qs.iter().all(has_judge));
        // the shortened ablation: first three questions, every rule
        let ab = out.join("ablation");
        let c = Compare { model: "fake/oracle", name: "devops", text: &text, rules: &rules, mode: "both", threshold: 0.0, ablation_root: Some(&ab) };
        let b = compare_guidelines(&r, &qs[..3], &c).unwrap();
        let (w, wo) = (b["with"].as_f64().unwrap(), b["without"].as_f64().unwrap());
        assert!(w > wo, "with {w} should beat without {wo}");
        let rows = b["ablation"]["rules"].as_array().unwrap();
        assert_eq!(rows.len(), rules.len());
        assert!(rows.iter().any(|x| x["verdict"] == "keep"), "{rows:?}");
        assert!(rows.iter().any(|x| x["verdict"] == "delete-candidate"), "{rows:?}");
        let md = render_md(&[b]);
        assert!(md.contains("### Ablation: devops") && md.contains("delete-candidate"));
        assert_eq!(without_rule("a\n- x\n- y\n- x", "x"), "a\n- y\n- x");
    }

    #[test]
    fn provenance_extends_the_judge_reference() {
        let c = cfg();
        let d = seagent_core::tmp::scratch("seagent-prov");
        std::fs::write(d.join("systems-administration.json"), json!([{"rule_index": 1, "rule": "R1", "from": [{"name": "N", "method": "M1", "sources": ["https://example.org/a"]}]}]).to_string()).unwrap();
        let mut qs = vec![Task { id: "q".into(), prompt: "p".into(), reference: Some("base".into()), ..Default::default() }];
        add_provenance(&mut qs, &c, "devops", &d);
        let r = qs[0].reference.as_deref().unwrap();
        assert!(r.starts_with("base") && r.contains("- R1 ← M1 (https://example.org/a)"), "{r}");
    }
}
