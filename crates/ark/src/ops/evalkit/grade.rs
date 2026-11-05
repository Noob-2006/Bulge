//! Scoring: deterministic checks and the judge model.
//!
//! A task's score is the weighted mean of its checks (a judge check weighs as much as all its
//! points together count as one check); it passes when every check passes. The judge is any
//! `provider/model`; `fake/*` judges score offline by rubric keywords.

use super::{fake, Check, Point, Task};
use ark_core::{Cancel, Message, ModelRequest, Provider, SystemSegment, Usage};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckResult {
    pub kind: String,
    pub pass: bool,
    pub score: f64,
    pub detail: String,
    /// Judge tokens (judge checks only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge_usage: Option<Usage>,
}

/// The judge model of a run.
#[derive(Clone)]
pub struct Judge {
    pub model: String,
    /// None for `fake/*` (keyword scoring, no call).
    pub provider: Option<Arc<dyn Provider>>,
}

impl Judge {
    pub fn is_offline(&self) -> bool {
        self.provider.is_none() || fake::is_fake(&self.model)
    }
}

/// Runs a command where the attempt happened (host workdir or task container): (output, exit).
pub type Exec<'a> = &'a dyn Fn(&str) -> (String, i32);

/// The answer GAIA-style prompts end with (`FINAL ANSWER: x`), else the whole reply trimmed.
pub fn final_answer(text: &str) -> String {
    let lower = text.to_lowercase();
    match lower.rfind("final answer:") {
        Some(i) => text[i + "final answer:".len()..].lines().next().unwrap_or("").trim().to_string(),
        None => text.trim().to_string(),
    }
}

fn norm_str(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace() && !c.is_ascii_punctuation()).flat_map(char::to_lowercase).collect()
}

fn as_number(s: &str) -> Option<f64> {
    let t: String = s.chars().filter(|c| !matches!(c, '$' | '%' | ',' | ' ')).collect();
    t.parse::<f64>().ok()
}

/// GAIA's quasi-exact match (the official scorer's rules): numbers compare as numbers after
/// dropping `$ % ,`; comma/semicolon lists compare element-wise; strings compare without
/// whitespace, punctuation and case.
pub fn gaia_match(answer: &str, expected: &str) -> bool {
    if expected.trim().parse::<f64>().is_ok() {
        return match as_number(answer) {
            Some(a) => (a - expected.trim().parse::<f64>().unwrap_or(f64::NAN)).abs() < 1e-9,
            None => false,
        };
    }
    if expected.contains([',', ';']) {
        let split = |s: &str| s.split([',', ';']).map(|p| p.trim().to_string()).collect::<Vec<_>>();
        let (a, e) = (split(answer), split(expected));
        return a.len() == e.len() && a.iter().zip(&e).all(|(x, y)| match (as_number(y), as_number(x)) {
            (Some(ny), Some(nx)) => (nx - ny).abs() < 1e-9,
            _ => norm_str(x) == norm_str(y),
        });
    }
    norm_str(answer) == norm_str(expected)
}

fn has(hay: &str, needle: &str, ic: bool) -> bool {
    if ic {
        hay.to_lowercase().contains(&needle.to_lowercase())
    } else {
        hay.contains(needle)
    }
}

/// Keyword scoring (the offline judge): a point is met when any keyword appears.
pub fn keyword_points(answer: &str, points: &[Point]) -> Vec<bool> {
    points.iter().map(|p| p.keywords.iter().any(|k| has(answer, k, true))).collect()
}

fn weighted(points: &[Point], met: &[bool]) -> f64 {
    let total: f64 = points.iter().map(|p| p.weight).sum();
    if total <= 0.0 {
        return 0.0;
    }
    // `+ 0.0`: an empty float sum is -0.0
    (points.iter().zip(met).filter(|(_, m)| **m).map(|(p, _)| p.weight).sum::<f64>() + 0.0) / total
}

pub const JUDGE_SYSTEM: &str = "You are a strict, fair evaluation judge. Score the candidate answer against each rubric point independently. A point is met only when the answer clearly does what the point describes; restating the question, vague intentions or contradicting advice do not count. Use the reference material when given: it records how expert practitioners handle the situation. Reply with JSON only: {\"points\":[{\"i\":1,\"met\":true,\"why\":\"…\"}],\"summary\":\"…\"}.";

pub fn judge_prompt(task: &Task, answer: &str, points: &[Point]) -> String {
    let rubric: Vec<String> = points.iter().enumerate().map(|(i, p)| format!("{}. {} (weight {})", i + 1, p.text, p.weight)).collect();
    format!(
        "## Question\n{}\n\n## Reference material\n{}\n\n## Rubric points\n{}\n\n## Candidate answer\n{}\n",
        task.prompt,
        task.reference.as_deref().unwrap_or("(none)"),
        rubric.join("\n"),
        answer
    )
}

/// First `{ … }` object in a reply (models wrap JSON in prose or fences).
pub fn extract_json(text: &str) -> Option<Value> {
    let (s, e) = (text.find('{')?, text.rfind('}')?);
    if e <= s {
        return None;
    }
    serde_json::from_str(&text[s..=e]).ok()
}

fn judge_check(task: &Task, answer: &str, points: &[Point], pass_at: f64, judge: Option<&Judge>) -> CheckResult {
    let fail = |d: String| CheckResult { kind: "judge".into(), pass: false, score: 0.0, detail: d, judge_usage: None };
    let Some(j) = judge else {
        return fail("no judge model (pass --judge provider/model, or fake/judge offline)".into());
    };
    let (met, usage, why) = match (&j.provider, j.is_offline()) {
        (_, true) | (None, _) => (keyword_points(answer, points), None, "keyword judge".to_string()),
        (Some(p), false) => {
            let req = ModelRequest {
                model: j.model.split_once('/').map(|(_, m)| m.to_string()).unwrap_or_else(|| j.model.clone()),
                system: vec![SystemSegment { id: "judge".into(), text: JUDGE_SYSTEM.into(), cache: false }],
                messages: vec![Message::user(judge_prompt(task, answer, points))],
                max_tokens: 2048,
                temperature: Some(0.0),
                ..Default::default()
            };
            match p.complete(&req, &mut |_| {}, &Cancel::new()) {
                Err(e) => return fail(format!("judge call failed: {e}")),
                Ok(r) => {
                    let text = r.message.text();
                    let Some(v) = extract_json(&text) else {
                        return CheckResult { judge_usage: Some(r.usage), ..fail(format!("judge reply is not JSON: {}", text.chars().take(200).collect::<String>())) };
                    };
                    let mut met = vec![false; points.len()];
                    for row in v["points"].as_array().cloned().unwrap_or_default() {
                        if let Some(i) = row["i"].as_u64().map(|i| i as usize).filter(|i| (1..=points.len()).contains(i)) {
                            met[i - 1] = row["met"].as_bool().unwrap_or(false);
                        }
                    }
                    (met, Some(r.usage), v["summary"].as_str().unwrap_or("").to_string())
                }
            }
        }
    };
    let score = weighted(points, &met);
    let missed: Vec<String> = points.iter().zip(&met).filter(|(_, m)| !**m).map(|(p, _)| p.text.clone()).collect();
    CheckResult {
        kind: "judge".into(),
        pass: score + 1e-9 >= pass_at,
        score,
        detail: format!("{}/{} points ({why}){}", met.iter().filter(|m| **m).count(), points.len(), if missed.is_empty() { String::new() } else { format!("; missed: {}", missed.join(" | ")) }),
        judge_usage: usage,
    }
}

/// Score one attempt. `exec` runs command checks where the attempt ran; `workdir` serves file
/// checks (None for chat tasks).
pub fn grade(task: &Task, answer: &str, workdir: Option<&Path>, exec: Option<Exec>, judge: Option<&Judge>) -> (Vec<CheckResult>, f64, bool) {
    let mut out = vec![];
    for c in &task.checks {
        let r = |pass: bool, detail: String| CheckResult { kind: c.kind().into(), pass, score: if pass { 1.0 } else { 0.0 }, detail, judge_usage: None };
        out.push(match c {
            Check::Exact { expected, normalize } => {
                let got = final_answer(answer);
                let ok = match normalize.as_deref() {
                    Some("gaia") => gaia_match(&got, expected),
                    Some("plain") | None => got.trim() == expected.trim(),
                    Some(o) => {
                        out.push(r(false, format!("unknown normalize `{o}`")));
                        continue;
                    }
                };
                r(ok, format!("answer `{}` vs expected `{expected}`", got.chars().take(120).collect::<String>()))
            }
            Check::Contains { all, any, none, ignore_case } => {
                let miss: Vec<&String> = all.iter().filter(|s| !has(answer, s, *ignore_case)).collect();
                let any_ok = any.is_empty() || any.iter().any(|s| has(answer, s, *ignore_case));
                let bad: Vec<&String> = none.iter().filter(|s| has(answer, s, *ignore_case)).collect();
                r(miss.is_empty() && any_ok && bad.is_empty(), format!("missing {miss:?}; any-of met: {any_ok}; forbidden present {bad:?}"))
            }
            Check::Regex { pattern } => match regex::Regex::new(pattern) {
                Ok(re) => r(re.is_match(answer), format!("/{pattern}/")),
                Err(e) => r(false, format!("bad regex: {e}")),
            },
            Check::Command { cmd, expect_exit } => match exec {
                None => r(false, "command check needs a working directory (agent task)".into()),
                Some(x) => {
                    let (o, code) = x(cmd);
                    let tail: String = o.chars().rev().take(400).collect::<Vec<_>>().into_iter().rev().collect();
                    r(code == *expect_exit, format!("`{cmd}` exit {code} (want {expect_exit}): {}", tail.trim()))
                }
            },
            Check::File { path, text } => match workdir.map(|w| w.join(path)) {
                None => r(false, "file check needs a working directory".into()),
                Some(p) => {
                    let body = std::fs::read_to_string(&p).unwrap_or_default();
                    r(body.contains(text.as_str()), format!("{path} contains `{text}`"))
                }
            },
            Check::Judge { points, pass_at } => judge_check(task, answer, points, pass_at.unwrap_or(0.6), judge),
        });
    }
    if out.is_empty() {
        return (out, 0.0, false);
    }
    let score = out.iter().map(|c| c.score).sum::<f64>() / out.len() as f64;
    let pass = out.iter().all(|c| c.pass);
    (out, score, pass)
}

/// Host command runner for a working directory.
pub fn host_exec(dir: &Path, timeout: u64) -> impl Fn(&str) -> (String, i32) + '_ {
    move |cmd: &str| {
        let mut c = std::process::Command::new("bash");
        c.arg("-c").arg(cmd).current_dir(dir);
        match super::run::capture(c, std::time::Duration::from_secs(timeout)) {
            Ok(x) => x,
            Err(e) => (e, -1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gaia_rules_and_final_answer() {
        assert_eq!(final_answer("thinking…\nFINAL ANSWER: 1,234 \nbye"), "1,234");
        assert!(gaia_match("1234", "1234"));
        assert!(gaia_match("$1,234", "1234"));
        assert!(!gaia_match("1235", "1234"));
        assert!(gaia_match("Paris ", "paris"));
        assert!(gaia_match("St. Louis", "St Louis"));
        assert!(gaia_match("a, b ,c", "a,b,c"));
        assert!(!gaia_match("a,b", "a,b,c"));
        assert!(gaia_match("3, 4.0", "3,4"));
    }

    #[test]
    fn checks_score_and_pass() {
        let d = ark_core::tmp::scratch("ark-grade");
        std::fs::write(d.join("out.txt"), "hello world").unwrap();
        let t = Task {
            id: "t".into(),
            prompt: "q".into(),
            checks: vec![
                Check::Exact { expected: "42".into(), normalize: None },
                Check::Contains { all: vec!["ROOT".into()], any: vec![], none: vec!["rm -rf".into()], ignore_case: true },
                Check::Command { cmd: "test -f out.txt".into(), expect_exit: 0 },
                Check::File { path: "out.txt".into(), text: "world".into() },
                Check::Judge { points: vec![Point { text: "a".into(), keywords: vec!["root".into()], weight: 1.0 }, Point { text: "b".into(), keywords: vec!["nope".into()], weight: 3.0 }], pass_at: None },
            ],
            ..Default::default()
        };
        let ex = host_exec(&d, 10);
        let j = Judge { model: "fake/judge".into(), provider: None };
        let (c, score, pass) = grade(&t, "root cause found\nFINAL ANSWER: 42", Some(&d), Some(&ex), Some(&j));
        assert_eq!(c.iter().map(|c| c.pass).collect::<Vec<_>>(), vec![true, true, true, true, false]);
        assert!((c[4].score - 0.25).abs() < 1e-9, "{:?}", c[4]);
        assert!(!pass && (score - (4.25 / 5.0)).abs() < 1e-9);
        // no judge configured → the judge check fails loudly instead of passing
        let (c, _, _) = grade(&t, "x", None, None, None);
        assert!(c[2].detail.contains("working directory") && c[4].detail.contains("no judge"));
        assert_eq!(extract_json("sure: ```{\"a\": 1}```").unwrap()["a"], 1);
    }
}
