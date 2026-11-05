//! Auxiliary-model helpers: the triage specifier (one-liner -> spec), the decomposer
//! (triage task -> routed task graph) and the goal-mode judge. All go through
//! `Kernel::sample` with the aux model; parsing is lenient and expected failures
//! come back as `ok = false`, never a panic.

use super::ops::{self, Child};
use super::{store, KanbanConfig};
use crate::kernel::Kernel;
use ark_core::{Cancel, Message};
use serde_json::{json, Value};
use std::path::Path;

pub const SPECIFY_SYSTEM: &str = r#"You are the Kanban triage specifier for the ark agent board.
A user dropped a rough idea into the Triage column. Your job is to turn it
into a concrete, actionable task spec that an autonomous worker can pick up
and execute without further clarification.

Output a single JSON object with exactly two keys:

  {
    "title": "<tightened task title, <= 80 chars, imperative voice>",
    "body":  "<multi-line spec, see structure below>"
  }

The body MUST include these sections, each prefixed with a bold markdown
heading, in this order:

  **Goal** — one sentence, user-facing outcome.
  **Approach** — 2-5 bullets on how a worker should tackle it.
  **Acceptance criteria** — checklist of concrete, verifiable conditions.
  **Out of scope** — short list of things NOT to touch (omit if nothing
      obvious; never invent scope creep).

Rules:
  - Keep the tightened title close in meaning to the original idea — do
    NOT invent a different project.
  - If the original idea is already detailed, preserve its substance and
    just reformat into the sections above.
  - Never add invented requirements the user didn't hint at.
  - No preamble, no closing remarks, no code fences around the JSON.
  - Output only the JSON object and nothing else.
"#;

pub const DECOMPOSE_SYSTEM: &str = r#"You are the Kanban decomposer for the ark agent board.

A user dropped a rough idea into the Triage column. Your job is to break it
into a small graph of concrete child tasks and route each one to the best-
matching profile from the available roster.

You will be given:
  - The original task title and body
  - The list of available profiles (each with name + description)
  - The fallback "default_assignee" used when no profile fits

Output a single JSON object with this exact shape:

  {
    "fanout": true,
    "rationale": "<one sentence on why this decomposition>",
    "tasks": [
      {
        "title": "<concrete task title, imperative voice, <= 80 chars>",
        "body":  "<detailed spec for the worker on this child task>",
        "assignee": "<profile name from the roster, or null for default>",
        "parents": [<int>, ...]
      },
      ...
    ]
  }

Rules:
  - "parents" is a list of INDICES (0-based) into this same "tasks" list,
    expressing actual data dependencies. Tasks with no parents run in
    PARALLEL. Tasks with parents wait until every parent completes.
  - Prefer parallelism. If two tasks can be done independently, give
    them no parents so the dispatcher fans them out at once.
  - Use 2-6 tasks for normal work. Don't create 20 tiny tasks. Don't
    cram everything into 1 task.
  - Pick assignees from the roster by matching the task to the profile's
    DESCRIPTION (not just the name). When nothing matches well, use null
    and the system will route to the default_assignee.
  - Each child task body is what a fresh worker will read with no other
    context — be specific about goal, approach, and acceptance criteria.

When the task is genuinely a single unit of work (no useful decomposition),
return:

  {
    "fanout": false,
    "rationale": "<one sentence>",
    "title": "<tightened title>",
    "body":  "<concrete spec for a single worker>",
    "assignee": "<profile name from the roster, or null for default>"
  }

No preamble, no closing remarks, no code fences. Output only the JSON object.
"#;

pub const JUDGE_SYSTEM: &str = r#"You judge whether an autonomous agent has finished a task.
Given the task (goal) and the agent's latest response, answer with a single JSON object:
  {"verdict": "done" | "continue" | "blocked", "reason": "<one sentence>"}
"done": the response shows the goal's acceptance criteria are verifiably met.
"continue": work remains that the agent can still do.
"blocked": the goal cannot be achieved by the agent (missing access, contradictory requirements).
Output only the JSON object."#;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Outcome {
    pub task_id: String,
    pub ok: bool,
    pub reason: String,
    pub fanout: bool,
    pub child_ids: Vec<String>,
    pub new_title: Option<String>,
}

impl Outcome {
    fn fail(id: &str, reason: impl Into<String>) -> Outcome {
        Outcome { task_id: id.into(), ok: false, reason: reason.into(), ..Default::default() }
    }
    pub fn to_json(&self) -> Value {
        json!({"task_id": self.task_id, "ok": self.ok, "reason": self.reason, "fanout": self.fanout, "child_ids": self.child_ids, "new_title": self.new_title})
    }
}

/// Strip code fences and take the first `{` .. last `}`; None unless it is an object.
pub fn extract_json(raw: &str) -> Option<serde_json::Map<String, Value>> {
    let s = raw.trim();
    let s = s.strip_prefix("```json").or_else(|| s.strip_prefix("```")).unwrap_or(s);
    let s = s.strip_suffix("```").unwrap_or(s);
    let (a, b) = (s.find('{')?, s.rfind('}')?);
    if b <= a {
        return None;
    }
    serde_json::from_str::<Value>(&s[a..=b]).ok()?.as_object().cloned()
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.into()
    } else {
        s.chars().take(n - 1).collect::<String>() + "…"
    }
}

fn nonblank(v: Option<&Value>) -> Option<String> {
    v.and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()).map(String::from)
}

fn call(k: &Kernel, system: &str, user: String, max_tokens: u32) -> Result<String, String> {
    let (m, _, _) = k.sample(None, system, vec![Message::user(user)], vec![], max_tokens, &Cancel::new()).map_err(|e| format!("LLM error: {e}"))?;
    Ok(m.text())
}

fn load_triage(data: &Path, slug: &str, id: &str) -> Result<super::store::Task, String> {
    let b = store::read_board(data, slug)?;
    let t = b.task(id).cloned().ok_or("unknown task id")?;
    if t.status != "triage" {
        return Err(format!("task is not in triage (status={:?})", t.status));
    }
    Ok(t)
}

fn prompt_fields(t: &super::store::Task) -> String {
    format!("Task id: {}\nCurrent title: {}\nCurrent body:\n{}\n", t.id, truncate(&t.title, 400), truncate(t.body.as_deref().unwrap_or("(no body)"), 4000))
}

/// Specify one triage task and promote it to todo. Malformed JSON keeps the whole reply as the body.
pub fn specify_task(k: &Kernel, data: &Path, slug: &str, cfg: &KanbanConfig, id: &str, author: Option<&str>) -> Outcome {
    let t = match load_triage(data, slug, id) {
        Ok(t) => t,
        Err(e) => return Outcome::fail(id, e),
    };
    let raw = match call(k, SPECIFY_SYSTEM, prompt_fields(&t), 6000) {
        Ok(r) => r.trim().to_string(),
        Err(e) => return Outcome::fail(id, e),
    };
    let (title, body) = match extract_json(&raw) {
        Some(p) => (nonblank(p.get("title")).map(|s| s.trim().to_string()), nonblank(p.get("body"))),
        None if raw.is_empty() => return Outcome::fail(id, "LLM returned an empty response"),
        None => (None, Some(raw)),
    };
    if title.is_none() && body.is_none() {
        return Outcome::fail(id, "LLM response missing title and body");
    }
    let author = author.unwrap_or("specifier");
    match store::with_board(data, slug, |b| ops::specify_triage(b, id, title.as_deref(), body.as_deref(), None, Some(author), cfg.failure_limit)) {
        Ok(true) => Outcome { task_id: id.into(), ok: true, reason: "specified".into(), new_title: title, ..Default::default() },
        Ok(false) => Outcome::fail(id, "task moved out of triage before promotion"),
        Err(e) => Outcome::fail(id, e),
    }
}

/// Explicit profile, else the root's own assignee, else the default profile name.
fn route(cfg: &KanbanConfig, explicit: &str, root: Option<&str>) -> String {
    for c in [explicit, root.unwrap_or("")] {
        let c = c.trim();
        if !c.is_empty() && cfg.profile_exists(c) {
            return c.to_string();
        }
    }
    cfg.identity.clone()
}

fn roster(cfg: &KanbanConfig) -> (String, Vec<String>) {
    if cfg.profiles.is_empty() {
        return ("  (no profiles configured — any assignee name is spawnable with the default model)".into(), vec![]);
    }
    let lines: Vec<String> = cfg.profiles.iter().map(|(n, p)| if p.description.trim().is_empty() { format!("  - {n} ⚠ undescribed: (no description; profile named {n:?})") } else { format!("  - {n}: {}", p.description.trim()) }).collect();
    (lines.join("\n"), cfg.profiles.keys().cloned().collect())
}

fn pick(a: Option<&Value>, default: &str, valid: &[String]) -> String {
    match a.and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) if valid.is_empty() || valid.iter().any(|v| v == s) => s.to_string(),
        _ => default.to_string(),
    }
}

/// Decompose a triage task into a graph of routed children (or, with `fanout=false`,
/// tighten it like `specify`).
pub fn decompose_task(k: &Kernel, data: &Path, slug: &str, cfg: &KanbanConfig, id: &str, author: Option<&str>) -> Outcome {
    let t = match load_triage(data, slug, id) {
        Ok(t) => t,
        Err(e) => return Outcome::fail(id, e),
    };
    let meta = super::boards::read_meta(data, slug);
    let orchestrator = route(cfg, meta.orchestration.orchestrator_profile.as_deref().unwrap_or(&cfg.orchestrator_profile), t.assignee.as_deref());
    let default_assignee = route(cfg, meta.orchestration.default_assignee.as_deref().unwrap_or(&cfg.default_assignee), t.assignee.as_deref());
    let (roster_text, valid) = roster(cfg);
    let user = format!("Task id: {}\nTitle: {}\nBody:\n{}\n\nAvailable profiles (assignees you may pick from):\n{roster_text}\n\nDefault assignee (used when no profile fits a task): {default_assignee}\n", t.id, truncate(&t.title, 400), truncate(t.body.as_deref().unwrap_or("(no body)"), 4000));
    let raw = match call(k, DECOMPOSE_SYSTEM, user, 4000) {
        Ok(r) => r,
        Err(e) => return Outcome::fail(id, e),
    };
    let Some(p) = extract_json(&raw) else { return Outcome::fail(id, "LLM returned malformed JSON") };
    let author = author.unwrap_or("decomposer");
    if p.get("fanout").and_then(|v| v.as_bool()) != Some(true) {
        let (title, body) = (nonblank(p.get("title")).map(|s| s.trim().to_string()), nonblank(p.get("body")));
        if title.is_none() && body.is_none() {
            return Outcome::fail(id, "decomposer returned fanout=false with no title/body");
        }
        let assignee = t.assignee.is_none().then(|| pick(p.get("assignee"), &default_assignee, &valid));
        return match store::with_board(data, slug, |b| ops::specify_triage(b, id, title.as_deref(), body.as_deref(), assignee.as_deref(), Some(author), cfg.failure_limit)) {
            Ok(true) => Outcome { task_id: id.into(), ok: true, reason: "single task (no fanout)".into(), new_title: title, ..Default::default() },
            Ok(false) => Outcome::fail(id, "task moved out of triage before promotion"),
            Err(e) => Outcome::fail(id, e),
        };
    }
    let Some(tasks) = p.get("tasks").and_then(|v| v.as_array()).filter(|a| !a.is_empty()) else {
        return Outcome::fail(id, "decomposer returned fanout=true with empty tasks list");
    };
    let mut children = vec![];
    for (i, e) in tasks.iter().enumerate() {
        let Some(o) = e.as_object() else { return Outcome::fail(id, format!("tasks[{i}] is not an object")) };
        let Some(title) = nonblank(o.get("title")) else { return Outcome::fail(id, format!("tasks[{i}].title is missing or empty")) };
        let parents = o.get("parents").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_u64()).map(|x| x as usize).filter(|x| *x < tasks.len() && *x != i).collect()).unwrap_or_default();
        children.push(Child { title: title.trim().chars().take(200).collect(), body: Some(o.get("body").and_then(|v| v.as_str()).unwrap_or("").trim().to_string()), assignee: Some(pick(o.get("assignee"), &default_assignee, &valid)), parents, ..Default::default() });
    }
    match store::with_board(data, slug, |b| ops::decompose_triage(b, id, Some(&orchestrator), &children, Some(author), cfg.auto_promote_children, cfg.failure_limit)) {
        Ok(Some(ids)) => Outcome { task_id: id.into(), ok: true, reason: format!("decomposed into {} children", ids.len()), fanout: true, child_ids: ids, ..Default::default() },
        Ok(None) => Outcome::fail(id, "task already decomposed or moved out of triage"),
        Err(e) => Outcome::fail(id, format!("DB rejected graph: {e}")),
    }
}

/// `(verdict, reason)`: done / continue / blocked. Err when the judge is unreachable
/// (callers fail open).
pub fn judge_goal(k: &Kernel, goal: &str, last_response: &str) -> Result<(String, String), String> {
    let raw = call(k, JUDGE_SYSTEM, format!("GOAL:\n{}\n\nLATEST RESPONSE:\n{}", truncate(goal, 6000), truncate(last_response, 6000)), 400)?;
    let p = extract_json(&raw).ok_or("judge returned malformed JSON")?;
    let v = p.get("verdict").and_then(|v| v.as_str()).unwrap_or("continue").to_lowercase();
    let v = if matches!(v.as_str(), "done" | "continue" | "blocked") { v } else { "continue".into() };
    Ok((v, p.get("reason").and_then(|v| v.as_str()).unwrap_or("").to_string()))
}

#[cfg(test)]
mod tests;
