//! `graph`: LangGraph-style durable state graphs — nodes, conditional edges, channels with
//! reducers, a checkpoint after every superstep, `interrupt` (approval / input) and resume,
//! and time travel from any checkpoint.
//!
//! Where [`super::lobster`] runs a fixed sequence of pipeline stages with a resume token, a
//! graph is a state machine: `state` is a map of *channels* (each with a reducer), `nodes` are
//! steps that only *declare* writes, and `edges` (static or conditional) pick the next batch.
//! This is LangGraph's execution model (`langgraph/pregel/_loop.py`: `tick()` runs a batch,
//! `after_tick()` applies channel writes and checkpoints), ported to what seagent needs — see
//! `docs/ecosystem/graph-flows.md` for the comparison against `lobster` and the upstream
//! implementation.
//!
//! Design constraints from the plan (§0): an approval is only asked where a **gate** node
//! says so; everything else runs headless, and an unanswered gate is *resumable*, not fatal
//! (the checkpoint holds the whole state, so the operator can answer hours later, or resume
//! from an earlier checkpoint and branch).
//!
//! ```json
//! {"name":"triage",
//!  "state":{"notes":{"reducer":"append"},"round":{"reducer":"sum","default":0}},
//!  "nodes":{
//!    "research":{"kind":"llm","prompt":"Summarise {{input.question}}","schema":{"type":"object"},"save":"brief"},
//!    "more":{"kind":"set","state":{"round":1,"notes":"{{brief}}"}},
//!    "ship":{"kind":"gate","mode":"approval","prompt":"Send this?","save":"ok"}},
//!  "edges":[{"from":"START","to":"research"},{"from":"research","to":"more"},
//!           {"from":"more","router":[{"when":"state.round < 3","to":"research"}],"default":"ship"},
//!           {"from":"ship","to":"END"}]}
//! ```
//!
//! Node kinds: `run` (shell), `tool` (an seagent tool), `llm` (`llm-task`), `set` (pure state
//! writes), `gate` (interrupt for approval or input), `noop`. Every node writes its result to
//! the `save` channel (default `result`); `set` writes the channels it names.
//!
//! Checkpoints live in `<data>/surfaces/graph/threads/<thread>/<step>-<id>.json`, each with its
//! `parent` and the graph it belongs to, so `resume` needs nothing else.

use super::{llm_task, now_ms, yaml, Env};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn d_timeout() -> u64 {
    30_000
}
fn d_steps() -> u64 {
    64
}
fn d_stdout() -> u64 {
    512_000
}
fn d_deny() -> Vec<String> {
    vec!["gateway".into(), "lobster".into(), "graph-flow".into()]
}

/// `[surfaces.graph]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GraphConfig {
    /// Tools a `tool` node may call. Empty = every tool except `tool_deny`.
    pub tool_allow: Vec<String>,
    /// Tools a `tool` node may never call. Default ["gateway", "lobster", "graph-flow"].
    #[serde(default = "d_deny")]
    pub tool_deny: Vec<String>,
    /// Supersteps one run may take before it stops with an error. Default 64.
    #[serde(default = "d_steps")]
    pub max_steps: u64,
    /// Default per-node timeout. Default 30000 ms.
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    /// Cap on one node's captured output. Default 512000 bytes.
    #[serde(default = "d_stdout")]
    pub max_stdout_bytes: u64,
}

impl Default for GraphConfig {
    fn default() -> Self {
        GraphConfig { tool_allow: vec![], tool_deny: d_deny(), max_steps: d_steps(), timeout_ms: d_timeout(), max_stdout_bytes: d_stdout() }
    }
}

fn allowed(cfg: &GraphConfig, name: &str) -> bool {
    if cfg.tool_allow.is_empty() {
        !cfg.tool_deny.iter().any(|d| seagent_plugin::glob_match(d, name))
    } else {
        cfg.tool_allow.iter().any(|a| seagent_plugin::glob_match(a, name)) && !cfg.tool_deny.iter().any(|d| seagent_plugin::glob_match(d, name))
    }
}

// ───────────────────────── the graph ─────────────────────────

/// How a channel folds a batch of writes (LangGraph's channel types).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reducer {
    /// Last write wins (LangGraph `LastValue`).
    Last,
    /// Collect into a list (`add` on a list channel): scalars are wrapped, lists flattened.
    Append,
    /// Concatenate strings or lists (`add` on a str channel).
    Concat,
    /// Numeric sum, or concatenation for lists.
    Sum,
    /// Shallow-merge objects.
    Merge,
    /// The first write wins (LangGraph `EphemeralValue` for inputs).
    First,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Channel {
    pub reducer: Reducer,
    pub default: Value,
}
impl Default for Channel {
    fn default() -> Self {
        Channel { reducer: Reducer::Last, default: Value::Null }
    }
}

/// One node. Unknown keys are refused when the spec is parsed, so a typo cannot silently
/// turn a `run` node into a no-op.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Node {
    /// `run` | `tool` | `llm` | `set` | `gate` | `noop`.
    pub kind: String,
    /// `run`: a shell command (`sh -c`) or, with `argv`, an exact argv.
    pub cmd: Option<String>,
    pub argv: Vec<String>,
    /// `run`: stdin (templated).
    pub stdin: Option<String>,
    /// `tool`: name and arguments (templated strings; `{{path}}` alone keeps the JSON type).
    pub tool: Option<String>,
    pub args: Option<Value>,
    /// `llm`: prompt, optional JSON schema, model overrides.
    pub prompt: Option<String>,
    pub schema: Option<Value>,
    pub model: Option<String>,
    /// `gate`: `approval` (yes/no) or `input` (structured answer).
    pub mode: Option<String>,
    /// `gate`: what the operator is asked.
    pub message: Option<String>,
    /// Channel this node's result is written to. Default `result`.
    pub save: Option<String>,
    /// `set`: channels to write (templated).
    pub state: Option<Map<String, Value>>,
    /// `run`/`tool`/`llm`: parse the result as JSON before saving.
    pub save_json: bool,
    /// `run`: working directory inside the workspace.
    pub cwd: Option<String>,
    pub timeout_ms: Option<u64>,
    /// `fail` (default) or `continue` (record the error in `error` and move on).
    pub on_error: Option<String>,
    /// Description shown by `explain`/`status`.
    pub description: Option<String>,
}

/// A conditional edge: rules are tried in order, then `default` (absent = no edge).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rule {
    #[serde(rename = "when")]
    pub cond: String,
    pub to: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Edge {
    pub from: String,
    /// Static target. Mutually exclusive with `router`.
    pub to: Option<String>,
    /// Conditional targets.
    pub router: Vec<Rule>,
    pub default: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Graph {
    pub name: String,
    pub state: std::collections::BTreeMap<String, Channel>,
    pub nodes: std::collections::BTreeMap<String, Node>,
    pub edges: Vec<Edge>,
    /// Pause before these nodes run (LangGraph `interrupt_before`).
    pub interrupt_before: Vec<String>,
    /// Pause after these nodes run (LangGraph `interrupt_after`).
    pub interrupt_after: Vec<String>,
}

pub const START: &str = "START";
pub const END: &str = "END";

impl Graph {
    pub fn parse(v: &Value) -> Result<Graph, String> {
        let g: Graph = serde_json::from_value(v.clone()).map_err(|e| format!("graph: {e}"))?;
        g.validate()?;
        Ok(g)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.nodes.is_empty() {
            return Err("graph needs at least one node".into());
        }
        for (name, n) in &self.nodes {
            if name == START || name == END {
                return Err(format!("`{name}` is reserved and cannot be a node"));
            }
            match n.kind.as_str() {
                "run" => {
                    if n.cmd.as_deref().unwrap_or("").trim().is_empty() && n.argv.is_empty() {
                        return Err(format!("node `{name}`: run needs `cmd` or `argv`"));
                    }
                }
                "tool" => {
                    if n.tool.as_deref().unwrap_or("").trim().is_empty() {
                        return Err(format!("node `{name}`: tool needs `tool`"));
                    }
                }
                "llm" => {
                    if n.prompt.as_deref().unwrap_or("").trim().is_empty() {
                        return Err(format!("node `{name}`: llm needs `prompt`"));
                    }
                }
                "set" => {
                    if n.state.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                        return Err(format!("node `{name}`: set needs `state`"));
                    }
                }
                "gate" => {
                    if !matches!(n.mode.as_deref().unwrap_or("approval"), "approval" | "input") {
                        return Err(format!("node `{name}`: gate mode must be approval or input"));
                    }
                }
                "noop" => {}
                other => return Err(format!("node `{name}`: unknown kind `{other}` (run|tool|llm|set|gate|noop)")),
            }
            if let Some(s) = &n.save {
                if !channel_name_ok(s) {
                    return Err(format!("node `{name}`: invalid save channel `{s}`"));
                }
            }
            if let Some(m) = &n.mode {
                if n.kind != "gate" && m != "approval" && m != "input" {
                    return Err(format!("node `{name}`: `mode` is only meaningful on a gate"));
                }
            }
        }
        for e in &self.edges {
            if e.from != START && !self.nodes.contains_key(&e.from) {
                return Err(format!("edge from unknown node `{}`", e.from));
            }
            let targets: Vec<&str> = e.to.iter().map(String::as_str).chain(e.router.iter().map(|r| r.to.as_str())).chain(e.default.as_deref()).collect();
            if targets.is_empty() {
                return Err(format!("edge from `{}` needs `to`, `router` or `default`", e.from));
            }
            if e.to.is_some() && !e.router.is_empty() {
                return Err(format!("edge from `{}`: use either `to` or `router`", e.from));
            }
            for t in targets {
                if t != END && !self.nodes.contains_key(t) {
                    return Err(format!("edge from `{}` targets unknown node `{t}`", e.from));
                }
            }
        }
        for n in self.interrupt_before.iter().chain(&self.interrupt_after) {
            if !self.nodes.contains_key(n) {
                return Err(format!("interrupt on unknown node `{n}`"));
            }
        }
        self.entry()?;
        Ok(())
    }

    /// Nodes the run starts with (every edge out of START).
    pub fn entry(&self) -> Result<Vec<String>, String> {
        let mut v: Vec<String> = Vec::new();
        for e in self.edges.iter().filter(|e| e.from == START) {
            let mut targets = Vec::new();
            if let Some(t) = &e.to {
                targets.push(t.clone());
            }
            for r in &e.router {
                targets.push(r.to.clone());
            }
            if let Some(d) = &e.default {
                targets.push(d.clone());
            }
            for t in targets {
                if t == END {
                    continue;
                }
                if !self.nodes.contains_key(&t) {
                    return Err(format!("START targets unknown node `{t}`"));
                }
                if !v.contains(&t) {
                    v.push(t);
                }
            }
        }
        if v.is_empty() {
            // No START edge: begin at the first node (insertion order is name order).
            v.push(self.nodes.keys().next().cloned().unwrap());
        }
        Ok(v)
    }

    /// Successors of `node` for the current state (LangGraph's conditional edges).
    pub fn next_of(&self, node: &str, state: &Value) -> Result<Vec<String>, String> {
        let mut out: Vec<String> = Vec::new();
        for e in self.edges.iter().filter(|e| e.from == node) {
            let mut picked: Option<String> = None;
            if let Some(t) = &e.to {
                picked = Some(t.clone());
            } else {
                for r in &e.router {
                    if eval_cond(&r.cond, state)? {
                        picked = Some(r.to.clone());
                        break;
                    }
                }
                if picked.is_none() {
                    picked = e.default.clone();
                }
            }
            if let Some(t) = picked.filter(|t| t != END) {
                if !self.nodes.contains_key(&t) {
                    return Err(format!("edge from `{node}` targets unknown node `{t}`"));
                }
                if !out.contains(&t) {
                    out.push(t);
                }
            }
        }
        Ok(out)
    }

    /// The effects this graph may cause (computed before it runs, so seagent's gates judge the
    /// whole flow at once instead of stalling on every node).
    pub fn effects(&self, env: &Env, ctx: &ToolCtx, state: &Value) -> Vec<Effect> {
        let mut e = Vec::new();
        for n in self.nodes.values() {
            match n.kind.as_str() {
                "run" => {
                    let cmd = if n.argv.is_empty() { render(n.cmd.as_deref().unwrap_or(""), state) } else { n.argv.iter().map(|a| render(a, state)).collect::<Vec<_>>().join(" ") };
                    e.push(Effect::Exec { command: cmd });
                }
                "tool" => {
                    let name = n.tool.as_deref().unwrap_or("");
                    if let (Ok(k), true) = (env.kernel(), allowed(&env.cfg.graph, name)) {
                        if let Some(t) = k.tools.iter().find(|t| t.spec().name == name) {
                            e.extend(t.effects(ctx, &render_value(n.args.clone().unwrap_or(Value::Null), state)));
                        }
                    }
                }
                _ => {}
            }
        }
        e
    }
}

fn channel_name_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.') && !s.starts_with(['.', '-'])
}

// ───────────────────────── templating & conditions ─────────────────────────

/// `{{a.b.c}}` → the value at that path (dotted keys index objects, numbers index arrays).
pub fn lookup<'a>(state: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = state;
    for seg in path.split('.').filter(|s| !s.is_empty()) {
        cur = match cur {
            Value::Object(m) => m.get(seg)?,
            Value::Array(a) => a.get(seg.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

fn scalar(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Interpolate `{{path}}` occurrences into a string. A missing path renders empty.
pub fn render(s: &str, state: &Value) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 2..];
        let Some(j) = after.find("}}") else {
            out.push_str(&rest[i..]);
            return out;
        };
        let path = after[..j].trim();
        out.push_str(&lookup(state, path).map(scalar).unwrap_or_default());
        rest = &after[j + 2..];
    }
    out.push_str(rest);
    out
}

/// Render a JSON value: a string that is exactly `{{path}}` keeps the referenced type.
pub fn render_value(v: Value, state: &Value) -> Value {
    match v {
        Value::String(s) => {
            let t = s.trim();
            if let Some(p) = t.strip_prefix("{{").and_then(|x| x.strip_suffix("}}")) {
                return lookup(state, p.trim()).cloned().unwrap_or(Value::Null);
            }
            Value::String(render(&s, state))
        }
        Value::Array(a) => Value::Array(a.into_iter().map(|x| render_value(x, state)).collect()),
        Value::Object(m) => Value::Object(m.into_iter().map(|(k, x)| (k, render_value(x, state))).collect()),
        other => other,
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        Value::String(s) => !s.is_empty() && s != "false" && s != "0",
        Value::Array(a) => !a.is_empty(),
        Value::Object(m) => !m.is_empty(),
    }
}

fn operand(tok: &str, state: &Value) -> Value {
    let t = tok.trim();
    if let Some(p) = t.strip_prefix("{{").and_then(|x| x.strip_suffix("}}")) {
        return lookup(state, p.trim()).cloned().unwrap_or(Value::Null);
    }
    if let Some(p) = t.strip_prefix("state.") {
        return lookup(state, p).cloned().unwrap_or(Value::Null);
    }
    if (t.starts_with('"') && t.ends_with('"') && t.len() >= 2) || (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2) {
        return Value::String(t[1..t.len() - 1].to_string());
    }
    match t {
        "true" => Value::Bool(true),
        "false" => Value::Bool(false),
        "null" => Value::Null,
        _ => match t.parse::<f64>() {
            Ok(f) => json!(f),
            Err(_) => Value::String(t.to_string()),
        },
    }
}

fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

fn cmp_values(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    match (num(a), num(b)) {
        (Some(x), Some(y)) => x.partial_cmp(&y),
        _ => Some(scalar(a).cmp(&scalar(b))),
    }
}

/// `a == b`, `a != b`, `<`, `<=`, `>`, `>=`, `contains(a, b)`, `a in b`, `and` / `or` / `not`,
/// bare truthiness. Deliberately small: a flow condition is not a programming language.
pub fn eval_cond(src: &str, state: &Value) -> Result<bool, String> {
    let src = src.trim();
    if src.is_empty() {
        return Err("empty condition".into());
    }
    for (sep, is_or) in [(" or ", true), (" || ", true), (" and ", false), (" && ", false)] {
        if let Some((l, r)) = split_top(src, sep) {
            let (a, b) = (eval_cond(&l, state)?, eval_cond(&r, state)?);
            return Ok(if is_or { a || b } else { a && b });
        }
    }
    if let Some(rest) = src.strip_prefix("not ").or_else(|| src.strip_prefix('!')) {
        return Ok(!eval_cond(rest, state)?);
    }
    if src.starts_with('(') && src.ends_with(')') {
        return eval_cond(&src[1..src.len() - 1], state);
    }
    for op in ["==", "!=", ">=", "<=", ">", "<"] {
        if let Some((l, r)) = split_op(src, op) {
            let (a, b) = (operand(&l, state), operand(&r, state));
            let o = cmp_values(&a, &b);
            return Ok(match op {
                "==" => a == b || matches!(o, Some(std::cmp::Ordering::Equal)),
                "!=" => !(a == b || matches!(o, Some(std::cmp::Ordering::Equal))),
                ">=" => matches!(o, Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)),
                "<=" => matches!(o, Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)),
                ">" => matches!(o, Some(std::cmp::Ordering::Greater)),
                _ => matches!(o, Some(std::cmp::Ordering::Less)),
            });
        }
    }
    if let Some((l, r)) = split_top(src, " in ") {
        let (a, b) = (operand(&l, state), operand(&r, state));
        return Ok(match &b {
            Value::Array(items) => items.iter().any(|i| *i == a || scalar(i) == scalar(&a)),
            Value::Object(m) => m.contains_key(scalar(&a).trim()),
            Value::String(s) => s.contains(&scalar(&a)),
            _ => false,
        });
    }
    if src.starts_with("contains(") && src.ends_with(')') {
        let inner = &src["contains(".len()..src.len() - 1];
        if let Some((l, r)) = split_top(inner, ",") {
            let (a, b) = (operand(&l, state), operand(&r, state));
            return Ok(match &a {
                Value::Array(items) => items.iter().any(|i| *i == b || scalar(i) == scalar(&b)),
                _ => scalar(&a).contains(&scalar(&b)),
            });
        }
        return Err(format!("contains() needs two arguments: {src}"));
    }
    Ok(truthy(&operand(src, state)))
}

/// Split on `sep` outside quotes and parentheses.
fn split_top(s: &str, sep: &str) -> Option<(String, String)> {
    let (mut depth, mut q, mut i) = (0i32, None::<char>, 0usize);
    let b = s.as_bytes();
    while i + sep.len() <= s.len() {
        let c = b[i] as char;
        match (q, c) {
            (Some(x), _) if c == x => q = None,
            (Some(_), _) => {}
            (None, '"' | '\'') => q = Some(c),
            (None, '(') => depth += 1,
            (None, ')') => depth -= 1,
            (None, _) => {}
        }
        if q.is_none() && depth == 0 && s[i..].starts_with(sep) {
            return Some((s[..i].trim().to_string(), s[i + sep.len()..].trim().to_string()));
        }
        i += 1;
    }
    None
}

fn split_op(s: &str, op: &str) -> Option<(String, String)> {
    split_top(s, &format!(" {op} ")).or_else(|| {
        // `a==b` without spaces, but never inside a quoted literal.
        let (mut q, mut i) = (None::<char>, 0usize);
        let b = s.as_bytes();
        while i + op.len() <= s.len() {
            let c = b[i] as char;
            match (q, c) {
                (Some(x), _) if c == x => q = None,
                (Some(_), _) => {}
                (None, '"' | '\'') => q = Some(c),
                _ => {}
            }
            if q.is_none() && s[i..].starts_with(op) {
                return Some((s[..i].trim().to_string(), s[i + op.len()..].trim().to_string()));
            }
            i += 1;
        }
        None
    })
}

// ───────────────────────── checkpoints ─────────────────────────

/// One durable checkpoint (LangGraph `CheckpointTuple` + `pending_writes` + metadata).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cp {
    pub v: u32,
    pub thread: String,
    pub id: String,
    pub parent: Option<String>,
    pub step: u64,
    pub ts: u64,
    /// `running` | `interrupted` | `done` | `error` | `cancelled`
    pub status: String,
    /// Nodes the next superstep will run (empty when done).
    pub next: Vec<String>,
    pub state: Value,
    /// Present when `status == "interrupted"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub halt: Option<Halt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The graph itself, so a resume needs nothing but the thread id.
    pub graph: Value,
    /// The original input (for `status` and replay).
    pub input: Value,
}

/// Why a run is waiting for a human (the operator answers; the run continues).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Halt {
    /// `approval` | `input` | `before` | `after`.
    pub kind: String,
    /// The node that is paused (`before`/`after` name it; a gate node names itself).
    pub node: String,
    pub prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<Value>,
    /// The state as the operator will see it when deciding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<Value>,
}

pub fn thread_ok(t: &str) -> bool {
    !t.is_empty() && t.len() <= 64 && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') && !t.starts_with(['-', '_'])
}

fn threads_dir(env: &Env) -> PathBuf {
    env.dir.join("graph").join("threads")
}

pub fn list_threads(env: &Env) -> Value {
    let root = threads_dir(env);
    let mut rows = Vec::new();
    let Ok(rd) = std::fs::read_dir(&root) else { return json!({"threads": []}) };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if let Some(cp) = latest_cp(env, &name) {
            rows.push(json!({"thread": name, "checkpoint": cp.id, "step": cp.step, "status": cp.status, "next": cp.next, "ts": cp.ts, "halt": cp.halt, "error": cp.error}));
        }
    }
    rows.sort_by(|a, b| b["ts"].as_u64().unwrap_or(0).cmp(&a["ts"].as_u64().unwrap_or(0)));
    json!({"threads": rows})
}

fn cp_dir(env: &Env, thread: &str) -> Result<PathBuf, String> {
    if !thread_ok(thread) {
        return Err(format!("invalid thread id `{thread}` (a-z, 0-9, -, _; ≤64)"));
    }
    Ok(threads_dir(env).join(thread))
}

fn latest_cp(env: &Env, thread: &str) -> Option<Cp> {
    let Ok(d) = cp_dir(env, thread) else { return None };
    let pointer = std::fs::read_to_string(d.join("latest.json")).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok())?;
    let id = pointer["id"].as_str()?;
    load_cp(env, thread, id).ok()
}

pub fn load_cp(env: &Env, thread: &str, id: &str) -> Result<Cp, String> {
    let d = cp_dir(env, thread)?;
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') || id.is_empty() {
        return Err(format!("invalid checkpoint id `{id}`"));
    }
    let p = d.join(format!("{id}.json"));
    let t = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    serde_json::from_str(&t).map_err(|e| format!("{}: {e}", p.display()))
}

fn save_cp(env: &Env, cp: &Cp) -> Result<(), String> {
    let d = cp_dir(env, &cp.thread)?;
    std::fs::create_dir_all(&d).map_err(|e| format!("{}: {e}", d.display()))?;
    let p = d.join(format!("{}.json", cp.id));
    let body = serde_json::to_vec_pretty(cp).map_err(|e| e.to_string())?;
    let tmp = d.join(format!(".{}.tmp", cp.id));
    std::fs::write(&tmp, &body).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, &p).map_err(|e| format!("{}: {e}", p.display()))?;
    std::fs::write(d.join("latest.json"), json!({"id": cp.id, "step": cp.step}).to_string()).map_err(|e| e.to_string())?;
    Ok(())
}

/// Every checkpoint of a thread, oldest first (`seagent graph status`/time travel).
pub fn history(env: &Env, thread: &str) -> Result<Vec<Cp>, String> {
    let d = cp_dir(env, thread)?;
    let Ok(rd) = std::fs::read_dir(&d) else { return Ok(vec![]) };
    let mut out: Vec<Cp> = rd
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json") && e.file_name() != "latest.json")
        .filter_map(|e| std::fs::read_to_string(e.path()).ok().and_then(|t| serde_json::from_str::<Cp>(&t).ok()))
        .collect();
    out.sort_by_key(|c| (c.step, c.ts));
    Ok(out)
}

// ───────────────────────── the runner ─────────────────────────

fn new_id() -> String {
    seagent_kernel::util::random_hex(8)
}

/// Timestamp for a checkpoint: milliseconds, but strictly increasing inside this process.
///
/// `history()` orders a thread by `(step, ts)`, and a fork writes a checkpoint with the *same*
/// step number as the branch it forked from (step 1 → 2 again). Two writes inside one
/// millisecond then looked identical to the sort, so the order of the two branches fell back to
/// `read_dir` order and "the newest checkpoint" was a coin flip. Bumping the clock by one
/// millisecond when it has not advanced keeps the pair unique and the unit unchanged.
fn checkpoint_ts() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static LAST: AtomicU64 = AtomicU64::new(0);
    let mut last = LAST.load(Ordering::Relaxed);
    loop {
        let next = now_ms().max(last + 1);
        match LAST.compare_exchange_weak(last, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(actual) => last = actual,
        }
    }
}

/// Initial channels: declared defaults, then the caller's input (unknown keys are kept: a
/// flow may accept ad-hoc input without declaring every channel).
pub fn initial_state(g: &Graph, input: &Value) -> Value {
    let mut m = Map::new();
    for (k, c) in &g.state {
        m.insert(k.clone(), c.default.clone());
    }
    if let Some(o) = input.as_object() {
        for (k, v) in o {
            m.insert(k.clone(), v.clone());
        }
    } else if !input.is_null() {
        m.insert("input".into(), input.clone());
    }
    Value::Object(m)
}

fn apply_writes(g: &Graph, state: &mut Value, writes: Vec<(String, Value)>) {
    for (ch, v) in writes {
        let reducer = g.state.get(&ch).map(|c| c.reducer).unwrap_or(Reducer::Last);
        let cur = state.get(&ch).cloned().unwrap_or(Value::Null);
        let next = match reducer {
            Reducer::Last => v,
            Reducer::First => {
                if cur.is_null() {
                    v
                } else {
                    cur
                }
            }
            Reducer::Append => match (cur, v) {
                (Value::Null, Value::Array(a)) => Value::Array(a),
                (Value::Null, v) => json!([v]),
                (Value::Array(mut a), Value::Array(b)) => {
                    a.extend(b);
                    Value::Array(a)
                }
                (Value::Array(mut a), v) => {
                    a.push(v);
                    Value::Array(a)
                }
                (a, Value::Array(b)) => {
                    let mut out = vec![a];
                    out.extend(b);
                    Value::Array(out)
                }
                (a, v) => json!([a, v]),
            },
            Reducer::Concat => match (cur, v) {
                (Value::Null, v) => v,
                (Value::String(mut a), v) => {
                    a.push_str(&scalar(&v));
                    Value::String(a)
                }
                (Value::Array(mut a), Value::Array(b)) => {
                    a.extend(b);
                    Value::Array(a)
                }
                (Value::Array(mut a), v) => {
                    a.push(v);
                    Value::Array(a)
                }
                (a, v) => json!([a, v]),
            },
            Reducer::Sum => match (num(&cur), num(&v)) {
                (Some(a), Some(b)) => {
                    let f = a + b;
                    if f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15 {
                        json!(f as i64)
                    } else {
                        json!(f)
                    }
                }
                _ => match (cur, v) {
                    (Value::Array(mut a), Value::Array(b)) => {
                        a.extend(b);
                        Value::Array(a)
                    }
                    (Value::Null, v) => v,
                    (a, v) => json!([a, v]),
                },
            },
            Reducer::Merge => match (cur, v) {
                (Value::Object(mut a), Value::Object(b)) => {
                    for (k, x) in b {
                        a.insert(k, x);
                    }
                    Value::Object(a)
                }
                (_, v) => v,
            },
        };
        if let Value::Object(m) = state {
            m.insert(ch, next);
        }
    }
}

/// What one node run produced.
struct NodeOut {
    writes: Vec<(String, Value)>,
    /// A gate that has no answer yet.
    halt: Option<Halt>,
}

fn render_map(v: &Option<Map<String, Value>>, state: &Value) -> Vec<(String, Value)> {
    v.iter().flat_map(|m| m.iter()).map(|(k, x)| (k.clone(), render_value(x.clone(), state))).collect()
}

struct Rt<'a> {
    env: &'a Env,
    ctx: &'a ToolCtx,
    deadline: Instant,
    max_bytes: u64,
}

impl Rt<'_> {
    fn left(&self) -> Result<Duration, String> {
        let l = self.deadline.saturating_duration_since(Instant::now());
        if l.is_zero() || self.ctx.cancel.is_cancelled() {
            return Err("graph run timed out".into());
        }
        Ok(l)
    }

    fn cwd(&self, n: &Node) -> PathBuf {
        match n.cwd.as_deref().filter(|c| !c.trim().is_empty()) {
            Some(c) => self.ctx.resolve(c),
            None => self.ctx.workspace.clone(),
        }
    }

    fn process(&self, n: &Node, state: &Value) -> Result<String, String> {
        use std::process::Stdio;
        let argv: Vec<String> = if n.argv.is_empty() { super::sh_argv(render(n.cmd.as_deref().unwrap_or(""), state)) } else { n.argv.iter().map(|a| render(a, state)).collect() };
        let t = n.timeout_ms.map(Duration::from_millis).unwrap_or_else(|| self.left().unwrap_or_default()).min(self.left()?);
        let mut cmd = seagent_core::platform::layout::program_command(&argv[0]);
        cmd.args(&argv[1..]).current_dir(self.cwd(n)).stdin(if n.stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
        if !self.cwd(n).is_dir() {
            return Err(format!("working directory {} does not exist", self.cwd(n).display()));
        }
        let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", argv[0]))?;
        if let Some(s) = n.stdin.as_ref() {
            let s = render(s, state);
            if let Some(mut w) = child.stdin.take() {
                std::thread::spawn(move || {
                    use std::io::Write;
                    let _ = w.write_all(s.as_bytes());
                });
            }
        }
        let max = self.max_bytes as usize;
        let read = |r: Option<Box<dyn Read + Send>>| {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                if let Some(mut r) = r {
                    let mut buf = [0u8; 8192];
                    while let Ok(k) = r.read(&mut buf) {
                        if k == 0 {
                            break;
                        }
                        out.extend_from_slice(&buf[..k]);
                        if out.len() > max {
                            break;
                        }
                    }
                }
                out
            })
        };
        let so = read(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
        let se = read(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
        let start = Instant::now();
        let status = loop {
            if let Some(st) = child.try_wait().map_err(|e| e.to_string())? {
                break st;
            }
            if start.elapsed() > t || self.ctx.cancel.is_cancelled() {
                let _ = child.kill();
                let _ = child.wait();
                return Err("node timed out".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let out = so.join().unwrap_or_default();
        let err = se.join().unwrap_or_default();
        if !status.success() {
            return Err(format!("command exited {}: {}", status.code().unwrap_or(-1), String::from_utf8_lossy(&err).trim()));
        }
        Ok(String::from_utf8_lossy(&out).to_string())
    }
}

/// Run one node. `resume` carries the operator's answer when this node was a paused gate.
fn run_node(rt: &Rt, name: &str, n: &Node, state: &Value, resume: Option<&Value>) -> Result<NodeOut, String> {
    let save = n.save.clone().unwrap_or_else(|| "result".into());
    let wrap = |v: Value| -> NodeOut { NodeOut { writes: vec![(save.clone(), v)], halt: None } };
    match n.kind.as_str() {
        "noop" => Ok(NodeOut { writes: vec![], halt: None }),
        "set" => Ok(NodeOut { writes: render_map(&n.state, state), halt: None }),
        "run" => {
            let out = rt.process(n, state)?;
            let v = if n.save_json { serde_json::from_str(&out).unwrap_or(Value::String(out)) } else { Value::String(out) };
            Ok(wrap(v))
        }
        "tool" => {
            let name = n.tool.as_deref().unwrap_or("");
            if !allowed(&rt.env.cfg.graph, name) {
                return Err(format!("tool `{name}` is not allowed in flows"));
            }
            let k = rt.env.kernel()?;
            let tool = k.tools.iter().find(|t| t.spec().name == name).cloned().ok_or(format!("tool `{name}` is not available"))?;
            let args = render_value(n.args.clone().unwrap_or_else(|| json!({})), state);
            let r = tool.call(rt.ctx, args);
            if r.is_error {
                return Err(format!("{name} failed: {}", r.content));
            }
            let v = if n.save_json { serde_json::from_str(&r.content).unwrap_or(Value::String(r.content)) } else { Value::String(r.content) };
            Ok(wrap(v))
        }
        "llm" => {
            let req = llm_task::parse_request(&json!({
                "prompt": render(n.prompt.as_deref().unwrap_or(""), state),
                "input": state,
                "schema": n.schema,
                "model": n.model.as_deref().map(|m| render(m, state)),
            }))?;
            let (v, _) = llm_task::run(rt.env, &req, &rt.ctx.cancel)?;
            Ok(wrap(v))
        }
        "gate" => {
            let kind = n.mode.clone().unwrap_or_else(|| "approval".into());
            match resume {
                Some(v) => Ok(wrap(v.clone())),
                None => {
                    let prompt = n.message.clone().unwrap_or_else(|| format!("Approve `{name}`?"));
                    Ok(NodeOut {
                        writes: vec![],
                        halt: Some(Halt { kind, node: name.into(), prompt: render(&prompt, state), schema: n.schema.clone(), preview: Some(state.clone()) }),
                    })
                }
            }
        }
        other => Err(format!("unknown node kind `{other}`")),
    }
}

/// How a run ended.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Outcome {
    Done { thread: String, checkpoint: String, state: Value },
    Interrupted { thread: String, checkpoint: String, halt: Halt, state: Value },
    Failed { thread: String, checkpoint: Option<String>, error: String },
}

impl Outcome {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| json!({"status": "failed"}))
    }
}

fn drive(env: &Env, rt: &Rt, g: &Graph, thread: &str, mut cp: Cp, mut next: Vec<String>, resume: Option<(String, Value)>) -> Outcome {
    let limit = env.cfg.graph.max_steps.max(1);
    let mut resume = resume;
    loop {
        if cp.step >= limit {
            cp.status = "error".into();
            cp.error = Some(format!("max_steps ({limit}) exceeded"));
            let _ = save_cp(env, &cp);
            return Outcome::Failed { thread: thread.into(), checkpoint: Some(cp.id.clone()), error: cp.error.clone().unwrap_or_default() };
        }
        let mut writes: Vec<(String, Value)> = Vec::new();
        let mut executed: Vec<String> = Vec::new();
        let mut halt: Option<Halt> = None;
        let mut pending = next.clone();
        for name in &next {
            let Some(n) = g.nodes.get(name) else {
                cp.status = "error".into();
                cp.error = Some(format!("unknown node `{name}`"));
                let _ = save_cp(env, &cp);
                return Outcome::Failed { thread: thread.into(), checkpoint: Some(cp.id.clone()), error: cp.error.clone().unwrap_or_default() };
            };
            if g.interrupt_before.iter().any(|x| x == name) && !matches!(&resume, Some((r, _)) if r == name) {
                halt = Some(Halt { kind: "before".into(), node: name.clone(), prompt: format!("Paused before `{name}`"), schema: None, preview: Some(cp.state.clone()) });
                break;
            }
            let answer = match &resume {
                Some((r, v)) if r == name => Some(v.clone()),
                _ => None,
            };
            match run_node(rt, name, n, &cp.state, answer.as_ref()) {
                Ok(out) => {
                    if let Some(h) = out.halt {
                        halt = Some(h);
                        break;
                    }
                    writes.extend(out.writes);
                }
                Err(e) => {
                    if n.on_error.as_deref() == Some("continue") {
                        writes.push(("error".into(), Value::String(e)));
                    } else {
                        apply_writes(g, &mut cp.state, std::mem::take(&mut writes));
                        cp.step += 1;
                        cp.status = "error".into();
                        cp.error = Some(format!("node `{name}`: {e}"));
                        cp.next = vec![];
                        cp.parent = Some(cp.id.clone());
                        cp.ts = checkpoint_ts();
                        cp.id = format!("{:04}-{}", cp.step, new_id());
                        let _ = save_cp(env, &cp);
                        return Outcome::Failed { thread: thread.into(), checkpoint: Some(cp.id.clone()), error: cp.error.clone().unwrap_or_default() };
                    }
                }
            }
            executed.push(name.clone());
            if g.interrupt_after.iter().any(|x| x == name) {
                apply_writes(g, &mut cp.state, std::mem::take(&mut writes));
                let succ = g.next_of(name, &cp.state).unwrap_or_default();
                halt = Some(Halt { kind: "after".into(), node: name.clone(), prompt: format!("Paused after `{name}`"), schema: None, preview: Some(cp.state.clone()) });
                pending = succ;
                break;
            }
        }
        if let Some((r, _)) = &resume {
            if executed.iter().any(|x| x == r) {
                resume = None;
            }
        }
        apply_writes(g, &mut cp.state, writes);
        cp.step += 1;
        cp.parent = Some(cp.id.clone());
        cp.ts = checkpoint_ts();
        cp.id = format!("{:04}-{}", cp.step, new_id());
        if let Some(h) = halt {
            let rest: Vec<String> = pending.iter().filter(|n| !executed.contains(n)).cloned().collect();
            cp.status = "interrupted".into();
            cp.halt = Some(h.clone());
            cp.next = rest;
            let _ = save_cp(env, &cp);
            return Outcome::Interrupted { thread: thread.into(), checkpoint: cp.id.clone(), halt: h, state: cp.state.clone() };
        }
        let mut nxt: Vec<String> = Vec::new();
        for name in &executed {
            for t in g.next_of(name, &cp.state).unwrap_or_default() {
                if !nxt.contains(&t) {
                    nxt.push(t);
                }
            }
        }
        cp.next = nxt.clone();
        cp.halt = None;
        next = nxt;
        if next.is_empty() {
            cp.status = "done".into();
            let _ = save_cp(env, &cp);
            return Outcome::Done { thread: thread.into(), checkpoint: cp.id.clone(), state: cp.state.clone() };
        }
        cp.status = "running".into();
        if let Err(e) = save_cp(env, &cp) {
            return Outcome::Failed { thread: thread.into(), checkpoint: None, error: e };
        }
    }
}

// ───────────────────────── the tool ─────────────────────────

pub struct GraphTool(Arc<Env>);

impl GraphTool {
    pub fn new(env: Arc<Env>) -> GraphTool {
        GraphTool(env)
    }

    fn load_spec(&self, input: &Value, ctx: &ToolCtx) -> Result<(Graph, Value), String> {
        let v = match &input["graph"] {
            Value::Object(_) => input["graph"].clone(),
            Value::String(s) if !s.trim().is_empty() => {
                let p = ctx.resolve(s);
                let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                if p.extension().is_some_and(|x| x == "json") {
                    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))?
                } else {
                    yaml::parse(&text).map_err(|e| format!("{}: {e}", p.display()))?
                }
            }
            _ => return Err("`graph` is required (an object or a .json/.yaml path)".into()),
        };
        let g = Graph::parse(&v)?;
        Ok((g, v))
    }

    fn timeout(&self, input: &Value) -> Duration {
        Duration::from_millis(input["timeoutMs"].as_u64().unwrap_or(self.0.cfg.graph.timeout_ms).max(1))
    }

    fn run(&self, ctx: &ToolCtx, input: &Value) -> Result<Value, String> {
        let env = &self.0;
        let action = input["action"].as_str().unwrap_or("run");
        match action {
            "run" => {
                let (g, spec) = self.load_spec(input, ctx)?;
                let thread = input["threadId"].as_str().map(str::to_string).unwrap_or_else(|| format!("t-{}", new_id()));
                if !thread_ok(&thread) {
                    return Err(format!("invalid threadId `{thread}`"));
                }
                if latest_cp(env, &thread).is_some() && input["overwrite"] != true {
                    return Err(format!("thread `{thread}` already exists; pass a new threadId or overwrite: true"));
                }
                let state = initial_state(&g, &input["input"]);
                let next = g.entry()?;
                let cp = Cp {
                    v: 1,
                    thread: thread.clone(),
                    id: format!("{:04}-{}", 0, new_id()),
                    parent: None,
                    step: 0,
                    ts: checkpoint_ts(),
                    status: "running".into(),
                    next: next.clone(),
                    state,
                    halt: None,
                    error: None,
                    graph: spec,
                    input: input["input"].clone(),
                };
                save_cp(env, &cp)?;
                let rt = Rt { env, ctx, deadline: Instant::now() + self.timeout(input), max_bytes: env.cfg.graph.max_stdout_bytes };
                Ok(drive(env, &rt, &g, &thread, cp, next, None).to_json())
            }
            "resume" => {
                let thread = input["threadId"].as_str().ok_or("`threadId` is required")?;
                let mut cp = match input["checkpointId"].as_str().filter(|c| !c.is_empty()) {
                    Some(id) => load_cp(env, thread, id)?,
                    None => latest_cp(env, thread).ok_or_else(|| format!("no run for thread `{thread}`"))?,
                };
                if input["cancel"] == true {
                    cp.status = "cancelled".into();
                    cp.next = vec![];
                    save_cp(env, &cp)?;
                    return Ok(json!({"status": "cancelled", "thread": thread, "checkpoint": cp.id, "state": cp.state}));
                }
                let g = Graph::parse(&cp.graph)?;
                // A gate is re-run with the operator's answer; a plain pause just continues.
                let paused = cp.halt.clone();
                let resume: Option<(String, Value)> = match &paused {
                    Some(h) if h.kind == "approval" => Some((h.node.clone(), Value::Bool(input["approve"] == true))),
                    Some(h) if h.kind == "input" => {
                        let v = input.get("response").cloned().filter(|v| !v.is_null()).ok_or("`response` is required for an input gate")?;
                        if let Some(s) = &h.schema {
                            seagent_plugin::schema::validate(s, &v).map_err(|e| format!("response does not match the gate schema: {e}"))?;
                        }
                        Some((h.node.clone(), v))
                    }
                    Some(h) => Some((h.node.clone(), Value::Bool(input["approve"] != false))),
                    None => None,
                };
                // Time travel: `checkpointId` of an older checkpoint forks a new branch.
                let next = if cp.next.is_empty() {
                    if cp.status == "done" && paused.is_none() {
                        return Ok(json!({"status": "done", "thread": thread, "checkpoint": cp.id, "state": cp.state, "note": "nothing left to do"}));
                    }
                    g.entry()?
                } else {
                    cp.next.clone()
                };
                let parent = Some(cp.id.clone());
                cp.parent = parent;
                cp.halt = None;
                cp.error = None;
                cp.status = "running".into();
                cp.input = cp.input.clone();
                let rt = Rt { env, ctx, deadline: Instant::now() + self.timeout(input), max_bytes: env.cfg.graph.max_stdout_bytes };
                let _ = &mut cp;
                Ok(drive(env, &rt, &g, thread, cp, next, resume).to_json())
            }
            "status" => {
                let thread = input["threadId"].as_str();
                match thread {
                    Some(t) => {
                        let cp = match input["checkpointId"].as_str().filter(|c| !c.is_empty()) {
                            Some(id) => load_cp(env, t, id)?,
                            None => latest_cp(env, t).ok_or_else(|| format!("no run for thread `{t}`"))?,
                        };
                        let hist: Vec<Value> = history(env, t)?.iter().map(|c| json!({"id": c.id, "step": c.step, "status": c.status, "next": c.next, "parent": c.parent, "ts": c.ts, "halt": c.halt, "error": c.error})).collect();
                        Ok(json!({"thread": t, "checkpoint": cp, "history": hist}))
                    }
                    None => Ok(list_threads(env)),
                }
            }
            "list" => Ok(list_threads(env)),
            "explain" => {
                let (g, _) = self.load_spec(input, ctx)?;
                let nodes: Vec<Value> = g.nodes.iter().map(|(n, x)| json!({"node": n, "kind": x.kind, "description": x.description, "save": x.save.clone().unwrap_or_else(|| "result".into())})).collect();
                Ok(json!({"name": g.name, "entry": g.entry()?, "nodes": nodes, "edges": g.edges, "interrupt_before": g.interrupt_before, "interrupt_after": g.interrupt_after}))
            }
            other => Err(format!("unknown action `{other}` (run|resume|status|list|explain)")),
        }
    }
}

impl Tool for GraphTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "graph-flow".into(),
            description: "Run a durable state graph (LangGraph-style): nodes write to state channels with reducers, edges are static or conditional, and every superstep is checkpointed so a run can be interrupted (gate node: approval or structured input) and resumed hours later — even from an older checkpoint, which forks the thread. Use it for multi-step automations that must survive a restart or wait for a human; `lobster` is the simpler linear pipeline. Answer a gate with action=resume + threadId + approve/response.".into(),
            input_schema: json!({"type": "object", "properties": {
                "action": {"type": "string", "enum": ["run", "resume", "status", "list", "explain"]},
                "graph": {"description": "The graph: an object, or a path to a .json/.yaml spec."},
                "threadId": {"type": "string", "description": "Run id (a-z, 0-9, -, _). Generated for action=run when omitted."},
                "input": {"description": "Initial state for action=run."},
                "checkpointId": {"type": "string", "description": "Resume (or fork) from this checkpoint instead of the latest one."},
                "approve": {"type": "boolean", "description": "Answer to an approval gate."},
                "response": {"description": "Answer to an input gate (validated against the gate's schema)."},
                "cancel": {"type": "boolean", "enum": [true], "description": "Cancel the thread."},
                "overwrite": {"type": "boolean", "description": "Replace an existing thread of the same id."},
                "timeoutMs": {"type": "integer", "minimum": 1}
            }, "required": ["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }

    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        if input["action"].as_str() != Some("run") {
            return vec![];
        }
        let Ok((g, _)) = GraphTool::load_spec(self, input, ctx) else { return vec![] };
        let state = initial_state(&g, &input["input"]);
        g.effects(&self.0, ctx, &state)
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok(v) => {
                let body = serde_json::to_string_pretty(&v).unwrap_or_default();
                // A run that ended in `failed`/`cancelled` is an error for the caller, but the
                // checkpoint and the partial state stay available under the thread id.
                if matches!(v["status"].as_str(), Some("failed") | Some("cancelled")) {
                    ToolOutput::err(body)
                } else {
                    ToolOutput::ok(body)
                }
            }
            Err(e) => ToolOutput::err(json!({"ok": false, "error": {"message": e}}).to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;

    fn graph(spec: Value) -> Graph {
        Graph::parse(&spec).expect("valid graph")
    }

    /// The test env plus its temp root: dropping it removes the whole throwaway tree, so a
    /// test run leaves nothing behind (D5 test hygiene).
    struct TEnv(Arc<Env>);

    impl std::ops::Deref for TEnv {
        type Target = Arc<Env>;
        fn deref(&self) -> &Arc<Env> {
            &self.0
        }
    }

    impl Drop for TEnv {
        fn drop(&mut self) {
            if let Some(root) = self.0.dir.parent() {
                let _ = std::fs::remove_dir_all(root);
            }
        }
    }

    fn env(tag: &str) -> TEnv {
        TEnv(testkit::env(tag, &["{}"], "").0)
    }

    fn call(env: &Arc<Env>, input: Value) -> Value {
        let ctx = testkit::ctx(env, &env.dir.join("ws"));
        std::fs::create_dir_all(&ctx.workspace).unwrap();
        let out = GraphTool::new((*env).clone()).call(&ctx, input);
        assert!(!out.is_error, "{}", out.content);
        serde_json::from_str(&out.content).unwrap()
    }

    #[test]
    fn parse_rejects_typos_and_dangling_edges() {
        let e = Graph::parse(&json!({"nodes": {"a": {"kind": "run", "cmd": "true", "saave": "x"}}})).unwrap_err();
        assert!(e.contains("unknown field"), "{e}");
        let e = Graph::parse(&json!({"nodes": {"a": {"kind": "nope"}}})).unwrap_err();
        assert!(e.contains("unknown kind"), "{e}");
        let e = Graph::parse(&json!({"nodes": {"a": {"kind": "noop"}}, "edges": [{"from": "a", "to": "b"}]})).unwrap_err();
        assert!(e.contains("unknown node `b`"), "{e}");
        let e = Graph::parse(&json!({"nodes": {"a": {"kind": "gate", "mode": "maybe"}}})).unwrap_err();
        assert!(e.contains("gate mode"), "{e}");
        // An empty graph or a node named START are refused.
        assert!(Graph::parse(&json!({"nodes": {}})).is_err());
        assert!(Graph::parse(&json!({"nodes": {"START": {"kind":"noop"}}})).is_err());
    }

    #[test]
    fn templating_and_conditions() {
        let s = json!({"count": 2, "plan": {"steps": ["a", "b"]}, "flag": true, "note": "hello world"});
        assert_eq!(render("n={{count}} step0={{plan.steps.0}} missing={{nope}}", &s), "n=2 step0=a missing=");
        assert_eq!(render_value(json!({"x": "{{plan}}"}), &s), json!({"x": {"steps": ["a", "b"]}}));
        assert_eq!(render_value(json!({"x": "n={{count}}"}), &s), json!({"x": "n=2"}));
        assert!(eval_cond("state.count >= 2", &s).unwrap());
        assert!(!eval_cond("state.count > 2", &s).unwrap());
        assert!(eval_cond("state.count < 3 and state.flag", &s).unwrap());
        assert!(eval_cond("not state.missing", &s).unwrap());
        assert!(eval_cond("contains(state.note, \"world\")", &s).unwrap());
        assert!(eval_cond("\"world\" in state.note", &s).unwrap());
        assert!(eval_cond("state.count == 2 or state.flag == false", &s).unwrap());
        assert!(eval_cond("{{flag}}", &s).unwrap());
        assert!(!eval_cond("state.nope", &s).is_err(), "a missing path is falsy, not an error");
    }

    #[test]
    fn reducers_fold_writes_like_langgraph_channels() {
        let g = graph(json!({"state": {"log": {"reducer": "append"}, "n": {"reducer": "sum", "default": 0}, "m": {"reducer": "merge"}}, "nodes": {"a": {"kind": "noop"}}}));
        let mut st = initial_state(&g, &json!({"n": 5}));
        apply_writes(&g, &mut st, vec![("log".into(), json!("x")), ("n".into(), json!(2)), ("m".into(), json!({"a": 1}))]);
        apply_writes(&g, &mut st, vec![("log".into(), json!(["y"])), ("n".into(), json!(3)), ("m".into(), json!({"b": 2}))]);
        assert_eq!(st["n"], json!(10), "sum");
        assert_eq!(st["m"], json!({"a": 1, "b": 2}), "merge");
        assert_eq!(st["log"], json!(["x", "y"]), "append collects and flattens");
        // `concat` is the string channel variant (LangGraph `add` on a str); it never wraps.
        let g2 = graph(json!({"state": {"msg": {"reducer": "concat"}}, "nodes": {"a": {"kind": "noop"}}}));
        let mut st2 = initial_state(&g2, &json!({}));
        apply_writes(&g2, &mut st2, vec![("msg".into(), json!("a")), ("msg".into(), json!("b"))]);
        assert_eq!(st2["msg"], json!("ab"));
        // Undeclared channels behave like LastValue.
        apply_writes(&g, &mut st, vec![("other".into(), json!(1))]);
        apply_writes(&g, &mut st, vec![("other".into(), json!(2))]);
        assert_eq!(st["other"], json!(2));
    }

    #[test]
    fn linear_run_checkpoints_every_superstep_and_finishes() {
        let env = env("graph-linear");
        let v = call(
            &env,
            json!({"action": "run", "threadId": "t1", "input": {"x": 1}, "graph": {
                "state": {"out": {"reducer": "append"}},
                "nodes": {
                    "one": {"kind": "set", "state": {"out": "a"}},
                    "two": {"kind": "run", "cmd": "printf b", "save": "out"},
                    "three": {"kind": "set", "state": {"done": true}}
                },
                "edges": [{"from": "START", "to": "one"}, {"from": "one", "to": "two"}, {"from": "two", "to": "three"}, {"from": "three", "to": "END"}]
            }}),
        );
        assert_eq!(v["status"], "done", "{v}");
        assert_eq!(v["state"]["out"], json!(["a", "b"]), "append collects");
        assert_eq!(v["state"]["done"], json!(true));
        let hist = history(&env, "t1").unwrap();
        assert_eq!(hist.iter().map(|c| c.step).collect::<Vec<_>>(), vec![0, 1, 2, 3], "one checkpoint per superstep, plus the start");
        assert_eq!(hist.last().unwrap().status, "done");
        assert_eq!(hist.last().unwrap().parent.as_deref(), Some(hist[hist.len() - 2].id.as_str()), "parent chain is walkable");
        // A second run on the same thread id is refused unless overwrite is set.
        let e = GraphTool::new((*env).clone()).call(&testkit::ctx(&env, &env.dir.join("ws")), json!({"action": "run", "threadId": "t1", "graph": {"nodes": {"a": {"kind": "noop"}}}}));
        assert!(e.is_error && e.content.contains("already exists"));
    }

    #[test]
    fn a_gate_interrupts_and_resumes_hours_later() {
        let env = env("graph-gate");
        let spec = json!({"nodes": {
            "ask": {"kind": "gate", "mode": "approval", "message": "Deploy {{svc}}?", "save": "ok"},
            "ship": {"kind": "set", "state": {"shipped": "{{ok}}"}}
        }, "edges": [{"from": "START", "to": "ask"}, {"from": "ask", "to": "ship"}, {"from": "ship", "to": "END"}]});
        let v = call(&env, json!({"action": "run", "threadId": "g1", "input": {"svc": "api"}, "graph": spec}));
        assert_eq!(v["status"], "interrupted", "{v}");
        assert_eq!(v["halt"]["kind"], "approval");
        assert_eq!(v["halt"]["prompt"], "Deploy api?", "the prompt is templated from state");
        assert_eq!(v["halt"]["node"], "ask");
        // Nothing ran after the gate; the checkpoint holds the paused state.
        let cp = latest_cp(&env, "g1").unwrap();
        assert_eq!(cp.status, "interrupted");
        assert_eq!(cp.next, vec!["ask"], "the gate itself is pending");
        assert_eq!(cp.state["svc"], json!("api"));
        // Approve → the gate node re-runs and yields the answer.
        let v = call(&env, json!({"action": "resume", "threadId": "g1", "approve": true}));
        assert_eq!(v["status"], "done", "{v}");
        assert_eq!(v["state"]["ok"], json!(true));
        assert_eq!(v["state"]["shipped"], json!(true), "an exact {{path}} keeps the JSON type");
    }

    #[test]
    fn input_gate_validates_the_response_against_its_schema() {
        let env = env("graph-input");
        let spec = json!({"nodes": {
            "ask": {"kind": "gate", "mode": "input", "message": "Which host?", "schema": {"type": "object", "required": ["host"], "properties": {"host": {"type": "string"}}}, "save": "answer"}
        }, "edges": [{"from": "START", "to": "ask"}, {"from": "ask", "to": "END"}]});
        let v = call(&env, json!({"action": "run", "threadId": "i1", "graph": spec}));
        assert_eq!(v["status"], "interrupted");
        assert_eq!(v["halt"]["schema"]["required"], json!(["host"]));
        let bad = GraphTool::new((*env).clone()).call(&testkit::ctx(&env, &env.dir.join("ws")), json!({"action": "resume", "threadId": "i1", "response": {"port": 1}}));
        assert!(bad.is_error && bad.content.contains("does not match"), "{}", bad.content);
        let v = call(&env, json!({"action": "resume", "threadId": "i1", "response": {"host": "web1"}}));
        assert_eq!(v["state"]["answer"], json!({"host": "web1"}));
        assert_eq!(v["status"], "done");
    }

    #[test]
    fn a_conditional_edge_loops_until_the_condition_clears() {
        let env = env("graph-loop");
        let spec = json!({
            "state": {"round": {"reducer": "sum", "default": 0}, "seen": {"reducer": "append"}},
            "nodes": {"tick": {"kind": "set", "state": {"round": 1, "seen": "tick"}}},
            "edges": [{"from": "START", "to": "tick"}, {"from": "tick", "router": [{"when": "state.round < 3", "to": "tick"}], "default": "END"}]
        });
        let v = call(&env, json!({"action": "run", "threadId": "l1", "graph": spec}));
        assert_eq!(v["status"], "done", "{v}");
        assert_eq!(v["state"]["round"], json!(3));
        assert_eq!(v["state"]["seen"], json!(["tick", "tick", "tick"]));
    }

    #[test]
    fn interrupt_before_pauses_a_plain_node_and_resumes_it() {
        let env = env("graph-before");
        let spec = json!({
            "nodes": {"a": {"kind": "set", "state": {"a": 1}}, "b": {"kind": "set", "state": {"b": 2}}},
            "edges": [{"from": "START", "to": "a"}, {"from": "a", "to": "b"}, {"from": "b", "to": "END"}],
            "interrupt_before": ["b"]
        });
        let v = call(&env, json!({"action": "run", "threadId": "p1", "graph": spec}));
        assert_eq!(v["status"], "interrupted");
        assert_eq!(v["halt"]["kind"], "before");
        assert_eq!(v["state"]["a"], json!(1));
        assert!(v["state"].get("b").is_none(), "b did not run");
        let v = call(&env, json!({"action": "resume", "threadId": "p1"}));
        assert_eq!(v["status"], "done");
        assert_eq!(v["state"]["b"], json!(2));
    }

    #[test]
    fn time_travel_forks_from_an_older_checkpoint() {
        let env = env("graph-fork");
        let spec = json!({
            "state": {"n": {"reducer": "sum", "default": 0}},
            "nodes": {"inc": {"kind": "set", "state": {"n": 1}}},
            "edges": [{"from": "START", "to": "inc"}, {"from": "inc", "router": [{"when": "state.n < 2", "to": "inc"}], "default": "END"}]
        });
        let v = call(&env, json!({"action": "run", "threadId": "f1", "graph": spec}));
        assert_eq!(v["state"]["n"], json!(2));
        let hist = history(&env, "f1").unwrap();
        let first = hist.iter().find(|c| c.step == 1).expect("checkpoint after the first tick");
        assert_eq!(first.state["n"], json!(1));
        // Resume from that checkpoint: it starts over from n == 1 and ends at 2 again,
        // on a new branch (new checkpoint ids, parent chain rooted at the old one).
        let v = call(&env, json!({"action": "resume", "threadId": "f1", "checkpointId": first.id, "approve": true}));
        assert_eq!(v["status"], "done", "{v}");
        assert_eq!(v["state"]["n"], json!(2));
        let hist2 = history(&env, "f1").unwrap();
        assert!(hist2.len() > hist.len(), "the fork wrote new checkpoints");
        let newest = hist2.last().unwrap();
        assert_ne!(newest.id, hist.last().unwrap().id);
    }

    #[test]
    fn a_failing_node_stops_the_run_and_is_recorded_on_error_continue_moves_on() {
        let env = env("graph-fail");
        let spec = json!({"nodes": {
            "bad": {"kind": "run", "cmd": "echo boom >&2; exit 3"},
            "after": {"kind": "set", "state": {"after": 1}}
        }, "edges": [{"from": "START", "to": "bad"}, {"from": "bad", "to": "after"}, {"from": "after", "to": "END"}]});
        let ws = env.dir.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let out = GraphTool::new((*env).clone()).call(&testkit::ctx(&env, &ws), json!({"action": "run", "threadId": "e1", "graph": spec}));
        assert!(out.is_error);
        let cp = latest_cp(&env, "e1").unwrap();
        assert_eq!(cp.status, "error", "{:?} {}", cp.error, out.content);
        assert!(cp.error.clone().unwrap_or_default().contains("exited 3"), "{:?} {}", cp.error, out.content);
        // on_error: continue records the error in `error` and keeps going.
        let spec = json!({"nodes": {
            "bad": {"kind": "run", "cmd": "exit 3", "on_error": "continue"},
            "after": {"kind": "set", "state": {"after": 1}}
        }, "edges": [{"from": "START", "to": "bad"}, {"from": "bad", "to": "after"}, {"from": "after", "to": "END"}]});
        let v = call(&env, json!({"action": "run", "threadId": "e2", "graph": spec}));
        assert_eq!(v["status"], "done");
        assert_eq!(v["state"]["after"], json!(1));
        assert!(v["state"]["error"].as_str().unwrap().contains("exited 3"));
    }

    #[test]
    fn max_steps_bounds_an_endless_loop() {
        let env = env("graph-steps");
        let spec = json!({"nodes": {"spin": {"kind": "noop"}},
            "edges": [{"from": "START", "to": "spin"}, {"from": "spin", "to": "spin"}]});
        let out = GraphTool::new((*env).clone()).call(&testkit::ctx(&env, &env.dir.join("ws")), json!({"action": "run", "threadId": "s1", "graph": spec}));
        assert!(out.is_error);
        assert!(out.content.contains("max_steps"), "{}", out.content);
        assert_eq!(latest_cp(&env, "s1").unwrap().status, "error");
    }

    #[test]
    fn cancel_and_status_and_list() {
        let env = env("graph-status");
        let spec = json!({"nodes": {"ask": {"kind": "gate", "message": "ok?"}},
            "edges": [{"from": "START", "to": "ask"}, {"from": "ask", "to": "END"}]});
        let v = call(&env, json!({"action": "run", "threadId": "c1", "graph": spec}));
        assert_eq!(v["status"], "interrupted");
        let st = call(&env, json!({"action": "status", "threadId": "c1"}));
        assert_eq!(st["checkpoint"]["status"], "interrupted");
        assert_eq!(st["history"].as_array().unwrap().len(), 2, "start + interrupted");
        let all = call(&env, json!({"action": "list"}));
        assert!(all["threads"].as_array().unwrap().iter().any(|t| t["thread"] == "c1"));
        // A cancelled run is reported as an error for the caller, with the checkpoint kept.
        let out = GraphTool::new((*env).clone()).call(&testkit::ctx(&env, &env.dir.join("ws")), json!({"action": "resume", "threadId": "c1", "cancel": true}));
        assert!(out.is_error);
        let v: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(v["status"], "cancelled");
        assert_eq!(latest_cp(&env, "c1").unwrap().status, "cancelled");
    }

    #[test]
    fn tool_nodes_call_seagent_tools_and_respect_the_deny_list() {
        let env = env("graph-tool");
        let ctx = testkit::ctx(&env, &env.dir.join("ws"));
        std::fs::create_dir_all(&ctx.workspace).unwrap();
        // A flow may not call itself, and the deny list is enforced before the tool runs.
        let g = GraphTool::new((*env).clone());
        let e = g.call(&ctx, json!({"action": "run", "threadId": "tt", "graph": {"nodes": {"t": {"kind": "tool", "tool": "graph-flow"}}, "edges": [{"from": "START", "to": "t"}]}}));
        assert!(e.is_error && e.content.contains("not allowed"), "{}", e.content);
    }

    #[test]
    fn effects_are_declared_before_the_run_so_gates_judge_once() {
        let env = env("graph-effects");
        let ctx = testkit::ctx(&env, &env.dir.join("ws"));
        let g = graph(json!({"nodes": {"r": {"kind": "run", "cmd": "git status {{dir}}"}, "s": {"kind": "set", "state": {"a": 1}}},
            "edges": [{"from": "START", "to": "r"}, {"from": "r", "to": "s"}, {"from": "s", "to": "END"}]}));
        let ef = g.effects(&env, &ctx, &json!({"dir": "src"}));
        assert!(matches!(&ef[0], Effect::Exec { command } if command == "git status src"), "{ef:?}");
        assert_eq!(ef.len(), 1, "set nodes declare nothing");
    }

    #[test]
    fn specs_load_from_a_yaml_file_and_thread_ids_are_validated() {
        let env = env("graph-file");
        let dir = testkit::temp("graph-spec");
        std::fs::write(dir.join("flow.yaml"), "nodes:\n  a:\n    kind: set\n    state:\n      x: 1\nedges:\n  - from: START\n    to: a\n  - from: a\n    to: END\n").unwrap();
        let ws = env.dir.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("flow.yaml"), std::fs::read_to_string(dir.join("flow.yaml")).unwrap()).unwrap();
        let v = call(&env, json!({"action": "run", "threadId": "yaml1", "graph": "flow.yaml"}));
        assert_eq!(v["state"]["x"], json!(1));
        let bad = GraphTool::new((*env).clone()).call(&testkit::ctx(&env, &ws), json!({"action": "run", "threadId": "../escape", "graph": {"nodes": {"a": {"kind": "noop"}}}}));
        assert!(bad.is_error && bad.content.contains("invalid threadId"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
