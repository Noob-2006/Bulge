//! `lobster`: typed (JSON-first) workflow pipelines with resumable approval and input
//! checkpoints — a native port of the Lobster runtime OpenClaw embeds
//! (@clawdbot/lobster + extensions/lobster, MIT).
//!
//! A pipeline is `stage | stage | …`; items flow between stages as JSON values:
//! `exec [--json] [--shell] [--stdin raw|json|jsonl] cmd…`, `where field<op>value`,
//! `pick a,b`, `head --n N`, `sort --key k [--desc]`, `dedupe [--key k]`, `groupBy --key k`,
//! `map [--wrap k|--unwrap k] k=v…`, `template --text '…{{path | filter}}…'`, `json`, `table`,
//! `approve [--prompt …] [--preview-from-stdin --limit N]`, `ask --prompt … [--schema JSON]`,
//! `state.get key`, `state.set key`, `diff.last --key k`, `llm.invoke --prompt … [--output-schema JSON]`
//! (alias `llm_task.invoke`), and `openclaw.invoke --tool name [--action a] [--args-json …]
//! [--each --item-key k]` (alias `clawd.invoke`, `seagent.invoke`) which calls an seagent tool.
//!
//! Workflow files (`.lobster`, `.yaml`, `.yml`, `.json`) list steps: `run`/`command` (shell),
//! `pipeline`, `approval`, `input`, with `stdin: $step.stdout|$step.json`, `when`/`condition`,
//! `env`, `cwd`, `retry {max, delay_ms}`, `timeout_ms` and `on_error: fail|continue|skip_rest`.
//!
//! A gate halts the run and stores its state; the envelope carries a `resumeToken` (and short
//! `approvalId`) that `action=resume` continues with `approve`, `responseJson` or `cancel`.

use super::{llm_task, now_ms, read_json, write_json, yaml, Env};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn d_deny() -> Vec<String> {
    vec!["gateway".into(), "lobster".into()]
}
fn d_timeout() -> u64 {
    20_000
}
fn d_stdout() -> u64 {
    512_000
}

/// `[surfaces.lobster]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LobsterConfig {
    /// Tools `openclaw.invoke` may call. Empty = every tool except `invoke_deny`.
    pub invoke_allow: Vec<String>,
    /// Tools `openclaw.invoke` may never call. Default ["gateway", "lobster"].
    #[serde(default = "d_deny")]
    pub invoke_deny: Vec<String>,
    /// Default run timeout. Default 20000 ms.
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
    /// Default cap on the result envelope and each process's output. Default 512000 bytes.
    #[serde(default = "d_stdout")]
    pub max_stdout_bytes: u64,
}

impl Default for LobsterConfig {
    fn default() -> Self {
        LobsterConfig { invoke_allow: vec![], invoke_deny: d_deny(), timeout_ms: d_timeout(), max_stdout_bytes: d_stdout() }
    }
}

// ───────────────────────── parsing ─────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stage {
    pub name: String,
    pub argv: Vec<String>,
}

/// Shell-like tokens: quotes, backslash escapes, `|` between stages.
pub fn parse_pipeline(src: &str) -> Result<Vec<Stage>, String> {
    let mut stages = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut tok = String::new();
    let mut has = false;
    let mut it = src.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\'' => {
                has = true;
                loop {
                    match it.next() {
                        Some('\'') => break,
                        Some(x) => tok.push(x),
                        None => return Err("unterminated ' quote".into()),
                    }
                }
            }
            '"' => {
                has = true;
                loop {
                    match it.next() {
                        Some('"') => break,
                        Some('\\') => match it.next() {
                            Some(x @ ('"' | '\\' | '$' | '`')) => tok.push(x),
                            Some(x) => {
                                tok.push('\\');
                                tok.push(x);
                            }
                            None => return Err("unterminated \" quote".into()),
                        },
                        Some(x) => tok.push(x),
                        None => return Err("unterminated \" quote".into()),
                    }
                }
            }
            '\\' => {
                if let Some(x) = it.next() {
                    tok.push(x);
                    has = true;
                }
            }
            '|' => {
                if has {
                    cur.push(std::mem::take(&mut tok));
                    has = false;
                }
                if cur.is_empty() {
                    return Err("empty pipeline stage".into());
                }
                stages.push(Stage { name: cur.remove(0), argv: std::mem::take(&mut cur) });
            }
            c if c.is_whitespace() => {
                if has {
                    cur.push(std::mem::take(&mut tok));
                    has = false;
                }
            }
            c => {
                tok.push(c);
                has = true;
            }
        }
    }
    if has {
        cur.push(tok);
    }
    if cur.is_empty() {
        return Err(if stages.is_empty() { "pipeline required".into() } else { "empty pipeline stage".into() });
    }
    stages.push(Stage { name: cur.remove(0), argv: cur });
    Ok(stages)
}

/// `--k v`, `--k=v`, bare `--flag`, positionals in `_`. `exec` keeps its command verbatim.
fn parse_args(stage: &Stage) -> Map<String, Value> {
    let mut m = Map::new();
    let mut pos = Vec::new();
    let mut i = 0;
    let a = &stage.argv;
    while i < a.len() {
        let t = &a[i];
        if stage.name == "exec" && !pos.is_empty() {
            pos.push(Value::String(t.clone()));
            i += 1;
            continue;
        }
        if let Some(k) = t.strip_prefix("--").filter(|k| !k.is_empty()) {
            if let Some((k, v)) = k.split_once('=') {
                m.insert(k.into(), Value::String(v.into()));
            } else if stage.name == "exec" && matches!(k, "json" | "shell") {
                m.insert(k.into(), Value::Bool(true));
            } else if a.get(i + 1).is_some_and(|n| !n.starts_with("--")) && !matches!(k, "desc" | "emit" | "each" | "preview-from-stdin" | "dry-run" | "json" | "shell") {
                m.insert(k.into(), Value::String(a[i + 1].clone()));
                i += 1;
            } else {
                m.insert(k.into(), Value::Bool(true));
            }
        } else {
            pos.push(Value::String(t.clone()));
        }
        i += 1;
    }
    m.insert("_".into(), Value::Array(pos));
    m
}

fn path_get<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for p in path.split('.').filter(|s| !s.is_empty()) {
        cur = match cur {
            Value::Object(o) => o.get(p)?,
            Value::Array(a) => a.get(p.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(cur)
}

fn as_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Template filters (Lobster core/filters).
fn apply_filters(mut v: Value, chain: &[&str]) -> Result<Value, String> {
    for f in chain {
        let parts = split_filter(f.trim());
        let (name, args) = parts.split_first().ok_or("empty filter")?;
        let arg = |i: usize| args.get(i).map(String::as_str);
        v = match name.as_str() {
            "upper" => as_text(&v).to_uppercase().into(),
            "lower" => as_text(&v).to_lowercase().into(),
            "trim" => as_text(&v).trim().into(),
            "truncate" => {
                let n = arg(0).and_then(|n| n.parse().ok()).unwrap_or(80);
                let s = as_text(&v);
                if s.chars().count() > n { format!("{}...", s.chars().take(n).collect::<String>()).into() } else { s.into() }
            }
            "replace" => as_text(&v).replace(arg(0).unwrap_or(""), arg(1).unwrap_or("")).into(),
            "split" => json!(as_text(&v).split(arg(0).unwrap_or(",")).collect::<Vec<_>>()),
            "first" => v.as_array().map(|a| a.first().cloned().unwrap_or(Value::Null)).unwrap_or(v),
            "last" => v.as_array().map(|a| a.last().cloned().unwrap_or(Value::Null)).unwrap_or(v),
            "length" => json!(match &v {
                Value::Array(a) => a.len(),
                Value::String(s) => s.chars().count(),
                _ => 0,
            }),
            "join" => match &v {
                Value::Array(a) => a.iter().map(as_text).collect::<Vec<_>>().join(arg(0).unwrap_or(", ")).into(),
                _ => as_text(&v).into(),
            },
            "json" => serde_json::to_string_pretty(&v).unwrap_or_default().into(),
            "string" => as_text(&v).into(),
            "default" => {
                if v.is_null() || v == "" {
                    arg(0).unwrap_or("").into()
                } else {
                    v
                }
            }
            "round" => {
                let d = arg(0).and_then(|n| n.parse::<i32>().ok()).unwrap_or(0);
                match v.as_f64().or_else(|| as_text(&v).parse().ok()) {
                    Some(n) => json!((n * 10f64.powi(d)).round() / 10f64.powi(d)),
                    None => v,
                }
            }
            "date" => {
                let ms = v.as_u64().or_else(|| as_text(&v).trim().parse().ok()).or_else(|| super::parse_iso(&as_text(&v)));
                match ms {
                    None => as_text(&v).into(),
                    Some(ms) => {
                        let iso = super::iso(ms);
                        match arg(0) {
                            None => iso.into(),
                            Some(fmt) => fmt.replace("YYYY", &iso[0..4]).replace("MM", &iso[5..7]).replace("DD", &iso[8..10]).replace("HH", &iso[11..13]).replace("mm", &iso[14..16]).replace("ss", &iso[17..19]).into(),
                        }
                    }
                }
            }
            other => return Err(format!("Unknown template filter: {other}")),
        };
    }
    Ok(v)
}

fn split_filter(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = s.chars().peekable();
    while it.peek().is_some() {
        while it.peek() == Some(&' ') {
            it.next();
        }
        let Some(&c) = it.peek() else { break };
        let mut a = String::new();
        if c == '"' || c == '\'' {
            it.next();
            while let Some(x) = it.next() {
                if x == c {
                    break;
                }
                if x == '\\' {
                    if let Some(y) = it.next() {
                        a.push(y);
                    }
                    continue;
                }
                a.push(x);
            }
        } else {
            while let Some(&x) = it.peek() {
                if x == ' ' {
                    break;
                }
                a.push(x);
                it.next();
            }
        }
        out.push(a);
    }
    out
}

fn render_template(tpl: &str, item: &Value, filters: bool) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = tpl;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find("}}") else {
            out.push_str(&rest[i..]);
            return Ok(out);
        };
        let expr = rest[i + 2..i + j].trim();
        let mut parts = expr.split('|');
        let key = parts.next().unwrap_or("").trim();
        let v = if key == "." || key == "this" { item.clone() } else { path_get(item, key).cloned().unwrap_or(Value::Null) };
        let chain: Vec<&str> = parts.collect();
        let v = if filters { apply_filters(v, &chain)? } else { v };
        out.push_str(&as_text(&v));
        rest = &rest[i + j + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn loose_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::String(s)) | (Value::String(s), Value::Number(x)) => s.trim().parse::<f64>().ok() == x.as_f64(),
        (Value::Bool(x), Value::String(s)) | (Value::String(s), Value::Bool(x)) => s == &x.to_string(),
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}

fn where_pred(expr: &str) -> Result<impl Fn(&Value) -> bool, String> {
    let ops = ["==", "!=", "<=", ">=", "=", "<", ">"];
    let (at, op) = expr.char_indices().find_map(|(i, _)| ops.iter().find(|o| expr[i..].starts_with(**o)).map(|o| (i, *o))).ok_or_else(|| format!("Invalid where expression: {expr}"))?;
    let path = expr[..at].trim().to_string();
    if path.is_empty() || !path.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') {
        return Err(format!("Invalid where expression: {expr}"));
    }
    let raw = expr[at + op.len()..].trim();
    let value = match raw {
        "true" => json!(true),
        "false" => json!(false),
        "null" => Value::Null,
        r => r.parse::<f64>().ok().filter(|_| !r.is_empty()).map(|n| json!(n)).unwrap_or_else(|| json!(r)),
    };
    let op = if op == "=" { "==" } else { op };
    Ok(move |item: &Value| {
        let l = path_get(item, &path).cloned().unwrap_or(Value::Null);
        let num = |v: &Value| v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()));
        match op {
            "==" => loose_eq(&l, &value),
            "!=" => !loose_eq(&l, &value),
            _ => match (num(&l), num(&value)) {
                (Some(a), Some(b)) => match op {
                    "<" => a < b,
                    "<=" => a <= b,
                    ">" => a > b,
                    _ => a >= b,
                },
                _ => {
                    let (a, b) = (as_text(&l), as_text(&value));
                    match op {
                        "<" => a < b,
                        "<=" => a <= b,
                        ">" => a > b,
                        _ => a >= b,
                    }
                }
            },
        }
    })
}

fn cmp_values(a: &Value, b: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    match (a, b) {
        (Value::Null, Value::Null) => Equal,
        (Value::Null, _) => Greater,
        (_, Value::Null) => Less,
        (Value::Number(x), Value::Number(y)) => x.as_f64().partial_cmp(&y.as_f64()).unwrap_or(Equal),
        (Value::String(x), Value::String(y)) => x.cmp(y),
        (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
        _ => a.to_string().cmp(&b.to_string()),
    }
}

// ───────────────────────── runtime ─────────────────────────

/// Why a run stopped early.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Halt {
    ApprovalRequest { prompt: String, items: Vec<Value>, #[serde(default, skip_serializing_if = "Option::is_none")] preview: Option<String> },
    InputRequest { prompt: String, #[serde(rename = "responseSchema")] response_schema: Value, #[serde(default, skip_serializing_if = "Option::is_none")] defaults: Option<Value>, #[serde(default, skip_serializing_if = "Option::is_none")] subject: Option<Value> },
}

pub enum Ran {
    Done(Vec<Value>),
    /// Halted at stage `at` (resume continues after it).
    Halted { at: usize, halt: Halt },
}

/// Everything stages need.
pub struct Rt<'a> {
    pub env: &'a Env,
    pub ctx: &'a ToolCtx,
    pub cwd: PathBuf,
    pub vars: Vec<(String, String)>,
    pub deadline: Instant,
    pub max_bytes: u64,
}

impl Rt<'_> {
    fn left(&self) -> Result<Duration, String> {
        let l = self.deadline.saturating_duration_since(Instant::now());
        if l.is_zero() || self.ctx.cancel.is_cancelled() {
            return Err("lobster runtime timed out".into());
        }
        Ok(l)
    }

    fn state_dir(&self) -> PathBuf {
        self.env.dir.join("lobster/kv")
    }

    fn state_file(&self, key: &str) -> Result<PathBuf, String> {
        if key.is_empty() || key.len() > 128 || !key.chars().all(|c| c.is_ascii_alphanumeric() || "._-:".contains(c)) || key.starts_with('.') {
            return Err(format!("invalid state key `{key}`"));
        }
        Ok(self.state_dir().join(format!("{}.json", key.replace(':', "__"))))
    }

    /// Run a process with stdin, a deadline and an output cap.
    pub fn process(&self, argv: &[String], stdin: Option<String>, timeout: Option<Duration>) -> Result<String, String> {
        use std::process::Stdio;
        let t = timeout.map(|t| t.min(self.left().unwrap_or_default())).unwrap_or(self.left()?);
        let mut cmd = seagent_core::platform::layout::program_command(&argv[0]);
        cmd.args(&argv[1..]).current_dir(&self.cwd).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
        for (k, v) in &self.vars {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { format!("exec command not found: {}", argv[0]) } else { format!("{}: {e}", argv[0]) })?;
        if let Some(s) = stdin {
            let mut w = child.stdin.take().unwrap();
            std::thread::spawn(move || {
                let _ = w.write_all(s.as_bytes());
            });
        }
        let max = self.max_bytes as usize;
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let read = |r: Option<Box<dyn Read + Send>>| {
            let flag = flag.clone();
            std::thread::spawn(move || {
                let mut out = Vec::new();
                if let Some(mut r) = r {
                    let mut buf = [0u8; 8192];
                    while let Ok(n) = r.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        out.extend_from_slice(&buf[..n]);
                        if out.len() > max {
                            flag.store(true, std::sync::atomic::Ordering::SeqCst);
                            return (out, true);
                        }
                    }
                }
                (out, false)
            })
        };
        let so = read(child.stdout.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
        let se = read(child.stderr.take().map(|s| Box::new(s) as Box<dyn Read + Send>));
        let until = Instant::now() + t;
        let status = loop {
            if let Some(s) = child.try_wait().map_err(|e| e.to_string())? {
                break s;
            }
            if Instant::now() >= until || self.ctx.cancel.is_cancelled() || flag.load(std::sync::atomic::Ordering::SeqCst) {
                let _ = child.kill();
                let _ = child.wait();
                if flag.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(format!("{} output exceeded maxStdoutBytes", argv[0]));
                }
                return Err(format!("exec timed out: {}", argv.join(" ")));
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let (out, over) = so.join().unwrap_or_default();
        let (err, _) = se.join().unwrap_or_default();
        if over {
            return Err(format!("{} output exceeded maxStdoutBytes", argv[0]));
        }
        let (out, err) = (String::from_utf8_lossy(&out).into_owned(), String::from_utf8_lossy(&err).into_owned());
        if !status.success() {
            let why = if !err.trim().is_empty() { err.trim().to_string() } else if !out.trim().is_empty() { out.trim().to_string() } else { argv.join(" ") };
            return Err(format!("exec failed ({}): {why}", status.code().unwrap_or(-1)));
        }
        Ok(out)
    }
}

fn tool_allowed(cfg: &LobsterConfig, name: &str) -> bool {
    !cfg.invoke_deny.iter().any(|d| d == name) && (cfg.invoke_allow.is_empty() || cfg.invoke_allow.iter().any(|a| a == name))
}

/// The input object `openclaw.invoke` sends to a tool (per item with `--each`).
fn invoke_inputs(args: &Map<String, Value>, items: &[Value]) -> Result<Vec<Value>, String> {
    let mut base = match args.get("args-json").or(args.get("argsJson")).and_then(|v| v.as_str()) {
        Some(s) => serde_json::from_str::<Value>(s).map_err(|_| "openclaw.invoke --args-json must be valid JSON".to_string())?,
        None => json!({}),
    };
    if let Some(a) = args.get("action").and_then(|v| v.as_str()) {
        if base.is_object() && base.get("action").is_none() {
            base["action"] = a.into();
        }
    }
    if args.get("each") == Some(&Value::Bool(true)) {
        if !base.is_object() {
            return Err("openclaw.invoke --each requires --args-json to be an object".into());
        }
        let key = args.get("item-key").or(args.get("itemKey")).and_then(|v| v.as_str()).unwrap_or("item");
        return Ok(items.iter().map(|it| {
            let mut b = base.clone();
            b[key] = it.clone();
            b
        }).collect());
    }
    Ok(vec![base])
}

fn exec_argv(args: &Map<String, Value>) -> Result<Vec<String>, String> {
    let pos: Vec<String> = args["_"].as_array().map(|a| a.iter().map(as_text).collect()).unwrap_or_default();
    if pos.is_empty() {
        return Err("exec requires a command".into());
    }
    Ok(if args.get("shell") == Some(&Value::Bool(true)) { super::sh_argv(pos.join(" ")) } else { pos })
}

/// Run `stages[start..]` over `input`.
pub fn run_stages(rt: &Rt, stages: &[Stage], mut items: Vec<Value>, start: usize) -> Result<Ran, String> {
    for (i, st) in stages.iter().enumerate().skip(start) {
        rt.left()?;
        let a = parse_args(st);
        let pos = |n: usize| a["_"].get(n).and_then(|v| v.as_str()).map(str::to_string);
        let s = |k: &str| a.get(k).and_then(|v| v.as_str()).map(str::to_string);
        items = match st.name.as_str() {
            "exec" => {
                let argv = exec_argv(&a)?;
                let stdin = match s("stdin").as_deref() {
                    None => None,
                    Some("json") => Some(serde_json::to_string(&items).unwrap_or_default()),
                    Some("jsonl") => Some(items.iter().map(|x| format!("{x}\n")).collect()),
                    Some("raw") => Some(items.iter().map(as_text).collect::<Vec<_>>().join("\n")),
                    Some(m) => return Err(format!("exec --stdin must be raw, json, or jsonl (got {m})")),
                };
                let out = rt.process(&argv, stdin, None)?;
                if a.get("json") == Some(&Value::Bool(true)) {
                    let t = out.trim();
                    let v: Value = serde_json::from_str(if t.is_empty() { "null" } else { t }).map_err(|e| format!("exec --json could not parse stdout as JSON: {e}"))?;
                    match v {
                        Value::Array(a) => a,
                        v => vec![v],
                    }
                } else {
                    out.lines().filter(|l| !l.is_empty()).map(|l| Value::String(l.into())).collect()
                }
            }
            "where" => {
                let e = pos(0).ok_or("where requires an expression (e.g. field=value)")?;
                let p = where_pred(&e)?;
                items.into_iter().filter(|x| p(x)).collect()
            }
            "pick" => {
                let spec = pos(0).ok_or("pick requires a comma-separated field list")?;
                let fields: Vec<&str> = spec.split(',').map(str::trim).filter(|f| !f.is_empty()).collect();
                items.into_iter().map(|x| if x.is_object() { Value::Object(fields.iter().map(|f| (f.to_string(), x.get(*f).cloned().unwrap_or(Value::Null))).collect()) } else { x }).collect()
            }
            "head" => {
                let n = match a.get("n") {
                    None => 10,
                    Some(v) => as_text(v).parse::<usize>().map_err(|_| "head --n must be a non-negative number")?,
                };
                items.into_iter().take(n).collect()
            }
            "sort" => {
                let key = s("key");
                let desc = a.get("desc") == Some(&Value::Bool(true));
                let k = |x: &Value| key.as_deref().map(|k| path_get(x, k).cloned().unwrap_or(Value::Null)).unwrap_or_else(|| x.clone());
                items.sort_by(|x, y| {
                    let c = cmp_values(&k(x), &k(y));
                    if desc { c.reverse() } else { c }
                });
                items
            }
            "dedupe" => {
                let key = s("key");
                let mut seen = std::collections::HashSet::new();
                items.into_iter().filter(|x| seen.insert(key.as_deref().map(|k| path_get(x, k).cloned().unwrap_or(Value::Null)).unwrap_or_else(|| x.clone()).to_string())).collect()
            }
            "groupBy" | "group_by" => {
                let key = s("key").filter(|k| !k.trim().is_empty()).ok_or("groupBy requires --key")?;
                let mut groups: Vec<(String, Value, Vec<Value>)> = Vec::new();
                for x in items {
                    let kv = path_get(&x, &key).cloned().unwrap_or(Value::Null);
                    let ks = kv.to_string();
                    match groups.iter_mut().find(|g| g.0 == ks) {
                        Some(g) => g.2.push(x),
                        None => groups.push((ks, kv, vec![x])),
                    }
                }
                groups.into_iter().map(|(_, k, v)| json!({"key": k, "count": v.len(), "items": v})).collect()
            }
            "map" => {
                let (wrap, unwrap) = (s("wrap"), s("unwrap"));
                if wrap.is_some() && unwrap.is_some() {
                    return Err("map cannot use both --wrap and --unwrap".into());
                }
                let assigns: Vec<(String, String)> = a["_"].as_array().into_iter().flatten().filter_map(|t| t.as_str()?.split_once('=').filter(|(k, _)| !k.trim().is_empty()).map(|(k, v)| (k.trim().to_string(), v.to_string()))).collect();
                let mut out = Vec::new();
                for item in items {
                    if let Some(u) = &unwrap {
                        out.push(item.get(u).cloned().unwrap_or(Value::Null));
                        continue;
                    }
                    let mut cur = match &wrap {
                        Some(w) => json!({ w.clone(): item.clone() }),
                        None => item.clone(),
                    };
                    if !assigns.is_empty() {
                        if !cur.is_object() {
                            cur = json!({"value": cur});
                        }
                        for (k, v) in &assigns {
                            cur[k] = render_template(v, &item, false)?.into();
                        }
                    }
                    out.push(cur);
                }
                out
            }
            "template" => {
                let tpl = match (s("text"), s("file")) {
                    (Some(t), _) => t,
                    (None, Some(f)) => std::fs::read_to_string(rt.cwd.join(f)).map_err(|e| format!("template --file: {e}"))?,
                    _ => {
                        let p: Vec<String> = a["_"].as_array().into_iter().flatten().map(as_text).collect();
                        if p.is_empty() {
                            return Err("template requires --text or --file (or positional text)".into());
                        }
                        p.join(" ")
                    }
                };
                items.iter().map(|x| render_template(&tpl, x, true).map(Value::String)).collect::<Result<_, _>>()?
            }
            // In tool mode renderers keep the typed items in the envelope.
            "json" | "table" => items,
            "approve" => {
                let prompt = s("prompt").unwrap_or_else(|| "Approve?".into());
                let preview = (a.get("preview-from-stdin") == Some(&Value::Bool(true))).then(|| {
                    let n = s("limit").and_then(|l| l.parse().ok()).unwrap_or(5);
                    let head: Vec<&Value> = items.iter().take(n).collect();
                    if head.iter().all(|x| x.is_string()) { head.iter().map(|x| as_text(x)).collect::<Vec<_>>().join("\n") } else { serde_json::to_string_pretty(&head).unwrap_or_default() }
                });
                return Ok(Ran::Halted { at: i, halt: Halt::ApprovalRequest { prompt, items, preview } });
            }
            "ask" => {
                let prompt = s("prompt").unwrap_or_else(|| "Input required".into());
                let schema = match s("schema") {
                    Some(t) => serde_json::from_str::<Value>(&t).map_err(|_| "ask response schema is invalid".to_string())?,
                    None => json!({"type": "string"}),
                };
                let defaults = s("default").map(|d| serde_json::from_str(&d).unwrap_or(Value::String(d)));
                return Ok(Ran::Halted { at: i, halt: Halt::InputRequest { prompt, response_schema: schema, defaults, subject: (!items.is_empty()).then(|| json!(items)) } });
            }
            "state.get" => {
                let key = pos(0).ok_or("state.get requires a key")?;
                vec![read_json::<Value>(&rt.state_file(&key)?).unwrap_or(Value::Null)]
            }
            "state.set" => {
                let key = pos(0).ok_or("state.set requires a key")?;
                let v = if items.len() == 1 { items[0].clone() } else { json!(items) };
                write_json(&rt.state_file(&key)?, &v)?;
                items
            }
            "diff.last" => {
                let key = s("key").or_else(|| pos(0)).ok_or("diff.last requires --key")?;
                let after = if items.len() == 1 { items[0].clone() } else { json!(items) };
                let f = rt.state_file(&key)?;
                let before = read_json::<Value>(&f).unwrap_or(Value::Null);
                write_json(&f, &after)?;
                vec![json!({"kind": "diff.last", "key": key, "changed": before != after, "before": before, "after": after})]
            }
            "llm.invoke" | "llm_task.invoke" => {
                let prompt = s("prompt").or_else(|| a["_"].as_array().filter(|p| !p.is_empty()).map(|p| p.iter().map(as_text).collect::<Vec<_>>().join(" "))).ok_or("llm.invoke requires --prompt")?;
                let schema = match s("output-schema") {
                    Some(t) => Some(serde_json::from_str::<Value>(&t).map_err(|_| "llm.invoke --output-schema must be a JSON object".to_string())?),
                    None => None,
                };
                let retries = s("max-validation-retries").and_then(|n| n.parse::<u32>().ok()).unwrap_or(1);
                let mut req = llm_task::Request { prompt: prompt.clone(), input: if items.len() == 1 { items[0].clone() } else { json!(items) }, schema, model: s("model"), provider: s("provider").filter(|p| p != "openclaw" && p != "seagent"), max_tokens: s("max-output-tokens").and_then(|n| n.parse().ok()), temperature: s("temperature").and_then(|n| n.parse().ok()), timeout_ms: Some(rt.left()?.as_millis() as u64), ..Default::default() };
                let mut attempt = 0;
                let v = loop {
                    match llm_task::run(rt.env, &req, &rt.ctx.cancel) {
                        Ok((v, _)) => break v,
                        Err(e) if e.starts_with("LLM JSON did not match schema") || e == "LLM returned invalid JSON" => {
                            if attempt >= retries {
                                return Err(e);
                            }
                            attempt += 1;
                            req.prompt = format!("{prompt}\n\nYour previous answer was rejected: {e}. Return JSON that matches the schema.");
                        }
                        Err(e) => return Err(e),
                    }
                };
                match v {
                    Value::Array(a) => a,
                    v => vec![v],
                }
            }
            "openclaw.invoke" | "clawd.invoke" | "seagent.invoke" => {
                let name = s("tool").ok_or(format!("{} requires --tool", st.name))?;
                if !tool_allowed(&rt.env.cfg.lobster, &name) {
                    return Err(format!("Tool not available: {name}"));
                }
                let k = rt.env.kernel()?;
                let tool = k.tools.iter().find(|t| t.spec().name == name).cloned().ok_or(format!("Tool not available: {name}"))?;
                let mut out = Vec::new();
                for input in invoke_inputs(&a, &items)? {
                    let r = tool.call(rt.ctx, input);
                    if r.is_error {
                        return Err(format!("{name} failed: {}", r.content));
                    }
                    out.push(serde_json::from_str::<Value>(&r.content).unwrap_or(Value::String(r.content)));
                }
                out
            }
            other => return Err(format!("Unknown command: {other}")),
        };
    }
    Ok(Ran::Done(items))
}

/// The effects a pipeline declares before it runs (judged by seagent's gates as one call).
pub fn pipeline_effects(env: &Env, ctx: &ToolCtx, stages: &[Stage], start: usize) -> Vec<Effect> {
    let mut e = Vec::new();
    for st in stages.iter().skip(start) {
        let a = parse_args(st);
        match st.name.as_str() {
            "exec" => {
                if let Ok(argv) = exec_argv(&a) {
                    let line = if argv[0] == "sh" && argv.len() == 3 { argv[2].clone() } else { argv.iter().map(|x| if x.contains(char::is_whitespace) { format!("'{x}'") } else { x.clone() }).collect::<Vec<_>>().join(" ") };
                    e.push(Effect::Exec { command: line });
                }
            }
            "openclaw.invoke" | "clawd.invoke" | "seagent.invoke" => {
                let name = a.get("tool").and_then(|v| v.as_str()).unwrap_or("");
                if let (Ok(k), true) = (env.kernel(), tool_allowed(&env.cfg.lobster, name)) {
                    if let Some(t) = k.tools.iter().find(|t| t.spec().name == name) {
                        for input in invoke_inputs(&a, &[Value::Null]).unwrap_or_default() {
                            e.extend(t.effects(ctx, &input));
                        }
                    }
                }
            }
            "template" => {
                if let Some(f) = a.get("file").and_then(|v| v.as_str()) {
                    e.push(Effect::Read { path: ctx.resolve(f) });
                }
            }
            _ => {}
        }
    }
    e
}

// ───────────────────────── workflow files ─────────────────────────

fn load_workflow(p: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let v = if p.extension().is_some_and(|x| x == "json") { serde_json::from_str(&text).map_err(|e| format!("{}: {e}", p.display()))? } else { yaml::parse(&text).map_err(|e| format!("{}: {e}", p.display()))? };
    if !v["steps"].is_array() {
        return Err(format!("{}: workflow needs a `steps` list", p.display()));
    }
    let mut ids = std::collections::HashSet::new();
    for s in v["steps"].as_array().unwrap() {
        let id = s["id"].as_str().filter(|i| !i.is_empty()).ok_or("every workflow step needs an id")?;
        if !ids.insert(id.to_string()) {
            return Err(format!("duplicate step id `{id}`"));
        }
    }
    Ok(v)
}

fn wf_args(wf: &Value, given: &Map<String, Value>) -> Map<String, Value> {
    let mut a = Map::new();
    for (k, spec) in wf["args"].as_object().into_iter().flatten() {
        if let Some(d) = spec.get("default").or(if spec.is_object() { None } else { Some(spec) }) {
            a.insert(k.clone(), d.clone());
        }
    }
    for (k, v) in given {
        a.insert(k.clone(), v.clone());
    }
    a
}

/// `${arg}` then `$step.path` substitution.
fn resolve(s: &str, args: &Map<String, Value>, results: &Map<String, Value>) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("${") {
        out.push_str(&rest[..i]);
        match rest[i + 2..].find('}') {
            Some(j) if args.contains_key(&rest[i + 2..i + 2 + j]) => {
                out.push_str(&as_text(&args[&rest[i + 2..i + 2 + j]]));
                rest = &rest[i + 3 + j..];
            }
            _ => {
                out.push_str("${");
                rest = &rest[i + 2..];
            }
        }
    }
    out.push_str(rest);
    let s = out;
    let mut out = String::new();
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < b.len() {
        if b[i] == '$' && i + 1 < b.len() && (b[i + 1].is_ascii_alphanumeric() || b[i + 1] == '_') {
            let mut j = i + 1;
            while j < b.len() && (b[j].is_ascii_alphanumeric() || "_-.".contains(b[j])) {
                j += 1;
            }
            let r: String = b[i + 1..j].iter().collect();
            let r = r.trim_end_matches('.');
            if let Some((id, path)) = r.split_once('.') {
                if let Some(step) = results.get(id) {
                    let v = path_get(step, path).cloned();
                    out.push_str(&match v {
                        None if path == "approved" || path == "skipped" => "false".into(),
                        None => String::new(),
                        Some(v) => as_text(&v),
                    });
                    i += 1 + r.len();
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// `when:` / `condition:` expressions: `$step.path`, literals, ==, !=, <, <=, >, >=, and/or/not (&&, ||, !), parens.
pub fn condition(c: &Value, results: &Map<String, Value>) -> Result<bool, String> {
    match c {
        Value::Null => Ok(true),
        Value::Bool(b) => Ok(*b),
        Value::String(s) => {
            let toks = ctok(s)?;
            let mut i = 0;
            let v = cor(&toks, &mut i, results)?;
            if i != toks.len() {
                return Err(format!("Unsupported condition: {s}"));
            }
            Ok(truthy(&v))
        }
        _ => Err("Unsupported condition type".into()),
    }
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        _ => true,
    }
}

#[derive(Debug, Clone, PartialEq)]
enum T {
    V(Value),
    Ref(String, String),
    Op(&'static str),
    L,
    R,
}

fn ctok(s: &str) -> Result<Vec<T>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        if ch.is_whitespace() {
            i += 1;
            continue;
        }
        let two: String = c[i..(i + 2).min(c.len())].iter().collect();
        let op = match two.as_str() {
            "==" => Some("eq"),
            "!=" => Some("neq"),
            "<=" => Some("lte"),
            ">=" => Some("gte"),
            "&&" => Some("and"),
            "||" => Some("or"),
            _ => None,
        };
        if let Some(o) = op {
            out.push(T::Op(o));
            i += 2;
            continue;
        }
        match ch {
            '(' => out.push(T::L),
            ')' => out.push(T::R),
            '<' => out.push(T::Op("lt")),
            '>' => out.push(T::Op("gt")),
            '!' => out.push(T::Op("not")),
            '"' | '\'' => {
                let mut j = i + 1;
                let mut t = String::new();
                while j < c.len() && c[j] != ch {
                    t.push(c[j]);
                    j += 1;
                }
                if j >= c.len() {
                    return Err(format!("Unsupported condition: {s}"));
                }
                out.push(T::V(Value::String(t)));
                i = j;
            }
            '$' => {
                let mut j = i + 1;
                while j < c.len() && (c[j].is_ascii_alphanumeric() || "_-.".contains(c[j])) {
                    j += 1;
                }
                let r: String = c[i + 1..j].iter().collect();
                let (id, path) = r.split_once('.').ok_or_else(|| format!("Unsupported condition: {s}"))?;
                out.push(T::Ref(id.into(), path.into()));
                i = j - 1;
            }
            _ => {
                let mut j = i;
                while j < c.len() && !c[j].is_whitespace() && !"()<>=!&|".contains(c[j]) {
                    j += 1;
                }
                let w: String = c[i..j].iter().collect();
                out.push(match w.as_str() {
                    "and" => T::Op("and"),
                    "or" => T::Op("or"),
                    "not" => T::Op("not"),
                    "true" => T::V(json!(true)),
                    "false" => T::V(json!(false)),
                    "null" => T::V(Value::Null),
                    w => w.parse::<f64>().map(|n| T::V(json!(n))).unwrap_or_else(|_| T::V(Value::String(w.into()))),
                });
                i = j - 1;
            }
        }
        i += 1;
    }
    Ok(out)
}

fn cor(t: &[T], i: &mut usize, r: &Map<String, Value>) -> Result<Value, String> {
    let mut l = cand(t, i, r)?;
    while t.get(*i) == Some(&T::Op("or")) {
        *i += 1;
        let x = cand(t, i, r)?;
        l = json!(truthy(&l) || truthy(&x));
    }
    Ok(l)
}
fn cand(t: &[T], i: &mut usize, r: &Map<String, Value>) -> Result<Value, String> {
    let mut l = ceq(t, i, r)?;
    while t.get(*i) == Some(&T::Op("and")) {
        *i += 1;
        let x = ceq(t, i, r)?;
        l = json!(truthy(&l) && truthy(&x));
    }
    Ok(l)
}
fn ceq(t: &[T], i: &mut usize, r: &Map<String, Value>) -> Result<Value, String> {
    let l = cun(t, i, r)?;
    let Some(T::Op(o)) = t.get(*i).cloned() else { return Ok(l) };
    if !matches!(o, "eq" | "neq" | "lt" | "lte" | "gt" | "gte") {
        return Ok(l);
    }
    *i += 1;
    let x = cun(t, i, r)?;
    let num = |v: &Value| v.as_f64().or_else(|| v.as_str().filter(|s| !s.trim().is_empty()).and_then(|s| s.trim().parse().ok()));
    Ok(json!(match o {
        "eq" => l == x || (l.is_number() && x.is_number() && l.as_f64() == x.as_f64()),
        "neq" => !(l == x || (l.is_number() && x.is_number() && l.as_f64() == x.as_f64())),
        _ => match (num(&l), num(&x)) {
            (Some(a), Some(b)) => match o {
                "lt" => a < b,
                "lte" => a <= b,
                "gt" => a > b,
                _ => a >= b,
            },
            _ => false,
        },
    }))
}
fn cun(t: &[T], i: &mut usize, r: &Map<String, Value>) -> Result<Value, String> {
    if t.get(*i) == Some(&T::Op("not")) {
        *i += 1;
        return Ok(json!(!truthy(&cun(t, i, r)?)));
    }
    let tok = t.get(*i).cloned().ok_or("Unsupported condition")?;
    *i += 1;
    match tok {
        T::L => {
            let v = cor(t, i, r)?;
            if t.get(*i) != Some(&T::R) {
                return Err("Unsupported condition: missing )".into());
            }
            *i += 1;
            Ok(v)
        }
        T::Ref(id, path) => {
            let step = r.get(&id).ok_or_else(|| format!("Unknown step reference: {id}.{path}"))?;
            Ok(path_get(step, &path).cloned().unwrap_or(if path == "approved" || path == "skipped" { json!(false) } else { Value::Null }))
        }
        T::V(v) => Ok(v),
        _ => Err("Unsupported condition".into()),
    }
}

fn output_items(r: Option<&Value>) -> Vec<Value> {
    let Some(r) = r else { return vec![] };
    for k in ["json", "response"] {
        if let Some(v) = r.get(k).filter(|v| !v.is_null()) {
            return match v {
                Value::Array(a) => a.clone(),
                v => vec![v.clone()],
            };
        }
    }
    r.get("stdout").filter(|s| s.as_str().is_some_and(|s| !s.is_empty())).map(|s| vec![s.clone()]).unwrap_or_default()
}

fn parse_json_loose(s: &str) -> Value {
    serde_json::from_str(s.trim()).unwrap_or(Value::Null)
}

/// Saved progress of a paused run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Paused {
    pub kind: String,
    pub approval_id: String,
    pub created_ms: u64,
    pub cwd: PathBuf,
    pub session: String,
    pub halt: Halt,
    // pipeline
    #[serde(default)]
    pub stages: Vec<Stage>,
    #[serde(default)]
    pub resume_at: usize,
    // workflow
    #[serde(default)]
    pub file: Option<PathBuf>,
    #[serde(default)]
    pub args: Map<String, Value>,
    #[serde(default)]
    pub results: Map<String, Value>,
    #[serde(default)]
    pub step: usize,
    /// Within a workflow pipeline step that halted on a stage.
    #[serde(default)]
    pub inner: Option<(Vec<Stage>, usize)>,
    #[serde(default)]
    pub initiated_by: Option<String>,
}

fn paused_dir(dir: &Path) -> PathBuf {
    dir.join("lobster/runs")
}

pub fn list_paused(dir: &Path) -> Value {
    let mut out = vec![];
    for e in std::fs::read_dir(paused_dir(dir)).into_iter().flatten().flatten() {
        if let Some(p) = read_json::<Paused>(&e.path()) {
            let (gate, prompt) = match &p.halt {
                Halt::ApprovalRequest { prompt, .. } => ("approval", prompt.clone()),
                Halt::InputRequest { prompt, .. } => ("input", prompt.clone()),
            };
            out.push(json!({"approvalId": p.approval_id, "kind": p.kind, "gate": gate, "prompt": prompt, "session": p.session, "file": p.file, "createdMs": p.created_ms}));
        }
    }
    json!(out)
}

enum WfOut {
    Done(Vec<Value>),
    Halted(Box<Paused>),
}

fn run_workflow(rt: &Rt, file: &Path, wf: &Value, mut st: Paused) -> Result<WfOut, String> {
    let steps = wf["steps"].as_array().cloned().unwrap_or_default();
    let mut last: Option<String> = steps.get(..st.step).and_then(|s| s.iter().rev().find(|x| st.results.get(x["id"].as_str().unwrap_or("")).is_some_and(|r| r["skipped"] != true))).and_then(|x| x["id"].as_str().map(str::to_string));
    let mut skip_rest = false;
    let mut idx = st.step;
    while idx < steps.len() {
        let step = &steps[idx];
        let id = step["id"].as_str().unwrap_or("").to_string();
        if skip_rest {
            st.results.insert(id.clone(), json!({"id": id, "skipped": true}));
            idx += 1;
            continue;
        }
        let cond = step.get("when").or(step.get("condition")).cloned().unwrap_or(Value::Null);
        let cond = match cond {
            Value::String(s) => Value::String(resolve(&s, &st.args, &Map::new())),
            v => v,
        };
        if !condition(&cond, &st.results)? {
            st.results.insert(id.clone(), json!({"id": id, "skipped": true}));
            idx += 1;
            continue;
        }
        let res = |s: &str| resolve(s, &st.args, &st.results);
        let stdin_ref = step["stdin"].as_str().map(|s| s.trim().to_string());
        let stdin_val: Option<Value> = stdin_ref.as_deref().map(|r| match r.strip_prefix('$').and_then(|x| x.split_once('.')) {
            Some((sid, path)) => st.results.get(sid).and_then(|x| path_get(x, path)).cloned().unwrap_or(Value::Null),
            None => Value::String(res(r)),
        });
        let mut vars = rt.vars.clone();
        for (k, v) in wf["env"].as_object().into_iter().flatten().chain(step["env"].as_object().into_iter().flatten()) {
            vars.push((k.clone(), res(&as_text(v))));
        }
        let cwd = step["cwd"].as_str().or(wf["cwd"].as_str()).map(|c| rt.cwd.join(res(c))).unwrap_or_else(|| rt.cwd.clone());
        let srt = Rt { env: rt.env, ctx: rt.ctx, cwd, vars, deadline: rt.deadline, max_bytes: rt.max_bytes };
        // Approval and input gates.
        if let Some(ap) = step.get("approval").filter(|a| !a.is_null() && *a != false) {
            let prompt = match ap {
                Value::String(s) => res(s),
                Value::Object(o) => o.get("prompt").and_then(|p| p.as_str()).map(res).unwrap_or_else(|| "Approve?".into()),
                _ => "Approve?".into(),
            };
            let items = stdin_val.as_ref().map(|v| match v {
                Value::Array(a) => a.clone(),
                Value::Null => vec![],
                v => vec![v.clone()],
            }).unwrap_or_default();
            st.step = idx;
            st.inner = None;
            st.halt = Halt::ApprovalRequest { prompt, items, preview: None };
            return Ok(WfOut::Halted(Box::new(st)));
        }
        if let Some(inp) = step.get("input").filter(|a| !a.is_null()) {
            let prompt = inp["prompt"].as_str().map(res).unwrap_or_else(|| "Input required".into());
            let schema = inp.get("responseSchema").or(inp.get("schema")).cloned().unwrap_or(json!({"type": "string"}));
            st.step = idx;
            st.inner = None;
            st.halt = Halt::InputRequest { prompt, response_schema: schema, defaults: inp.get("defaults").cloned(), subject: stdin_val.clone() };
            return Ok(WfOut::Halted(Box::new(st)));
        }
        let retry = step["retry"]["max"].as_u64().unwrap_or(1).clamp(1, 10);
        let delay = Duration::from_millis(step["retry"]["delay_ms"].as_u64().unwrap_or(0).min(60_000));
        let timeout = step["timeout_ms"].as_u64().map(Duration::from_millis);
        let mut attempt = 0;
        let outcome = loop {
            attempt += 1;
            let r: Result<Option<Value>, String> = (|| {
                if let Some(cmd) = step["run"].as_str().or(step["command"].as_str()) {
                    let line = res(cmd);
                    let stdin = stdin_val.as_ref().map(as_text);
                    let out = srt.process(&super::sh_argv(line), stdin, timeout)?;
                    return Ok(Some(json!({"id": id, "stdout": out, "json": parse_json_loose(&out)})));
                }
                if let Some(p) = step["pipeline"].as_str() {
                    let stages = parse_pipeline(&res(p))?;
                    let input = match &stdin_val {
                        Some(Value::Array(a)) => a.clone(),
                        Some(Value::Null) | None => vec![],
                        Some(v) => vec![v.clone()],
                    };
                    let srt2 = Rt { deadline: timeout.map(|t| Instant::now() + t).map(|d| d.min(srt.deadline)).unwrap_or(srt.deadline), ..Rt { env: srt.env, ctx: srt.ctx, cwd: srt.cwd.clone(), vars: srt.vars.clone(), deadline: srt.deadline, max_bytes: srt.max_bytes } };
                    return match run_stages(&srt2, &stages, input, 0)? {
                        Ran::Done(items) => {
                            let v = if items.len() == 1 { items[0].clone() } else { json!(items) };
                            let stdout = match &v {
                                Value::String(s) => s.clone(),
                                v => v.to_string(),
                            };
                            Ok(Some(json!({"id": id, "stdout": stdout, "json": v})))
                        }
                        Ran::Halted { at, halt } => Err(format!("\u{0}halt:{}", serde_json::to_string(&(stages, at, halt)).unwrap_or_default())),
                    };
                }
                Err(format!("step `{id}` needs run, command, pipeline, approval or input"))
            })();
            match r {
                Err(e) if e.starts_with("\u{0}halt:") => break Err(e),
                Err(_) if attempt < retry => {
                    std::thread::sleep(delay);
                    continue;
                }
                other => break other,
            }
        };
        match outcome {
            Ok(Some(v)) => {
                st.results.insert(id.clone(), v);
                last = Some(id.clone());
            }
            Ok(None) => {}
            Err(e) if e.starts_with("\u{0}halt:") => {
                let (stages, at, halt): (Vec<Stage>, usize, Halt) = serde_json::from_str(&e["\u{0}halt:".len()..]).map_err(|e| e.to_string())?;
                st.step = idx;
                st.inner = Some((stages, at));
                st.halt = halt;
                let _ = file;
                return Ok(WfOut::Halted(Box::new(st)));
            }
            Err(e) => match step["on_error"].as_str().unwrap_or("fail") {
                "continue" => {
                    st.results.insert(id.clone(), json!({"id": id, "error": e}));
                }
                "skip_rest" => {
                    st.results.insert(id.clone(), json!({"id": id, "error": e}));
                    skip_rest = true;
                }
                _ => return Err(format!("step `{id}` failed: {e}")),
            },
        }
        idx += 1;
    }
    Ok(WfOut::Done(output_items(last.as_ref().and_then(|l| st.results.get(l)))))
}

// ───────────────────────── the tool ─────────────────────────

pub struct LobsterTool(pub Arc<Env>);

const WORKFLOW_EXTS: &[&str] = &["lobster", "yaml", "yml", "json"];

fn workflow_file(pipeline: &str, cwd: &Path) -> Result<Option<PathBuf>, String> {
    let t = pipeline.trim();
    let ext_ok = Path::new(t).extension().and_then(|e| e.to_str()).is_some_and(|e| WORKFLOW_EXTS.contains(&e.to_ascii_lowercase().as_str()));
    if t.is_empty() || t.contains('|') || !ext_ok {
        return Ok(None);
    }
    let p = if Path::new(t).is_absolute() { PathBuf::from(t) } else { cwd.join(t) };
    match std::fs::metadata(&p) {
        Ok(m) if m.is_file() => Ok(Some(p)),
        Ok(_) => Err("Workflow path is not a file".into()),
        Err(_) if t.contains(char::is_whitespace) => Ok(None),
        Err(e) => Err(format!("{}: {e}", p.display())),
    }
}

impl LobsterTool {
    fn cwd(&self, ctx: &ToolCtx, p: &Value) -> Result<PathBuf, String> {
        match p["cwd"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
            None => Ok(ctx.workspace.clone()),
            Some(c) if Path::new(c).is_absolute() => Err("cwd must be a relative path".into()),
            Some(c) => {
                let r = ctx.workspace.join(c);
                let (rc, wc) = (r.canonicalize().map_err(|e| format!("cwd: {e}"))?, ctx.workspace.canonicalize().map_err(|e| e.to_string())?);
                if !rc.starts_with(&wc) {
                    return Err("cwd must stay within the workspace".into());
                }
                Ok(rc)
            }
        }
    }

    fn load_paused(&self, p: &Value) -> Result<(PathBuf, Paused), String> {
        let token = p["token"].as_str().map(str::trim).filter(|s| !s.is_empty());
        let aid = p["approvalId"].as_str().map(str::trim).filter(|s| !s.is_empty());
        let dir = paused_dir(&self.0.dir);
        match (token, aid) {
            (Some(t), _) => {
                let key = t.strip_prefix("lob_").filter(|k| k.len() == 48 && k.chars().all(|c| c.is_ascii_hexdigit())).ok_or("invalid resume token")?;
                let f = dir.join(format!("{key}.json"));
                read_json::<Paused>(&f).map(|s| (f, s)).ok_or_else(|| "Resume state not found".to_string())
            }
            (None, Some(a)) => {
                for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                    if let Some(s) = read_json::<Paused>(&e.path()).filter(|s| s.approval_id == a) {
                        return Ok((e.path(), s));
                    }
                }
                Err(format!("Approval ID \"{a}\" not found or expired"))
            }
            _ => Err("token or approvalId required".into()),
        }
    }

    fn save(&self, st: &Paused) -> Result<(String, String), String> {
        let key = seagent_net::crypto::hex(&seagent_net::crypto::random_bytes(24));
        write_json(&paused_dir(&self.0.dir).join(format!("{key}.json")), st)?;
        Ok((format!("lob_{key}"), st.approval_id.clone()))
    }

    fn envelope(&self, out: Result<(String, Vec<Value>, Option<Paused>), String>, max: u64) -> Result<Value, String> {
        let (status, output, paused) = out?;
        let mut env = json!({"protocolVersion": 1, "ok": true, "status": status, "output": output, "requiresApproval": null});
        if let Some(st) = paused {
            let (token, aid) = self.save(&st)?;
            match &st.halt {
                Halt::ApprovalRequest { prompt, items, preview } => {
                    env["status"] = "needs_approval".into();
                    env["requiresApproval"] = json!({"type": "approval_request", "prompt": prompt, "items": items, "preview": preview, "resumeToken": token, "approvalId": aid});
                }
                Halt::InputRequest { prompt, response_schema, defaults, subject } => {
                    env["status"] = "needs_input".into();
                    env["requiresInput"] = json!({"type": "input_request", "prompt": prompt, "responseSchema": response_schema, "defaults": defaults, "subject": subject, "resumeToken": token, "approvalId": aid});
                }
            }
        }
        if serde_json::to_string_pretty(&env).unwrap_or_default().len() as u64 > max {
            return Err("lobster runtime result exceeded maxStdoutBytes".into());
        }
        Ok(env)
    }

    fn new_paused(kind: &str, cwd: &Path, session: &str) -> Paused {
        Paused { kind: kind.into(), approval_id: seagent_net::crypto::random_token(8), created_ms: now_ms(), cwd: cwd.to_path_buf(), session: session.into(), halt: Halt::ApprovalRequest { prompt: String::new(), items: vec![], preview: None }, stages: vec![], resume_at: 0, file: None, args: Map::new(), results: Map::new(), step: 0, inner: None, initiated_by: std::env::var("LOBSTER_APPROVAL_INITIATED_BY").ok() }
    }

    fn run(&self, ctx: &ToolCtx, p: &Value) -> Result<Value, String> {
        let cfg = &self.0.cfg.lobster;
        let action = p["action"].as_str().map(str::trim).filter(|s| !s.is_empty()).ok_or("action required")?;
        let timeout = p["timeoutMs"].as_u64().filter(|n| *n > 0).unwrap_or(cfg.timeout_ms).max(200);
        let max = p["maxStdoutBytes"].as_u64().filter(|n| *n > 0).unwrap_or(cfg.max_stdout_bytes).max(1024);
        let deadline = Instant::now() + Duration::from_millis(timeout);
        match action {
            "run" => {
                let cwd = self.cwd(ctx, p)?;
                let rt = Rt { env: &self.0, ctx, cwd: cwd.clone(), vars: vec![], deadline, max_bytes: max };
                let pipeline = p["pipeline"].as_str().map(str::trim).filter(|s| !s.is_empty()).ok_or("pipeline required")?;
                if let Some(file) = workflow_file(pipeline, &cwd)? {
                    let args: Map<String, Value> = match p["argsJson"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
                        Some(a) => serde_json::from_str(a).map_err(|_| "run --args-json must be valid JSON".to_string())?,
                        None => Map::new(),
                    };
                    let wf = load_workflow(&file)?;
                    let mut st = Self::new_paused("workflow", &cwd, &ctx.session_id);
                    st.file = Some(file.clone());
                    st.args = wf_args(&wf, &args);
                    let out = run_workflow(&rt, &file, &wf, st).map(|o| match o {
                        WfOut::Done(items) => ("ok".to_string(), items, None),
                        WfOut::Halted(st) => (String::new(), vec![], Some(*st)),
                    });
                    return self.envelope(out, max);
                }
                let stages = parse_pipeline(pipeline)?;
                let out = run_stages(&rt, &stages, vec![], 0).map(|r| match r {
                    Ran::Done(items) => ("ok".to_string(), items, None),
                    Ran::Halted { at, halt } => {
                        let mut st = Self::new_paused("pipeline", &cwd, &ctx.session_id);
                        st.stages = stages.clone();
                        st.resume_at = at + 1;
                        st.halt = halt;
                        (String::new(), vec![], Some(st))
                    }
                });
                self.envelope(out, max)
            }
            "resume" => {
                let has_ap = p["approve"].is_boolean();
                let has_resp = p["responseJson"].is_string();
                let has_cancel = !p["cancel"].is_null();
                if [has_ap, has_resp, has_cancel].iter().filter(|x| **x).count() != 1 {
                    return Err("resume requires exactly one of approve, responseJson, or cancel: true".into());
                }
                if has_cancel && p["cancel"] != true {
                    return Err("cancel must be true".into());
                }
                let (file, mut st) = self.load_paused(p)?;
                let response = match p["responseJson"].as_str() {
                    Some(r) => Some(serde_json::from_str::<Value>(r).map_err(|_| "responseJson must be valid JSON".to_string())?),
                    None => None,
                };
                if has_cancel {
                    std::fs::remove_file(&file).map_err(|_| "Resume state not found".to_string())?;
                    return self.envelope(Ok(("cancelled".into(), vec![], None)), max);
                }
                // Validate the decision against the kind of gate before consuming the state.
                let (gate_items, response) = match (&st.halt, response) {
                    (Halt::InputRequest { .. }, None) => return Err(format!("{} input resumes require response", st.kind)),
                    (Halt::InputRequest { response_schema, .. }, Some(r)) => {
                        seagent_plugin::schema::validate(response_schema, &r).map_err(|e| format!("response failed schema validation at {e}"))?;
                        (vec![], Some(r))
                    }
                    (Halt::ApprovalRequest { .. }, Some(_)) => return Err("approval resumes require approved=true|false, not response".into()),
                    (Halt::ApprovalRequest { items, .. }, None) => (items.clone(), None),
                };
                if matches!(st.halt, Halt::ApprovalRequest { .. }) {
                    if let Some(req) = self.required_approver(&st)? {
                        let by = p["approvedBy"].as_str().map(str::to_string).or_else(|| std::env::var("LOBSTER_APPROVAL_APPROVED_BY").ok());
                        if req.0.as_deref().is_some_and(|r| by.as_deref() != Some(r)) {
                            return Err(format!("approval requires approver `{}`", req.0.unwrap()));
                        }
                        if req.1 && (by.is_none() || by == st.initiated_by) {
                            return Err("approval requires a different approver than the initiator".into());
                        }
                    }
                }
                std::fs::remove_file(&file).map_err(|_| "Resume state not found".to_string())?;
                if p["approve"] == false {
                    return self.envelope(Ok(("cancelled".into(), vec![], None)), max);
                }
                let rt = Rt { env: &self.0, ctx, cwd: st.cwd.clone(), vars: vec![], deadline, max_bytes: max };
                if st.kind == "pipeline" {
                    let input = response.map(|r| vec![r]).unwrap_or(gate_items);
                    let stages = st.stages.clone();
                    let out = run_stages(&rt, &stages, input, st.resume_at).map(|r| match r {
                        Ran::Done(items) => ("ok".to_string(), items, None),
                        Ran::Halted { at, halt } => {
                            let mut s2 = Self::new_paused("pipeline", &st.cwd, &ctx.session_id);
                            s2.stages = stages.clone();
                            s2.resume_at = at + 1;
                            s2.halt = halt;
                            (String::new(), vec![], Some(s2))
                        }
                    });
                    return self.envelope(out, max);
                }
                let wfile = st.file.clone().ok_or("workflow resume state has no file")?;
                let wf = load_workflow(&wfile)?;
                let steps = wf["steps"].as_array().cloned().unwrap_or_default();
                let id = steps.get(st.step).and_then(|s| s["id"].as_str()).unwrap_or("").to_string();
                match st.inner.take() {
                    // A gate inside a pipeline step: finish that pipeline, then go on.
                    Some((stages, at)) => {
                        let input = response.map(|r| vec![r]).unwrap_or(gate_items);
                        match run_stages(&rt, &stages, input, at + 1)? {
                            Ran::Done(items) => {
                                let v = if items.len() == 1 { items[0].clone() } else { json!(items) };
                                st.results.insert(id.clone(), json!({"id": id, "stdout": as_text(&v), "json": v}));
                            }
                            Ran::Halted { at: a2, halt } => {
                                st.inner = Some((stages, a2));
                                st.halt = halt;
                                st.approval_id = seagent_net::crypto::random_token(8);
                                return self.envelope(Ok((String::new(), vec![], Some(st))), max);
                            }
                        }
                    }
                    None => {
                        let r = match response {
                            Some(r) => json!({"id": id, "response": r, "json": r}),
                            None => json!({"id": id, "approved": true, "approvedBy": p["approvedBy"], "json": gate_items}),
                        };
                        st.results.insert(id, r);
                    }
                }
                st.step += 1;
                st.approval_id = seagent_net::crypto::random_token(8);
                let out = run_workflow(&rt, &wfile, &wf, st).map(|o| match o {
                    WfOut::Done(items) => ("ok".to_string(), items, None),
                    WfOut::Halted(s) => (String::new(), vec![], Some(*s)),
                });
                self.envelope(out, max)
            }
            other => Err(format!("Unknown action: {other}")),
        }
    }

    /// (required approver, require different approver) for a workflow approval step.
    fn required_approver(&self, st: &Paused) -> Result<Option<(Option<String>, bool)>, String> {
        let Some(f) = &st.file else { return Ok(None) };
        if st.inner.is_some() {
            return Ok(None);
        }
        let wf = load_workflow(f)?;
        let ap = &wf["steps"][st.step]["approval"];
        if !ap.is_object() {
            return Ok(None);
        }
        let req = ap.get("required_approver").or(ap.get("requiredApprover")).and_then(|v| v.as_str()).map(str::to_string);
        let diff = ap.get("require_different_approver").or(ap.get("requireDifferentApprover")) == Some(&json!(true));
        Ok(Some((req, diff)))
    }
}

impl Tool for LobsterTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "lobster".into(),
            description: "Run Lobster workflows: typed JSON pipelines (`exec --json …| where x>=1 | pick a,b | approve --prompt '…' | openclaw.invoke --tool <seagent tool> --args-json …`, plus llm.invoke, template, map, sort, head, dedupe, groupBy, state.get/set, diff.last, ask) or a workflow file (.lobster/.yaml/.json with run/pipeline/approval/input steps) with resumable approvals and structured input. For needs_approval, show the prompt and items to the user, then resume with token + approve. For needs_input, ask the user the returned prompt, then resume with their answer as responseJson matching responseSchema. Use cancel: true to cancel a checkpoint. Use it for repeatable multi-step automations, not single actions.".into(),
            input_schema: json!({"type": "object", "properties": {
                "action": {"type": "string", "enum": ["run", "resume"]},
                "pipeline": {"type": "string", "description": "Pipeline text, or a workflow file path."},
                "argsJson": {"type": "string", "description": "Workflow args as a JSON object."},
                "token": {"type": "string", "description": "resumeToken from a paused run."},
                "approvalId": {"type": "string", "description": "Short approval id instead of token."},
                "approve": {"type": "boolean"},
                "approvedBy": {"type": "string", "description": "Approver id for workflow identity checks."},
                "responseJson": {"type": "string", "description": "User's answer as JSON for an input checkpoint. Use instead of approve."},
                "cancel": {"type": "boolean", "enum": [true]},
                "cwd": {"type": "string", "description": "Relative working directory inside the workspace."},
                "timeoutMs": {"type": "integer", "minimum": 1},
                "maxStdoutBytes": {"type": "integer", "minimum": 1}
            }, "required": ["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let env = &self.0;
        match input["action"].as_str() {
            Some("run") => {
                let Some(pl) = input["pipeline"].as_str() else { return vec![] };
                let cwd = self.cwd(ctx, input).unwrap_or_else(|_| ctx.workspace.clone());
                if let Ok(Some(f)) = workflow_file(pl, &cwd) {
                    let mut e = vec![Effect::Read { path: f.clone() }];
                    if let Ok(wf) = load_workflow(&f) {
                        let given: Map<String, Value> = input["argsJson"].as_str().and_then(|a| serde_json::from_str(a).ok()).unwrap_or_default();
                        e.extend(workflow_effects(env, ctx, &wf, &wf_args(&wf, &given), 0));
                    }
                    return e;
                }
                parse_pipeline(pl).map(|s| pipeline_effects(env, ctx, &s, 0)).unwrap_or_default()
            }
            Some("resume") if input["approve"] == true || input["responseJson"].is_string() => match self.load_paused(input) {
                Ok((_, st)) if st.kind == "pipeline" => pipeline_effects(env, ctx, &st.stages, st.resume_at),
                Ok((_, st)) => {
                    let mut e = st.inner.as_ref().map(|(s, at)| pipeline_effects(env, ctx, s, at + 1)).unwrap_or_default();
                    if let Some(wf) = st.file.as_ref().and_then(|f| load_workflow(f).ok()) {
                        e.extend(workflow_effects(env, ctx, &wf, &st.args, st.step + 1));
                    }
                    e
                }
                Err(_) => vec![],
            },
            _ => vec![],
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok(v) => ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
            Err(e) => ToolOutput::err(json!({"protocolVersion": 1, "ok": false, "error": {"message": e}}).to_string()),
        }
    }
}

/// Effects of workflow steps from `from` on (shell lines with args substituted).
fn workflow_effects(env: &Env, ctx: &ToolCtx, wf: &Value, args: &Map<String, Value>, from: usize) -> Vec<Effect> {
    let mut e = Vec::new();
    for s in wf["steps"].as_array().into_iter().flatten().skip(from) {
        if let Some(c) = s["run"].as_str().or(s["command"].as_str()) {
            e.push(Effect::Exec { command: resolve(c, args, &Map::new()) });
        }
        if let Some(p) = s["pipeline"].as_str() {
            if let Ok(st) = parse_pipeline(&resolve(p, args, &Map::new())) {
                e.extend(pipeline_effects(env, ctx, &st, 0));
            }
        }
    }
    e
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;

    fn tool(tag: &str, replies: &[&str]) -> (LobsterTool, ToolCtx) {
        let (env, _) = testkit::env(tag, replies, "");
        let ws = testkit::temp(&format!("{tag}-ws"));
        let ctx = testkit::ctx(&env, &ws);
        (LobsterTool(env), ctx)
    }

    fn out(t: &LobsterTool, ctx: &ToolCtx, v: Value) -> Value {
        let o = t.call(ctx, v);
        let r: Value = serde_json::from_str(&o.content).unwrap_or_else(|_| panic!("{}", o.content));
        assert!(!o.is_error, "{r}");
        r
    }

    #[test]
    fn parsing() {
        let s = parse_pipeline("exec --json --shell 'echo [1,2,3]' | where '0>=0' | template --text \"a \\\"b\\\" {{x}}\"").unwrap();
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].argv, vec!["--json", "--shell", "echo [1,2,3]"]);
        assert_eq!(s[2].argv[1], "a \"b\" {{x}}");
        assert!(parse_pipeline("a | | b").is_err());
        assert!(parse_pipeline("a 'x").is_err());
        let a = parse_args(&Stage { name: "exec".into(), argv: vec!["--json".into(), "gh".into(), "--repo".into(), "x".into()] });
        assert_eq!(a["_"], json!(["gh", "--repo", "x"]));
    }

    #[test]
    fn typed_pipeline_stages() {
        let (t, ctx) = tool("lob1", &[]);
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "exec --json echo '[{\"n\":3,\"t\":\"c\"},{\"n\":1,\"t\":\"a\"},{\"n\":2,\"t\":\"b\"},{\"n\":2,\"t\":\"b\"}]' | dedupe | where n>=2 | sort --key n | pick t,n | json"}));
        assert_eq!(v["status"], "ok");
        assert_eq!(v["output"], json!([{"t": "b", "n": 2}, {"t": "c", "n": 3}]));
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "exec --shell 'printf \"x\\ny\\n\"' | map --wrap name id={{.}}! | template --text '{{name | upper}}-{{id}}' | head --n 1"}));
        assert_eq!(v["output"], json!(["X-x!"]));
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "exec --json echo '[{\"k\":\"a\"},{\"k\":\"b\"},{\"k\":\"a\"}]' | groupBy --key k"}));
        assert_eq!(v["output"][0]["count"], 2);
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "exec --json --shell 'echo 5' | diff.last --key k1"}));
        assert_eq!(v["output"][0]["changed"], true);
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "exec --json --shell 'echo 5' | diff.last --key k1"}));
        assert_eq!(v["output"][0]["changed"], false);
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "exec --json echo '{\"a\":1}' | state.set s1 | exec --stdin json --json cat"}));
        assert_eq!(v["output"], json!([{"a": 1}]));
        let e = t.call(&ctx, json!({"action": "run", "pipeline": "exec --shell 'exit 3'"}));
        assert!(e.is_error && e.content.contains("exec failed (3)"), "{}", e.content);
        assert!(t.call(&ctx, json!({"action": "run", "pipeline": "nosuch"})).content.contains("Unknown command"));
        let e = t.call(&ctx, json!({"action": "run", "pipeline": "exec --shell 'sleep 5'", "timeoutMs": 300}));
        assert!(e.content.contains("timed out"), "{}", e.content);
        assert!(t.call(&ctx, json!({"action": "run", "pipeline": "exec --shell 'yes'", "maxStdoutBytes": 2000})).content.contains("exceeded maxStdoutBytes"));
        assert!(t.call(&ctx, json!({"action": "run", "pipeline": "json", "cwd": "/etc"})).content.contains("relative"));
        assert!(t.call(&ctx, json!({"action": "run", "pipeline": "json", "cwd": ".."})).content.contains("within the workspace"));
        // Effects are declared up front.
        let eff = t.effects(&ctx, &json!({"action": "run", "pipeline": "exec --shell 'rm -rf x' | exec ls -la"}));
        assert_eq!(eff, vec![Effect::Exec { command: "rm -rf x".into() }, Effect::Exec { command: "ls -la".into() }]);
    }

    #[test]
    fn approvals_pause_and_resume() {
        let (t, ctx) = tool("lob2", &[]);
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "exec --json --shell 'echo [1,2]' | approve --prompt 'Send these?' --preview-from-stdin | exec --stdin json --json cat"}));
        assert_eq!(v["status"], "needs_approval");
        assert_eq!(v["requiresApproval"]["prompt"], "Send these?");
        assert_eq!(v["requiresApproval"]["items"], json!([1, 2]));
        let token = v["requiresApproval"]["resumeToken"].as_str().unwrap().to_string();
        assert_eq!(list_paused(&t.0.dir).as_array().unwrap().len(), 1);
        assert_eq!(t.effects(&ctx, &json!({"action": "resume", "token": token, "approve": true})), vec![Effect::Exec { command: "cat".into() }]);
        assert!(t.call(&ctx, json!({"action": "resume", "token": token})).content.contains("exactly one of"));
        assert!(t.call(&ctx, json!({"action": "resume", "token": token, "responseJson": "1"})).content.contains("approval resumes require"));
        let v = out(&t, &ctx, json!({"action": "resume", "token": token, "approve": true}));
        assert_eq!((v["status"].as_str(), v["output"].clone()), (Some("ok"), json!([1, 2])));
        assert!(t.call(&ctx, json!({"action": "resume", "token": token, "approve": true})).content.contains("Resume state not found"));
        // Rejection cancels; approvalId works too.
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "approve"}));
        let aid = v["requiresApproval"]["approvalId"].as_str().unwrap();
        assert_eq!(out(&t, &ctx, json!({"action": "resume", "approvalId": aid, "approve": false}))["status"], "cancelled");
        // Input checkpoints validate the response.
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "ask --prompt 'How many?' --schema '{\"type\":\"integer\"}' | map --wrap n"}));
        assert_eq!(v["status"], "needs_input");
        let tok = v["requiresInput"]["resumeToken"].as_str().unwrap();
        assert!(t.call(&ctx, json!({"action": "resume", "token": tok, "approve": true})).content.contains("input resumes require response"));
        assert!(t.call(&ctx, json!({"action": "resume", "token": tok, "responseJson": "\"x\""})).content.contains("schema validation"));
        assert_eq!(out(&t, &ctx, json!({"action": "resume", "token": tok, "responseJson": "4"}))["output"], json!([{"n": 4}]));
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "approve"}));
        assert_eq!(out(&t, &ctx, json!({"action": "resume", "token": v["requiresApproval"]["resumeToken"], "cancel": true}))["status"], "cancelled");
    }

    #[test]
    fn workflow_file_with_gates_conditions_and_llm() {
        let (t, ctx) = tool("lob3", &["{\"jacket\": true}"]);
        let wf = r#"
name: jacket-advice
args:
  location:
    default: Phoenix
steps:
  - id: fetch
    run: echo '{"city":"${location}","temp":9}'
  - id: confirm
    approval: Want jacket advice for ${location}?
    stdin: $fetch.json
  - id: advice
    pipeline: >
      llm.invoke --prompt "Should I wear a jacket?"
      --output-schema '{"type":"object","required":["jacket"]}'
    stdin: $fetch.json
    when: $confirm.approved
  - id: never
    run: echo nope
    when: $fetch.json.temp > 30
  - id: flaky
    run: exit 1
    on_error: continue
"#;
        std::fs::write(ctx.workspace.join("w.lobster"), wf).unwrap();
        let eff = t.effects(&ctx, &json!({"action": "run", "pipeline": "w.lobster", "argsJson": "{\"location\":\"Oslo\"}"}));
        assert!(eff.contains(&Effect::Exec { command: "echo '{\"city\":\"Oslo\",\"temp\":9}'".into() }), "{eff:?}");
        let v = out(&t, &ctx, json!({"action": "run", "pipeline": "w.lobster", "argsJson": "{\"location\":\"Oslo\"}"}));
        assert_eq!(v["status"], "needs_approval", "{v}");
        assert_eq!(v["requiresApproval"]["prompt"], "Want jacket advice for Oslo?");
        assert_eq!(v["requiresApproval"]["items"][0]["temp"], 9);
        let v = out(&t, &ctx, json!({"action": "resume", "token": v["requiresApproval"]["resumeToken"], "approve": true}));
        // `flaky` failed with on_error=continue; the last successful step is `advice`.
        assert_eq!(v["status"], "ok", "{v}");
        assert_eq!(v["output"], json!([{"jacket": true}]));
        // Conditions.
        let mut r = Map::new();
        r.insert("a".into(), json!({"approved": true, "json": {"n": 3}}));
        assert!(condition(&json!("$a.approved && $a.json.n >= 3"), &r).unwrap());
        assert!(!condition(&json!("not ($a.json.n == 3)"), &r).unwrap());
        assert!(condition(&json!("$b.x"), &r).is_err());
    }

    #[test]
    fn invoke_calls_allowed_seagent_tools() {
        let (t, ctx) = tool("lob4", &[]);
        // The kernel in the test env has no tools; denied names fail before lookup.
        assert!(t.call(&ctx, json!({"action": "run", "pipeline": "openclaw.invoke --tool gateway --action config.get"})).content.contains("Tool not available: gateway"));
        assert!(t.call(&ctx, json!({"action": "run", "pipeline": "openclaw.invoke --tool missing"})).content.contains("Tool not available: missing"));
        let ins = invoke_inputs(&parse_args(&Stage { name: "openclaw.invoke".into(), argv: vec!["--tool".into(), "x".into(), "--action".into(), "send".into(), "--each".into(), "--item-key".into(), "message".into(), "--args-json".into(), "{\"to\":\"a\"}".into()] }), &[json!("hi"), json!("yo")]).unwrap();
        assert_eq!(ins, vec![json!({"to": "a", "action": "send", "message": "hi"}), json!({"to": "a", "action": "send", "message": "yo"})]);
    }
}
