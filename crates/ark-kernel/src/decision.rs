//! Typed model sub-calls: `structured_output` (OpenClaw: the run's final answer
//! must validate against a schema), `llm_task` (extensions/llm-task: JSON-only
//! function call with optional schema) and `decision_evaluate` (OpenClaw
//! src/decisions + decision-tool: boolean / choice / score / sort / tags / box
//! questions over supplied state, answered by a decision provider).
//!
//! Decision backends: `llm` (any configured chat model, JSON reply validated per
//! question) and `openai` (the OpenAI `/decisions` endpoint used by OpenClaw's
//! bundled OpenAI decision provider).

use crate::jsonschema;
use crate::kernel::Host;
use ark_core::{Block, Cancel, Effect, Message, ModelRequest, Role, SystemSegment, Tool, ToolCtx, ToolOutput, ToolSchema, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ───────────────────────── structured_output ─────────────────────────

pub const STRUCTURED_OUTPUT: &str = "structured_output";
/// Reminders when a turn ends without the required submission.
pub const STRUCTURED_NUDGES: u32 = 2;
pub const STRUCTURED_NUDGE: &str = "[This run has an output contract: submit your final answer by calling `structured_output` with {\"result\": <value matching the schema>}. Do not answer in prose.]";

/// Model-facing typed sub-call tools (`llm_task`, `decision_evaluate`). Registered by
/// `new_kernel`; `structured_output` stays a kernel tool (it only exists with a schema).
pub fn tools() -> Vec<Arc<dyn Tool>> {
    vec![Arc::new(LlmTask), Arc::new(DecisionEvaluate)]
}

pub fn structured_output_schema(schema: &Value) -> ToolSchema {
    ToolSchema {
        name: STRUCTURED_OUTPUT.into(),
        description: format!("Submit the final result. Call exactly once as {{\"result\": ...}}, where result matches this JSON Schema: {schema}"),
        input_schema: json!({"type":"object","properties":{"result":{"type":["object","array","string","number","boolean","null"]}},"required":["result"],"additionalProperties":false}),
    }
}

/// Validate a `structured_output` call. A string that fails but parses as JSON
/// that passes is accepted decoded (models often stringify objects).
pub fn check_structured(schema: &Value, input: &Value) -> Result<Value, String> {
    let Some(v) = input.get("result") else { return Err("structured_output needs {\"result\": …}".into()) };
    let errs = jsonschema::validate(schema, v);
    if errs.is_empty() {
        return Ok(v.clone());
    }
    if let Some(s) = v.as_str() {
        if let Ok(d) = serde_json::from_str::<Value>(s) {
            if jsonschema::is_valid(schema, &d) {
                return Ok(d);
            }
        }
    }
    Err(format!("result rejected by the schema:\n{}\nCall structured_output again with a corrected result.", errs.iter().map(|e| format!("- {e}")).collect::<Vec<_>>().join("\n")))
}

// ───────────────────────── config ─────────────────────────

/// `[decision]` — the decision provider for `decision_evaluate`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DecisionConfig {
    /// `provider/model`. Empty = `decision_evaluate` reports `unavailable`.
    pub model: String,
    /// `llm` (any chat model) or `openai` (POST {base_url}/decisions).
    pub backend: String,
    /// For `openai`.
    pub base_url: String,
    /// For `openai`; a `{{secret:NAME}}` reference.
    pub api_key: String,
    pub timeout_secs: u64,
}

impl Default for DecisionConfig {
    fn default() -> Self {
        DecisionConfig { model: String::new(), backend: "llm".into(), base_url: "https://api.openai.com/v1".into(), api_key: "{{secret:OPENAI_API_KEY}}".into(), timeout_secs: 30 }
    }
}

/// `[llm_task]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LlmTaskConfig {
    /// `provider/model`; empty = the aux model.
    pub default_model: String,
    pub max_tokens: u32,
    pub timeout_secs: u64,
    /// Let the caller pick `model`.
    pub allow_model_override: bool,
    /// When non-empty, every completion (default included) must use one of these.
    pub allowed_models: Vec<String>,
}

impl Default for LlmTaskConfig {
    fn default() -> Self {
        LlmTaskConfig { default_model: String::new(), max_tokens: 800, timeout_secs: 30, allow_model_override: true, allowed_models: vec![] }
    }
}

/// The prompt/limit/timeout bundle a decision task needs is assembled here once per call
/// site; splitting it further would just move the plumbing.
#[allow(clippy::too_many_arguments)]
fn complete(host: &Host, model: &str, system: &str, user: Vec<Block>, max_tokens: u32, temperature: Option<f32>, reasoning: Option<String>, timeout: Duration, cancel: &Cancel) -> Result<(String, String), String> {
    let (pid, name) = crate::context::split_model(model);
    let p = host.rt.resolver.provider(pid)?;
    let req = ModelRequest {
        model: name.to_string(),
        system: vec![SystemSegment { id: "task".into(), text: system.into(), cache: false }],
        messages: vec![Message { role: Role::User, content: user }],
        tools: vec![],
        max_tokens,
        temperature,
        cache_after_message: None,
        reasoning,
        options: Default::default(),
    };
    let c = cancel.with_deadline(Instant::now() + timeout);
    let r = p.complete(&req, &mut |_| {}, &c).map_err(|e| if c.timed_out() { format!("timed out after {}s", timeout.as_secs()) } else { e.to_string() })?;
    Ok((r.message.text(), model.to_string()))
}

// ───────────────────────── llm_task ─────────────────────────

pub struct LlmTask;

const LLM_TASK_SYSTEM: &str = "You are a JSON-only function. Return ONLY a valid JSON value. Do not wrap in markdown fences. Do not include commentary. Do not call tools.";

impl Tool for LlmTask {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "llm_task".into(),
            description: "Run a JSON-only LLM sub-task (draft, summarize, classify, extract) on `input`, optionally validated against a JSON Schema. The model sees only the prompt and input — no tools, no conversation. Returns the parsed JSON.".into(),
            input_schema: json!({"type":"object","properties":{
                "prompt":{"type":"string","description":"What to compute"},
                "input":{"description":"Any JSON input"},
                "schema":{"type":"object","description":"Optional JSON Schema the output must satisfy"},
                "model":{"type":"string","description":"provider/model override (when allowed)"},
                "thinking":{"type":"string","enum":["off","low","medium","high"]},
                "temperature":{"type":"number"},
                "maxTokens":{"type":"integer","minimum":1},
                "timeoutMs":{"type":"integer","minimum":1}},"required":["prompt"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Some(host) = Host::of(ctx) else { return ToolOutput::err("llm_task needs the ark kernel") };
        match llm_task(host, &input, &ctx.cancel) {
            Ok(v) => ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default()),
            Err(e) => ToolOutput::err(e),
        }
    }
}

pub(crate) fn llm_task(host: &Host, p: &Value, cancel: &Cancel) -> Result<Value, String> {
    let cfg = &host.rt.cfg.llm_task;
    let prompt = p.get("prompt").and_then(Value::as_str).unwrap_or("");
    if prompt.trim().is_empty() {
        return Err("prompt required".into());
    }
    let requested = p.get("model").and_then(Value::as_str).filter(|m| !m.trim().is_empty());
    if requested.is_some() && !cfg.allow_model_override {
        return Err("model override is not allowed for llm_task (llm_task.allow_model_override = false)".into());
    }
    let model = requested.map(str::to_string).unwrap_or_else(|| if cfg.default_model.is_empty() { host.rt.cfg.aux_model().to_string() } else { cfg.default_model.clone() });
    if !model.contains('/') {
        return Err(format!("provider/model could not be resolved (model={model})"));
    }
    if !cfg.allowed_models.is_empty() && !cfg.allowed_models.contains(&model) {
        return Err(format!("model `{model}` is not in llm_task.allowed_models"));
    }
    let thinking = p.get("thinking").and_then(Value::as_str).filter(|t| !t.is_empty());
    if let Some(t) = thinking {
        if !matches!(t, "off" | "low" | "medium" | "high") {
            return Err(format!("Invalid thinking level \"{t}\"."));
        }
    }
    let schema = jsonschema::coerce_schema(p.get("schema")).map_err(|e| e.replace("output_schema", "schema"))?;
    let input_json = serde_json::to_string_pretty(p.get("input").unwrap_or(&Value::Null)).map_err(|_| "input must be JSON-serializable".to_string())?;
    let max_tokens = p.get("maxTokens").and_then(Value::as_u64).map(|n| n as u32).unwrap_or(cfg.max_tokens);
    let timeout = Duration::from_millis(p.get("timeoutMs").and_then(Value::as_u64).unwrap_or(cfg.timeout_secs * 1000).max(1));
    let temperature = p.get("temperature").and_then(Value::as_f64).map(|t| t as f32);
    let (raw, _) = complete(host, &model, LLM_TASK_SYSTEM, vec![Block::text(format!("TASK:\n{prompt}\n\nINPUT_JSON:\n{input_json}\n"))], max_tokens, temperature, thinking.map(String::from), timeout, cancel)?;
    let parsed: Value = serde_json::from_str(&strip_fences(&raw)).map_err(|_| "LLM returned invalid JSON".to_string())?;
    if let Some(s) = &schema {
        let errs = jsonschema::validate(s, &parsed);
        if !errs.is_empty() {
            return Err(format!("LLM JSON did not match schema: {}", errs.join("; ")));
        }
    }
    Ok(parsed)
}

fn strip_fences(s: &str) -> String {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("```") {
        let rest = rest.split_once('\n').map(|(_, r)| r).unwrap_or("");
        return rest.trim_end().trim_end_matches("```").trim().to_string();
    }
    t.to_string()
}

// ───────────────────────── decision_evaluate ─────────────────────────

pub const MAX_QUESTIONS: usize = 16;
pub const MAX_IMAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq)]
pub enum State {
    Text(String),
    Json(Value),
    Image { media_type: String, data: String, text: Option<String> },
    List(Vec<(String, Value)>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    pub name: String,
    pub kind: String,
    pub instructions: Value,
    pub criteria: Value,
}

fn entry_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        v => v.to_string(),
    }
}

/// Parse and bound a decision batch (contract v1 or v2).
pub fn parse_batch(p: &Value) -> Result<(State, Vec<Question>), String> {
    let v2 = p.get("contractVersion").and_then(Value::as_u64) == Some(2);
    if let Some(cv) = p.get("contractVersion") {
        if cv.as_u64() != Some(2) {
            return Err("contractVersion must be 2 (or omitted for legacy state)".into());
        }
    }
    let raw = p.get("state").ok_or("`state` is required")?;
    let state = if v2 {
        let t = raw.get("type").and_then(Value::as_str).unwrap_or("");
        match t {
            "text" => State::Text(raw.get("text").and_then(Value::as_str).ok_or("text state needs `text`")?.into()),
            "json" => State::Json(raw.get("value").cloned().ok_or("json state needs `value`")?),
            "image" => {
                let uri = raw.get("dataUri").and_then(Value::as_str).ok_or("image state needs `dataUri`")?;
                let (head, data) = uri.split_once(',').ok_or("dataUri must be data:<mime>;base64,<data>")?;
                let media = head.strip_prefix("data:").and_then(|h| h.strip_suffix(";base64")).ok_or("dataUri must be data:<mime>;base64,<data>")?;
                if !["image/png", "image/jpeg", "image/webp"].contains(&media) {
                    return Err(format!("image dataUri must be PNG, JPEG or WebP, got {media}"));
                }
                if data.len() / 4 * 3 > MAX_IMAGE_BYTES {
                    return Err("image dataUri is larger than 4 MiB decoded".into());
                }
                State::Image { media_type: media.into(), data: data.into(), text: raw.get("text").and_then(Value::as_str).map(String::from) }
            }
            "list" => {
                let items = raw.get("items").and_then(Value::as_array).ok_or("list state needs `items`")?;
                let mut out = Vec::new();
                for it in items {
                    let id = it.get("id").and_then(Value::as_str).ok_or("list items need `id`")?;
                    if out.iter().any(|(i, _): &(String, Value)| i == id) {
                        return Err(format!("duplicate list item id `{id}`"));
                    }
                    out.push((id.to_string(), it.get("content").cloned().unwrap_or(Value::Null)));
                }
                State::List(out)
            }
            other => return Err(format!("contractVersion 2 state type `{other}`: use text, json, image or list")),
        }
    } else {
        match raw {
            Value::String(s) => State::Text(s.clone()),
            v => State::Json(v.clone()),
        }
    };
    let qs = p.get("questions").and_then(Value::as_object).ok_or("`questions` must be an object of named questions")?;
    if qs.is_empty() || qs.len() > MAX_QUESTIONS {
        return Err(format!("ask 1–{MAX_QUESTIONS} questions"));
    }
    let mut out = Vec::new();
    for (name, q) in qs {
        let kind = q.get("type").and_then(Value::as_str).ok_or_else(|| format!("question `{name}` needs a `type`"))?.to_string();
        let criteria = q.get("criteria").cloned().unwrap_or(Value::Null);
        let instructions = q.get("instructions").cloned().unwrap_or(Value::Null);
        match kind.as_str() {
            "boolean" => {
                if !criteria.is_null() && !criteria.as_object().is_some_and(|o| o.keys().all(|k| k == "true" || k == "false")) {
                    return Err(format!("`{name}`: boolean criteria are {{true, false}} or null"));
                }
            }
            "choice" if criteria.as_object().is_some_and(|o| o.len() >= 2) => {}
            "choice" => return Err(format!("`{name}`: choice criteria need at least 2 alternatives")),
            "score" if criteria.as_array().is_some_and(|a| a.len() >= 2) => {}
            "score" => return Err(format!("`{name}`: score criteria need at least 2 levels")),
            "tags" if criteria.as_object().is_some_and(|o| !o.is_empty()) => {}
            "tags" => return Err(format!("`{name}`: tags criteria need at least 1 tag")),
            "sort" if v2 && matches!(state, State::List(_)) => {}
            "sort" => return Err(format!("`{name}`: sort needs contractVersion 2 list state")),
            "box" if v2 && matches!(state, State::Image { .. }) && !instructions.is_null() => {}
            "box" => return Err(format!("`{name}`: box needs contractVersion 2 image state and non-null instructions")),
            other => return Err(format!("`{name}`: unknown question type `{other}`")),
        }
        if !v2 && !matches!(kind.as_str(), "boolean" | "choice" | "score") {
            return Err(format!("`{name}`: {kind} needs contractVersion 2"));
        }
        out.push(Question { name: name.clone(), kind, instructions, criteria });
    }
    Ok((state, out))
}

fn qerr(code: &str) -> Value {
    json!({"type": "error", "code": code})
}

/// Check one provider answer against its question; never infer missing estimates.
fn check_answer(q: &Question, a: &Value, state: &State) -> Value {
    let prob = |v: &Value| v.as_f64().filter(|p| (0.0..=1.0).contains(p));
    let conf = a.get("confidence").and_then(Value::as_f64).filter(|c| (0.0..=1.0).contains(c));
    let mut out = Map::new();
    out.insert("type".into(), q.kind.clone().into());
    if let Some(c) = conf {
        out.insert("confidence".into(), c.into());
    }
    match q.kind.as_str() {
        "boolean" => {
            let answer = match a.get("answer") {
                Some(Value::Bool(b)) => Some(Value::Bool(*b)),
                Some(Value::Null) | None => None,
                _ => return qerr("invalid-response"),
            };
            let p = a.get("probabilityTrue").and_then(prob);
            if answer.is_none() && p.is_none() && a.get("answer") != Some(&Value::Null) {
                return qerr("invalid-response");
            }
            out.insert("answer".into(), answer.unwrap_or(Value::Null));
            if let Some(p) = p {
                out.insert("probabilityTrue".into(), p.into());
            }
        }
        "choice" => {
            let alts: Vec<&String> = q.criteria.as_object().map(|o| o.keys().collect()).unwrap_or_default();
            match a.get("choice") {
                Some(Value::Null) => {
                    out.insert("choice".into(), Value::Null);
                }
                Some(Value::String(c)) if alts.contains(&c) => {
                    out.insert("choice".into(), c.clone().into());
                }
                _ => return qerr("invalid-response"),
            }
            if let Some(ps) = a.get("probabilities").and_then(Value::as_object) {
                if ps.keys().any(|k| !alts.contains(&k)) || ps.values().any(|v| prob(v).is_none()) {
                    return qerr("invalid-response");
                }
                out.insert("probabilities".into(), Value::Object(ps.clone()));
            }
        }
        "score" => {
            let n = q.criteria.as_array().map(|a| a.len()).unwrap_or(0) as f64;
            match a.get("score").and_then(Value::as_f64) {
                Some(s) if (0.0..=n - 1.0).contains(&s) => {
                    out.insert("score".into(), s.into());
                }
                _ => return qerr("invalid-response"),
            }
            if let Some(ps) = a.get("probabilities").and_then(Value::as_array) {
                if ps.len() as f64 != n || ps.iter().any(|v| prob(v).is_none()) {
                    return qerr("invalid-response");
                }
                out.insert("probabilities".into(), Value::Array(ps.clone()));
            }
        }
        "sort" => {
            let State::List(items) = state else { return qerr("unsupported-input") };
            let ids: Vec<&String> = items.iter().map(|(i, _)| i).collect();
            let order: Option<Vec<String>> = a.get("order").and_then(Value::as_array).map(|o| o.iter().filter_map(|x| x.as_str().map(String::from)).collect());
            match order {
                Some(o) if o.len() == ids.len() && ids.iter().all(|i| o.contains(i)) => {
                    out.insert("order".into(), json!(o));
                }
                _ => return qerr("invalid-response"),
            }
        }
        "tags" => {
            let names: Vec<&String> = q.criteria.as_object().map(|o| o.keys().collect()).unwrap_or_default();
            let Some(tags) = a.get("tags").and_then(Value::as_array) else { return qerr("invalid-response") };
            let mut v = Vec::new();
            for t in tags {
                let Some(id) = t.get("id").and_then(Value::as_str).filter(|i| names.iter().any(|n| n.as_str() == *i)) else { return qerr("invalid-response") };
                let applies = match t.get("applies") {
                    Some(Value::Bool(b)) => Value::Bool(*b),
                    _ => Value::Null,
                };
                let mut e = json!({"id": id, "applies": applies});
                if let Some(p) = t.get("probability").and_then(prob) {
                    e["probability"] = p.into();
                }
                v.push(e);
            }
            out.insert("tags".into(), Value::Array(v));
        }
        "box" => {
            let b = a.get("box");
            let edge = |k: &str| b.and_then(|b| b.get(k)).and_then(prob);
            match (edge("top"), edge("bottom"), edge("left"), edge("right")) {
                (Some(t), Some(bo), Some(l), Some(r)) if t <= bo && l <= r => {
                    out.insert("box".into(), json!({"top": t, "bottom": bo, "left": l, "right": r}));
                }
                _ if b.is_some_and(Value::is_null) => {
                    out.insert("box".into(), Value::Null);
                }
                _ => return qerr("invalid-response"),
            }
        }
        _ => return qerr("unsupported-input"),
    }
    Value::Object(out)
}

fn decision_prompt(state: &State, qs: &[Question]) -> (String, Vec<Block>) {
    let mut q = String::new();
    for x in qs {
        q.push_str(&format!("\n## {} ({})\n", x.name, x.kind));
        if !x.instructions.is_null() {
            q.push_str(&format!("Instructions: {}\n", entry_text(&x.instructions)));
        }
        match x.kind.as_str() {
            "boolean" => {
                if let Some(o) = x.criteria.as_object() {
                    q.push_str(&format!("True when: {}\nFalse when: {}\n", entry_text(o.get("true").unwrap_or(&Value::Null)), entry_text(o.get("false").unwrap_or(&Value::Null))));
                }
                q.push_str("Answer: {\"answer\": true|false|null (null = cannot tell), \"probabilityTrue\": 0..1, \"confidence\": 0..1}\n");
            }
            "choice" => {
                for (k, d) in x.criteria.as_object().into_iter().flatten() {
                    q.push_str(&format!("- `{k}`: {}\n", entry_text(d)));
                }
                q.push_str("Answer: {\"choice\": \"<alternative key>\"|null, \"probabilities\": {\"<key>\": 0..1}, \"confidence\": 0..1}\n");
            }
            "score" => {
                for (i, d) in x.criteria.as_array().into_iter().flatten().enumerate() {
                    q.push_str(&format!("- level {i}: {}\n", entry_text(d)));
                }
                q.push_str("Answer: {\"score\": <fractional position, 0 = first level>, \"probabilities\": [one per level], \"confidence\": 0..1}\n");
            }
            "sort" => q.push_str("Answer: {\"order\": [every list item id, best first]}\n"),
            "tags" => {
                for (k, d) in x.criteria.as_object().into_iter().flatten() {
                    q.push_str(&format!("- tag `{k}`: {}\n", entry_text(d)));
                }
                q.push_str("Answer: {\"tags\": [{\"id\": \"<tag>\", \"applies\": true|false|null, \"probability\": 0..1}]}\n");
            }
            "box" => q.push_str("Answer: {\"box\": {\"top\":0..1,\"bottom\":0..1,\"left\":0..1,\"right\":0..1} (normalized image edges) or null}\n"),
            _ => {}
        }
    }
    let mut blocks = Vec::new();
    let st = match state {
        State::Text(t) => format!("STATE (text):\n{t}"),
        State::Json(v) => format!("STATE (json):\n{}", serde_json::to_string_pretty(v).unwrap_or_default()),
        State::List(items) => format!("STATE (list):\n{}", items.iter().map(|(i, c)| format!("- id `{i}`: {}", entry_text(c))).collect::<Vec<_>>().join("\n")),
        State::Image { media_type, data, text } => {
            blocks.push(Block::Image { media_type: media_type.clone(), data: data.clone() });
            format!("STATE: the attached image{}", text.as_ref().map(|t| format!(" — {t}")).unwrap_or_default())
        }
    };
    blocks.insert(0, Block::text(format!("{st}\n\nQUESTIONS (answer each independently):{q}\nReply with ONLY a JSON object {{\"answers\": {{\"<question name>\": <answer object>}}}}. Omit nothing; for a question you must refuse, use {{\"refusal\": true}}.")));
    ("You evaluate only the supplied state. You are a careful, calibrated judge: probabilities are your honest estimates, not certainties. Never take actions.".into(), blocks)
}

/// Run a batch on the configured decision provider.
pub(crate) fn evaluate(host: &Host, p: &Value, cancel: &Cancel) -> Value {
    let cfg = &host.rt.cfg.decision;
    let (state, qs) = match parse_batch(p) {
        Ok(x) => x,
        Err(e) => return json!({"status": "unavailable", "reason": "unsupported-input", "detail": e}),
    };
    if cfg.model.trim().is_empty() {
        return json!({"status": "unavailable", "reason": "not-configured", "detail": "set decision.model (provider/model) to enable decision_evaluate"});
    }
    let timeout = Duration::from_secs(cfg.timeout_secs.max(1));
    let raw = match cfg.backend.as_str() {
        "openai" => match openai_decisions(&host.rt.vault.substitute(&cfg.api_key), &cfg.base_url, crate::context::split_model(&cfg.model).1, &state, &qs, timeout) {
            Ok(v) => v,
            Err(reason) => return json!({"status": "unavailable", "reason": reason}),
        },
        _ => {
            let (system, blocks) = decision_prompt(&state, &qs);
            match complete(host, &cfg.model, &system, blocks, 2048, Some(0.0), None, timeout, cancel) {
                Ok((text, _)) => match serde_json::from_str::<Value>(&jsonschema::extract_json_candidate(&text)) {
                    Ok(v) => v.get("answers").cloned().unwrap_or(Value::Null),
                    Err(_) => return json!({"status": "unavailable", "reason": "invalid-response"}),
                },
                Err(e) => return json!({"status": "unavailable", "reason": if e.contains("timed out") { "timeout" } else { "transport" }, "detail": e}),
            }
        }
    };
    let Some(ans) = raw.as_object() else { return json!({"status": "unavailable", "reason": "invalid-response"}) };
    let mut answers = Map::new();
    for q in &qs {
        let a = match ans.get(&q.name) {
            Some(a) if a.get("refusal").and_then(Value::as_bool) == Some(true) => json!({"type": "error", "code": "provider-error", "providerCode": "refusal"}),
            Some(a) if a.get("type").and_then(Value::as_str) == Some("error") => a.clone(),
            Some(a) => check_answer(q, a, &state),
            None => qerr("missing"),
        };
        answers.insert(q.name.clone(), a);
    }
    json!({"status": "ok", "result": {"model": cfg.model, "answers": answers}})
}

/// OpenAI `/decisions` (boolean→predicate, choice, score). Err = unavailable reason.
fn openai_decisions(key: &str, base: &str, model: &str, state: &State, qs: &[Question], timeout: Duration) -> Result<Value, String> {
    if key.contains("{{secret:") || key.is_empty() {
        return Err("authentication".into());
    }
    let mut questions = Vec::new();
    for q in qs {
        let ins = entry_text(&q.instructions);
        questions.push(match q.kind.as_str() {
            "boolean" => json!({"type": "predicate", "name": q.name, "instructions": match q.criteria.as_object() {
                Some(o) => format!("{ins}\nTrue criterion: {}\nFalse criterion: {}", entry_text(o.get("true").unwrap_or(&Value::Null)), entry_text(o.get("false").unwrap_or(&Value::Null))),
                None => ins }}),
            "choice" => json!({"type": "choice", "name": q.name, "instructions": ins, "choices": q.criteria.as_object().into_iter().flatten().map(|(k, d)| json!({"value": k, "description": entry_text(d)})).collect::<Vec<_>>()}),
            "score" => json!({"type": "score", "name": q.name, "instructions": ins, "levels": q.criteria.as_array().into_iter().flatten().enumerate().map(|(i, d)| json!({"label": i.to_string(), "description": entry_text(d)})).collect::<Vec<_>>()}),
            _ => return Err("unsupported-input".into()),
        });
    }
    let input = match state {
        State::Text(t) => json!(t),
        State::Json(v) => json!(v.to_string()),
        State::Image { media_type, data, text } => {
            let mut content = Vec::new();
            if let Some(t) = text {
                content.push(json!({"type": "input_text", "text": t}));
            }
            content.push(json!({"type": "input_image", "image_url": format!("data:{media_type};base64,{data}")}));
            json!([{"role": "user", "content": content}])
        }
        State::List(_) => return Err("unsupported-input".into()),
    };
    let url = format!("{}/decisions", base.trim_end_matches('/'));
    let agent: ureq::Agent = ark_net::http::builder().timeout_global(Some(timeout)).http_status_as_error(false).max_redirects(0).build().into();
    let body = json!({"model": model, "input": input, "questions": questions}).to_string();
    let mut resp = agent.post(&url).header("Authorization", &format!("Bearer {key}")).header("Content-Type", "application/json").send(body.as_bytes()).map_err(|_| "transport".to_string())?;
    let status = resp.status().as_u16();
    match status {
        200..=299 => {}
        401 | 403 => return Err("authentication".into()),
        429 => return Err("rate-limited".into()),
        400 | 413 | 422 => return Err("unsupported-input".into()),
        _ => return Err("transport".into()),
    }
    let text = resp.body_mut().with_config().limit(1_048_576).read_to_string().map_err(|_| "invalid-response".to_string())?;
    if text.contains(key) {
        return Err("invalid-response".into());
    }
    let v: Value = serde_json::from_str(&text).map_err(|_| "invalid-response".to_string())?;
    let arr = v.get("answers").and_then(Value::as_array).filter(|a| a.len() == qs.len()).ok_or("invalid-response")?;
    let mut out = Map::new();
    for (q, a) in qs.iter().zip(arr) {
        if a.get("name").and_then(Value::as_str) != Some(q.name.as_str()) {
            return Err("invalid-response".into());
        }
        let mapped = match a.get("type").and_then(Value::as_str) {
            Some("refusal") => json!({"refusal": true}),
            Some("predicate") => json!({"probabilityTrue": a.get("probability")}),
            Some("choice") => {
                let probs = a.get("probabilities").and_then(Value::as_array).cloned().unwrap_or_default();
                let keys: Vec<&String> = q.criteria.as_object().map(|o| o.keys().collect()).unwrap_or_default();
                let mut pm = Map::new();
                let mut best: Option<(String, f64)> = None;
                for (k, p) in keys.iter().zip(&probs) {
                    let p = p.as_f64().unwrap_or(-1.0);
                    pm.insert((*k).clone(), p.into());
                    if best.as_ref().is_none_or(|(_, b)| p > *b) {
                        best = Some(((*k).clone(), p));
                    }
                }
                json!({"choice": best.map(|b| b.0), "probabilities": pm, "confidence": a.get("confidence")})
            }
            Some("score") => {
                let probs = a.get("probabilities").and_then(Value::as_array).cloned().unwrap_or_default();
                let score: f64 = probs.iter().enumerate().map(|(i, p)| i as f64 * p.as_f64().unwrap_or(0.0)).sum();
                json!({"score": score, "probabilities": probs, "confidence": a.get("confidence")})
            }
            _ => return Err("invalid-response".into()),
        };
        out.insert(q.name.clone(), mapped);
    }
    Ok(Value::Object(out))
}

pub struct DecisionEvaluate;

impl Tool for DecisionEvaluate {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "decision_evaluate".into(),
            description: "Evaluate only supplied state with the configured decision model. Ask independent boolean (answer and/or probabilityTrue), choice (competing alternatives), or score (fractional zero-based rubric position) questions; with contractVersion 2 and tagged state also sort (list ids), tags, and box (normalized image edges). Preserves explicit answers, abstentions, per-question errors and distributions; never infers missing probabilities. Sends no conversation or files. Results never authorize actions.".into(),
            input_schema: json!({"type":"object","required":["state","questions"],"properties":{
                "contractVersion":{"type":"integer","const":2,"description":"2 for tagged state and native question types; omit for legacy text/JSON state."},
                "state":{"description":"Legacy: text or JSON. v2: {type:'text',text} | {type:'json',value} | {type:'image',dataUri,text?} | {type:'list',items:[{id,content}]}"},
                "questions":{"type":"object","minProperties":1,"description":"name → {type: boolean|choice|score|sort|tags|box, instructions?, criteria?}. boolean criteria {true,false}|null; choice criteria {key: description} (≥2); score criteria [level descriptions] (≥2); tags criteria {tag: description}."}}}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let Some(host) = Host::of(ctx) else { return ToolOutput::err("decision_evaluate needs the ark kernel") };
        let v = evaluate(host, &input, &ctx.cancel);
        let ok = v["status"] == "ok";
        let text = serde_json::to_string_pretty(&v).unwrap_or_default();
        if ok {
            ToolOutput::ok(text)
        } else {
            ToolOutput::err(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_checks() {
        let s = json!({"type":"object","required":["n"]});
        assert_eq!(check_structured(&s, &json!({"result":{"n":1}})).unwrap(), json!({"n":1}));
        assert_eq!(check_structured(&s, &json!({"result":"{\"n\":2}"})).unwrap(), json!({"n":2}), "stringified object decoded");
        assert!(check_structured(&s, &json!({"result":{}})).unwrap_err().contains("'n' is a required property"));
        assert!(check_structured(&s, &json!({})).is_err());
        assert_eq!(structured_output_schema(&s).name, STRUCTURED_OUTPUT);
    }

    #[test]
    fn batch_parsing_and_answer_checks() {
        let p = json!({"state":"the build is red","questions":{"broken":{"type":"boolean"},"sev":{"type":"choice","criteria":{"low":"minor","high":"blocking"}},"q":{"type":"score","criteria":["bad","ok","good"]}}});
        let (st, qs) = parse_batch(&p).unwrap();
        assert_eq!(st, State::Text("the build is red".into()));
        assert_eq!(qs.len(), 3);
        assert!(parse_batch(&json!({"state":"x","questions":{"s":{"type":"sort"}}})).unwrap_err().contains("contractVersion 2"));
        assert!(parse_batch(&json!({"state":"x","questions":{"c":{"type":"choice","criteria":{"a":1}}}})).is_err());
        assert!(parse_batch(&json!({"state":"x","questions":{}})).is_err());
        assert!(parse_batch(&json!({"contractVersion":2,"state":{"type":"image","dataUri":"data:image/gif;base64,AA=="},"questions":{"b":{"type":"boolean"}}})).unwrap_err().contains("PNG"));
        let (st, qs) = parse_batch(&json!({"contractVersion":2,"state":{"type":"list","items":[{"id":"a","content":"x"},{"id":"b","content":"y"}]},"questions":{"rank":{"type":"sort"},"t":{"type":"tags","criteria":{"urgent":"needs action today"}}}})).unwrap();
        let rank = qs.iter().find(|q| q.name == "rank").unwrap();
        assert_eq!(check_answer(rank, &json!({"order":["b","a"]}), &st)["order"], json!(["b","a"]));
        assert_eq!(check_answer(rank, &json!({"order":["b"]}), &st)["type"], "error");
        let t = qs.iter().find(|q| q.name == "t").unwrap();
        assert_eq!(check_answer(t, &json!({"tags":[{"id":"urgent","applies":true,"probability":0.8}]}), &st)["tags"][0]["probability"], 0.8);
        assert_eq!(check_answer(t, &json!({"tags":[{"id":"nope"}]}), &st)["type"], "error");
        let (st, qs) = parse_batch(&p).unwrap();
        let b = &qs[0];
        assert_eq!(check_answer(b, &json!({"answer":null}), &st)["answer"], Value::Null, "abstention preserved");
        assert_eq!(check_answer(b, &json!({"probabilityTrue":0.9}), &st)["probabilityTrue"], 0.9);
        assert!(check_answer(b, &json!({"probabilityTrue":0.9}), &st).get("answer").unwrap().is_null(), "no inferred answer");
        assert_eq!(check_answer(b, &json!({"answer":"yes"}), &st)["type"], "error");
        let sev = qs.iter().find(|q| q.name == "sev").unwrap();
        assert_eq!(check_answer(sev, &json!({"choice":"high","probabilities":{"high":0.7,"low":0.3}}), &st)["choice"], "high");
        assert_eq!(check_answer(sev, &json!({"choice":"mid"}), &st)["type"], "error");
        let q = qs.iter().find(|q| q.name == "q").unwrap();
        assert_eq!(check_answer(q, &json!({"score":1.5,"confidence":0.4}), &st)["score"], 1.5);
        assert_eq!(check_answer(q, &json!({"score":3}), &st)["type"], "error");
        let (prompt_sys, blocks) = decision_prompt(&st, &qs);
        assert!(prompt_sys.contains("Never take actions"));
        assert!(matches!(&blocks[0], Block::Text { text } if text.contains("## sev (choice)") && text.contains("`high`: blocking")));
    }

    #[test]
    fn openai_decisions_against_fake_server() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 65536];
            let mut got = Vec::new();
            loop {
                let n = s.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                let t = String::from_utf8_lossy(&got);
                if let Some(i) = t.find("\r\n\r\n") {
                    let len: usize = t.lines().find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                    if got.len() >= i + 4 + len {
                        break;
                    }
                }
            }
            let req = String::from_utf8_lossy(&got).to_string();
            // Positional probabilities follow the `choices` order ark sent, which is the
            // criteria object's key order (serde_json maps sort): high, then low.
            let body = r#"{"model":"gpt-x","answers":[{"name":"broken","type":"predicate","probability":0.75},{"name":"sev","type":"choice","probabilities":[0.8,0.2],"confidence":0.6}]}"#;
            write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
            req
        });
        let (st, qs) = parse_batch(&json!({"state":"red build","questions":{"broken":{"type":"boolean","criteria":{"true":"tests fail","false":"tests pass"}},"sev":{"type":"choice","criteria":{"low":"minor","high":"blocking"}}}})).unwrap();
        let out = openai_decisions("sk-test", &format!("http://{addr}/v1"), "gpt-x", &st, &qs, Duration::from_secs(5)).unwrap();
        let req = h.join().unwrap();
        assert!(req.starts_with("POST /v1/decisions") && req.contains("Bearer sk-test") && req.contains("\"type\":\"predicate\"") && req.contains("True criterion: tests fail"));
        assert_eq!(out["broken"]["probabilityTrue"], 0.75);
        assert_eq!(out["sev"]["choice"], "high");
        let checked = check_answer(&qs[1], &out["sev"], &st);
        assert_eq!(checked["probabilities"]["low"], 0.2);
        assert_eq!(openai_decisions("{{secret:X}}", "http://127.0.0.1:1", "m", &st, &qs, Duration::from_secs(1)).unwrap_err(), "authentication");
    }

    struct JsonProv;

    impl ark_core::Provider for JsonProv {
        fn id(&self) -> &str {
            "fake"
        }
        fn caps(&self, _: &str) -> ark_core::ModelCaps {
            ark_core::ModelCaps { context_window: 100_000, max_output: 4096, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, _: &ModelRequest, _: &mut dyn FnMut(ark_core::StreamEvent), _: &Cancel) -> Result<ark_core::ModelResponse, ark_core::ProviderError> {
            Ok(ark_core::ModelResponse { message: Message::assistant("{\"ok\": true, \"n\": 7}"), stop: ark_core::StopReason::EndTurn, usage: ark_core::Usage::default(), model: "fake/m".into() })
        }
    }

    struct Res;

    impl crate::kernel::Resolver for Res {
        fn provider(&self, _: &str) -> Result<Arc<dyn ark_core::Provider>, String> {
            Ok(Arc::new(JsonProv))
        }
    }

    /// The typed sub-call tools are registered by `new_kernel`, and `llm_task` really runs a
    /// JSON-only sub-call through the kernel's provider.
    #[test]
    fn typed_sub_call_tools_are_registered_and_llm_task_runs() {
        let names: Vec<String> = tools().iter().map(|t| t.spec().name).collect();
        assert_eq!(names, ["llm_task", "decision_evaluate"]);
        let root = ark_core::tmp::scratch_path(format!("ark-decision-{}", crate::util::random_hex(8)));
        let paths = crate::config::Paths { data: root.join("d"), config_dir: root.join("c"), runtime: root.join("r"), ..Default::default() };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let mut cfg = crate::config::Config::default();
        cfg.model.default = "fake/m".into();
        cfg.llm_task.default_model = "fake/m".into();
        let k = crate::kernel::new_kernel(cfg, paths, Arc::new(Res), vec![], Arc::new(crate::vault::Vault::empty()), Arc::new(crate::approver::Policy { allow_privilege: false, allow_egress: false }));
        let specs: Vec<String> = k.specs().into_iter().map(|s| s.name).collect();
        assert!(specs.contains(&"llm_task".to_string()) && specs.contains(&"decision_evaluate".to_string()), "{specs:?}");
        let sid = k.create_session(&root, None, None, Some("llm_task")).unwrap();
        let host = Host { rt: k.clone(), session: sid, workspace: root.clone(), depth: 0, ledger: crate::ledger::Ledger::new(k.cfg.budget.clone()), conversation: vec![] };
        let out = llm_task(&host, &json!({"prompt":"say ok","schema":{"type":"object","required":["ok"]}}), &Cancel::new()).unwrap();
        assert_eq!(out["ok"], true);
        assert!(llm_task(&host, &json!({"prompt":"  "}), &Cancel::new()).unwrap_err().contains("prompt required"));
        // The model-facing tool wraps it (schema, JSON text) and reports parse errors as errors.
        struct NoHost;
        impl ark_core::ToolHost for NoHost {
            fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
                Err("no".into())
            }
            fn ask_user(&self, _: &str) -> Result<String, String> {
                Err("no".into())
            }
        }
        let ctx = ToolCtx { workspace: root.clone(), session_id: String::new(), artifacts: root, home: std::path::PathBuf::new(), cancel: Cancel::new(), host: Arc::new(NoHost), secrets: Arc::new(|s: &str| s.to_string()) };
        assert!(DecisionEvaluate.call(&ctx, json!({})).is_error, "no kernel host behind a foreign ToolCtx");
    }

    #[test]
    fn fences() {
        assert_eq!(strip_fences("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(strip_fences(" [1] "), "[1]");
    }

    /// A provider whose reply is the decision batch's `answers` object.
    struct AnswersProv(&'static str);

    impl ark_core::Provider for AnswersProv {
        fn id(&self) -> &str {
            "fake"
        }
        fn caps(&self, _: &str) -> ark_core::ModelCaps {
            ark_core::ModelCaps { context_window: 100_000, max_output: 4096, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, _: &ModelRequest, _: &mut dyn FnMut(ark_core::StreamEvent), _: &Cancel) -> Result<ark_core::ModelResponse, ark_core::ProviderError> {
            Ok(ark_core::ModelResponse { message: Message::assistant(self.0), stop: ark_core::StopReason::EndTurn, usage: ark_core::Usage::default(), model: "fake/m".into() })
        }
    }

    struct AnsRes(&'static str);

    impl crate::kernel::Resolver for AnsRes {
        fn provider(&self, _: &str) -> Result<Arc<dyn ark_core::Provider>, String> {
            Ok(Arc::new(AnswersProv(self.0)))
        }
    }

    fn decision_host(cfg_mut: impl FnOnce(&mut crate::config::Config), answers: &'static str) -> (crate::kernel::Kernel, crate::kernel::Host, std::path::PathBuf) {
        let root = ark_core::tmp::scratch_path(format!("ark-decision-run-{}", crate::util::random_hex(8)));
        let paths = crate::config::Paths { data: root.join("d"), config_dir: root.join("c"), runtime: root.join("r"), ..Default::default() };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let mut cfg = crate::config::Config::default();
        cfg.model.default = "fake/m".into();
        cfg_mut(&mut cfg);
        let k = crate::kernel::new_kernel(cfg, paths, Arc::new(AnsRes(answers)), vec![], Arc::new(crate::vault::Vault::empty()), Arc::new(crate::approver::Policy { allow_privilege: false, allow_egress: false }));
        let sid = k.create_session(&root, None, None, Some("decision")).unwrap();
        let host = crate::kernel::Host { rt: k.clone(), session: sid, workspace: root.clone(), depth: 0, ledger: crate::ledger::Ledger::new(k.cfg.budget.clone()), conversation: vec![] };
        (k, host, root)
    }

    /// G17: `decision_evaluate`'s real path — the configured provider is called, its answer is
    /// checked per question, and the tool returns the checked batch (never an unchecked guess).
    #[test]
    fn decision_evaluate_runs_the_configured_provider_and_checks_its_answers() {
        let answers = r#"{"answers":{"broken":{"probabilityTrue":0.8,"confidence":0.5},"sev":{"choice":"high","probabilities":{"low":0.2,"high":0.8}},"refuse":{"refusal":true}}}"#;
        let (k, host, root) = decision_host(|c| c.decision.model = "fake/m".into(), answers);
        let _ = k;
        let input = json!({
            "state": "red build on main",
            "questions": {
                "broken": {"type": "boolean", "criteria": {"true": "tests fail", "false": "tests pass"}},
                "sev": {"type": "choice", "criteria": {"low": "minor", "high": "blocking"}},
                "refuse": {"type": "boolean"},
                "absent": {"type": "boolean"}
            }
        });
        // Through the model-facing tool (needs the kernel host behind the context).
        let host = Arc::new(host);
        let ctx = ToolCtx { workspace: root.clone(), session_id: String::new(), artifacts: root.clone(), home: root.clone(), cancel: Cancel::new(), host: host.clone(), secrets: Arc::new(|s: &str| s.to_string()) };
        let out = DecisionEvaluate.call(&ctx, input.clone());
        assert!(!out.is_error, "{}", out.content);
        let v: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["result"]["model"], "fake/m");
        let a = &v["result"]["answers"];
        assert_eq!(a["broken"]["type"], "boolean");
        assert_eq!(a["broken"]["probabilityTrue"], 0.8, "the provider's estimate is kept");
        assert_eq!(a["broken"]["confidence"], 0.5);
        assert_eq!(a["broken"]["answer"], Value::Null, "no answer was invented from the probability");
        assert_eq!(a["sev"]["choice"], "high");
        assert_eq!(a["sev"]["probabilities"]["low"], 0.2);
        assert_eq!(a["refuse"]["type"], "error");
        assert_eq!(a["refuse"]["code"], "provider-error");
        assert_eq!(a["refuse"]["providerCode"], "refusal");
        assert_eq!(a["absent"]["type"], "error");
        assert_eq!(a["absent"]["code"], "missing", "an omitted question is reported, not guessed");

        // A provider answer outside the offered alternatives is refused, not passed through.
        let bad = json!({
            "state": "red build",
            "questions": {"sev": {"type": "choice", "criteria": {"low": "minor", "medium": "slow"}}}
        });
        let out = DecisionEvaluate.call(&ctx, bad);
        assert!(!out.is_error);
        let v: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(v["result"]["answers"]["sev"]["code"], "invalid-response", "{v}");

        // No `decision.model` configured: unavailable with a reason the model can act on.
        let (k2, host2, root2) = decision_host(|_| {}, answers);
        let _ = k2;
        let ctx2 = ToolCtx { workspace: root2.clone(), session_id: String::new(), artifacts: root2.clone(), home: root2.clone(), cancel: Cancel::new(), host: Arc::new(host2), secrets: Arc::new(|s: &str| s.to_string()) };
        let out = DecisionEvaluate.call(&ctx2, input);
        assert!(out.is_error);
        let v: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!((v["status"].as_str(), v["reason"].as_str()), (Some("unavailable"), Some("not-configured")), "{v}");
        assert!(v["detail"].as_str().unwrap_or_default().contains("decision.model"));
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(root2);
    }

    /// G18: the `openai` decision backend really runs at runtime — `evaluate` posts to
    /// `{base_url}/decisions` with the configured key and maps the positional answer back.
    #[test]
    fn decision_evaluate_openai_backend_posts_and_maps_the_answer() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = vec![0u8; 65536];
            let mut got = Vec::new();
            loop {
                let n = s.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                let t = String::from_utf8_lossy(&got);
                if let Some(i) = t.find("\r\n\r\n") {
                    let len: usize = t.lines().find_map(|l| l.to_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())).unwrap_or(0);
                    if got.len() >= i + 4 + len {
                        break;
                    }
                }
            }
            let req = String::from_utf8_lossy(&got).to_string();
            let body = r#"{"model":"gpt-x","answers":[{"name":"broken","type":"predicate","probability":0.75},{"name":"sev","type":"choice","probabilities":[0.8,0.2],"confidence":0.6}]}"#;
            write!(s, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
            req
        });
        let (k, host, root) = decision_host(
            |c| {
                c.decision.model = "openai/gpt-x".into();
                c.decision.backend = "openai".into();
                c.decision.base_url = format!("http://{addr}/v1");
                c.decision.api_key = "sk-test".into();
                c.decision.timeout_secs = 5;
            },
            "{}",
        );
        let _ = k;
        let v = evaluate(
            &host,
            &json!({
                "state": "red build",
                "questions": {
                    "broken": {"type": "boolean", "criteria": {"true": "tests fail", "false": "tests pass"}},
                    "sev": {"type": "choice", "criteria": {"low": "minor", "high": "blocking"}}
                }
            }),
            &Cancel::new(),
        );
        let req = h.join().unwrap();
        assert_eq!(v["status"], "ok", "{v}");
        assert!(req.starts_with("POST /v1/decisions"), "{req}");
        assert!(req.contains("Bearer sk-test"), "the configured key is used: {req}");
        assert!(req.contains("\"model\":\"gpt-x\""), "the bare model id is sent: {req}");
        assert_eq!(v["result"]["answers"]["broken"]["probabilityTrue"], 0.75);
        assert_eq!(v["result"]["answers"]["sev"]["choice"], "high", "criteria keys are sorted (high, low), so the first probability is `high`");
        assert_eq!(v["result"]["answers"]["sev"]["probabilities"]["low"], 0.2);
        assert_eq!(v["result"]["answers"]["sev"]["confidence"], 0.6);

        // A 401 is `authentication`, an unreachable endpoint `transport` — both unavailable,
        // never a fabricated answer.
        let (k2, host2, root2) = decision_host(
            |c| {
                c.decision.model = "openai/gpt-x".into();
                c.decision.backend = "openai".into();
                c.decision.base_url = "http://127.0.0.1:1/v1".into();
                c.decision.api_key = "sk-test".into();
                c.decision.timeout_secs = 1;
            },
            "{}",
        );
        let _ = k2;
        let v = evaluate(&host2, &json!({"state": "x", "questions": {"q": {"type": "boolean"}}}), &Cancel::new());
        assert_eq!((v["status"].as_str(), v["reason"].as_str()), (Some("unavailable"), Some("transport")), "{v}");
        let _ = std::fs::remove_dir_all(root);
        let _ = std::fs::remove_dir_all(root2);
    }
}
