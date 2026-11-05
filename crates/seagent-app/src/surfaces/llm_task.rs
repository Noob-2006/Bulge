//! `llm-task`: a JSON-only model sub-call with optional JSON Schema validation
//! (OpenClaw extensions/llm-task, MIT). Also the engine behind lobster's `llm.invoke`.

use super::{complete, Completion, Env};
use seagent_core::{Cancel, Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

fn d_timeout() -> u64 {
    30_000
}

/// `[surfaces.llm_task]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LlmTaskConfig {
    /// Default provider, combined with `default_model` when that has no `provider/` prefix.
    pub default_provider: String,
    /// `provider/model` (or a bare model id with `default_provider`). Empty = the aux model.
    pub default_model: String,
    /// Default max output tokens. Default 1024.
    pub max_tokens: Option<u32>,
    /// Default timeout for one call. Default 30000 ms.
    #[serde(default = "d_timeout")]
    pub timeout_ms: u64,
}

impl Default for LlmTaskConfig {
    fn default() -> Self {
        LlmTaskConfig { default_provider: String::new(), default_model: String::new(), max_tokens: None, timeout_ms: d_timeout() }
    }
}

const SYSTEM: &str = "You are a JSON-only function. Return ONLY a valid JSON value. Do not wrap in markdown fences. Do not include commentary. Do not call tools.";
const THINKING: &[&str] = &["off", "minimal", "low", "medium", "high", "xhigh"];

pub struct LlmTask(pub Arc<Env>);

/// The parsed request (shared with lobster's `llm.invoke`).
#[derive(Debug, Clone, Default)]
pub struct Request {
    pub prompt: String,
    pub input: Value,
    pub schema: Option<Value>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub thinking: Option<String>,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub timeout_ms: Option<u64>,
}

/// Fences like ```json … ``` around the whole reply are removed.
pub fn strip_code_fences(s: &str) -> &str {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("```") {
        if let Some(body) = rest.strip_suffix("```") {
            let body = body.strip_prefix("json").or_else(|| body.strip_prefix("JSON")).unwrap_or(body);
            return body.trim();
        }
    }
    t
}

/// provider/model resolution: request → config → the aux model.
fn resolve_model(cfg: &LlmTaskConfig, provider: Option<&str>, model: Option<&str>) -> Option<String> {
    let provider = provider.map(str::trim).filter(|s| !s.is_empty()).or(Some(cfg.default_provider.trim()).filter(|s| !s.is_empty()));
    let model = model.map(str::trim).filter(|s| !s.is_empty()).or(Some(cfg.default_model.trim()).filter(|s| !s.is_empty()));
    match (provider, model) {
        (Some(p), Some(m)) if m.starts_with(&format!("{p}/")) => Some(m.to_string()),
        (Some(p), Some(m)) if !m.contains('/') => Some(format!("{p}/{m}")),
        (_, Some(m)) if m.contains('/') => Some(m.to_string()),
        (Some(p), Some(m)) => Some(format!("{p}/{m}")),
        _ => None,
    }
}

/// Run one task; Ok((json, model)).
pub fn run(env: &Env, r: &Request, cancel: &Cancel) -> Result<(Value, String), String> {
    if r.prompt.trim().is_empty() {
        return Err("prompt required".into());
    }
    if let Some(t) = r.thinking.as_deref().filter(|t| !t.trim().is_empty()) {
        if !THINKING.contains(&t.trim().to_lowercase().as_str()) {
            return Err(format!("Invalid thinking level \"{t}\"."));
        }
    }
    let cfg = &env.cfg.llm_task;
    let model = resolve_model(cfg, r.provider.as_deref(), r.model.as_deref());
    if r.provider.as_deref().is_some_and(|p| !p.trim().is_empty()) && model.is_none() {
        return Err(format!("provider/model could not be resolved (provider={}, model=)", r.provider.as_deref().unwrap_or("")));
    }
    let input = serde_json::to_string_pretty(&r.input).map_err(|_| "input must be JSON-serializable")?;
    let k = env.kernel()?;
    let reasoning = r.thinking.as_deref().map(|t| match t.trim().to_lowercase().as_str() {
        "minimal" => "low".to_string(),
        "xhigh" => "high".to_string(),
        other => other.to_string(),
    });
    let (text, used) = complete(
        k,
        Completion {
            model: model.as_deref(),
            system: SYSTEM,
            user: format!("TASK:\n{}\n\nINPUT_JSON:\n{input}\n", r.prompt),
            max_tokens: r.max_tokens.or(cfg.max_tokens).unwrap_or(1024),
            temperature: r.temperature,
            reasoning,
            timeout: Duration::from_millis(r.timeout_ms.unwrap_or(cfg.timeout_ms).max(1)),
        },
        cancel,
    )?;
    let parsed: Value = serde_json::from_str(strip_code_fences(&text)).map_err(|_| "LLM returned invalid JSON".to_string())?;
    if let Some(s) = r.schema.as_ref().filter(|s| s.is_object()) {
        seagent_plugin::schema::validate(s, &parsed).map_err(|e| format!("LLM JSON did not match schema: {e}"))?;
    }
    Ok((parsed, used))
}

pub fn parse_request(v: &Value) -> Result<Request, String> {
    let pos_int = |k: &str| -> Result<Option<u64>, String> {
        match v.get(k) {
            None | Some(Value::Null) => Ok(None),
            Some(x) => x.as_u64().filter(|n| *n > 0).map(Some).ok_or_else(|| format!("{k} must be a positive integer")),
        }
    };
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
    Ok(Request {
        prompt: s("prompt").unwrap_or_default(),
        input: v.get("input").cloned().unwrap_or(Value::Null),
        schema: v.get("schema").cloned().filter(|s| !s.is_null()),
        provider: s("provider"),
        model: s("model"),
        thinking: s("thinking"),
        temperature: match v.get("temperature") {
            None | Some(Value::Null) => None,
            Some(t) => Some(t.as_f64().filter(|f| f.is_finite()).ok_or("temperature must be a finite number")? as f32),
        },
        max_tokens: pos_int("maxTokens")?.map(|n| n.min(u32::MAX as u64) as u32),
        timeout_ms: pos_int("timeoutMs")?,
    })
}

impl Tool for LlmTask {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "llm-task".into(),
            description: "Run a generic JSON-only LLM task and return schema-validated JSON. Designed for orchestration from lobster workflows (llm.invoke). `prompt` is the task, `input` an optional JSON payload, `schema` an optional JSON Schema the result must match.".into(),
            input_schema: json!({"type": "object", "properties": {
                "prompt": {"type": "string", "description": "Task instruction for the LLM."},
                "input": {"description": "Optional input payload for the task."},
                "schema": {"type": "object", "description": "Optional JSON Schema to validate the returned JSON."},
                "provider": {"type": "string", "description": "Provider override (e.g. openai, anthropic)."},
                "model": {"type": "string", "description": "Model id override."},
                "thinking": {"type": "string", "description": "Thinking level override (off, minimal, low, medium, high, xhigh)."},
                "temperature": {"type": "number", "description": "Best-effort temperature override."},
                "maxTokens": {"type": "integer", "minimum": 1, "description": "Best-effort maxTokens override."},
                "timeoutMs": {"type": "integer", "minimum": 1, "description": "Timeout for the LLM run."}
            }, "required": ["prompt"]}),
            parallel_safe: true,
            idempotent: true,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        // Same egress as the agent's own model calls.
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let r = match parse_request(&input) {
            Ok(r) => r,
            Err(e) => return ToolOutput::err(e),
        };
        match run(&self.0, &r, &ctx.cancel) {
            Ok((v, model)) => {
                let mut o = ToolOutput::ok(serde_json::to_string_pretty(&v).unwrap_or_default());
                o.content.push_str(&format!("\n(model: {model})"));
                o
            }
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;

    #[test]
    fn fences_and_models() {
        assert_eq!(strip_code_fences("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(strip_code_fences(" [1] "), "[1]");
        let c = LlmTaskConfig { default_provider: "openai".into(), default_model: "gpt-x".into(), ..Default::default() };
        assert_eq!(resolve_model(&c, None, None).as_deref(), Some("openai/gpt-x"));
        assert_eq!(resolve_model(&c, Some("anthropic"), Some("anthropic/claude")).as_deref(), Some("anthropic/claude"));
        assert_eq!(resolve_model(&LlmTaskConfig::default(), None, None), None);
    }

    #[test]
    fn json_task_validates_against_schema_with_fake_provider() {
        let (env, fake) = testkit::env("llm", &["```json\n{\"label\": \"bug\", \"score\": 3}\n```", "not json", "{\"label\": 5}"], "");
        let t = LlmTask(env.clone());
        let ws = testkit::temp("llm-ws");
        let ctx = testkit::ctx(&env, &ws);
        let schema = json!({"type": "object", "properties": {"label": {"type": "string"}, "score": {"type": "integer"}}, "required": ["label"]});
        let out = t.call(&ctx, json!({"prompt": "Classify", "input": {"title": "crash"}, "schema": schema, "temperature": 0.2, "maxTokens": 50}));
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.contains("\"label\": \"bug\""));
        let req = fake.seen.lock().unwrap()[0].clone();
        assert_eq!(req.model, "aux");
        assert_eq!(req.max_tokens, 50);
        assert_eq!(req.temperature, Some(0.2));
        assert!(req.system[0].text.contains("JSON-only function"));
        assert!(req.messages[0].text().contains("TASK:\nClassify\n\nINPUT_JSON:\n{\n  \"title\": \"crash\"\n}"));
        assert_eq!(t.call(&ctx, json!({"prompt": "x"})).content, "LLM returned invalid JSON");
        let bad = t.call(&ctx, json!({"prompt": "x", "schema": schema}));
        assert!(bad.is_error && bad.content.starts_with("LLM JSON did not match schema"), "{}", bad.content);
        assert_eq!(t.call(&ctx, json!({"prompt": " "})).content, "prompt required");
        assert!(t.call(&ctx, json!({"prompt": "x", "thinking": "turbo"})).content.contains("Invalid thinking level"));
        assert!(t.call(&ctx, json!({"prompt": "x", "maxTokens": 0})).content.contains("positive integer"));
    }
}
