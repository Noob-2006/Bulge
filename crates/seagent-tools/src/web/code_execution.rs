//! `code_execution`: sandboxed Python analysis run by xAI (OpenClaw `extensions/xai/code-execution*.ts`).
//! One Responses API call with Grok's server-side `code_interpreter` tool: the task (with any data
//! inline) goes to xAI, which writes and runs the code remotely and answers; nothing touches this
//! machine. Default model grok-4.7 with low tool reasoning, `store: false`, optional `max_turns`,
//! 30 s default timeout. Result: `{task, provider, model, tookMs, content, citations,
//! usedCodeExecution, outputTypes}`.
//!
//! Config (`[web.providers.xai]`): `api_key` (or XAI_API_KEY), `base_url`, `code_execution = false`
//! to disable, `code_execution_model`, `code_execution_max_turns`, `code_execution_timeout_seconds`.

use super::content::wrap;
use super::http::{host_of, EnvFn, WebCtx};
use super::providers::xai;
use super::WebConfig;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

pub struct CodeExecution {
    pub cfg: Arc<WebConfig>,
    pub env: EnvFn,
}

const MISSING_KEY: &str = "code_execution needs xAI credentials. Set XAI_API_KEY (or store it with `seagent secrets set XAI_API_KEY`), or configure [web.providers.xai] api_key.";

/// Configured model (`xai/` prefix dropped), else the default Grok model.
pub fn model(c: &WebCtx) -> String {
    let m = c.opt("xai", "code_execution_model").unwrap_or_default();
    let m = m.trim().trim_start_matches("xai/");
    if m.is_empty() { xai::ANSWER_MODEL } else { m }.to_string()
}

pub fn request_body(c: &WebCtx, task: &str) -> Value {
    let model = model(c);
    let mut body = json!({"model": model, "input": [{"role": "user", "content": task}], "tools": [{"type": "code_interpreter"}], "store": false});
    if let Some(e) = xai::tool_reasoning(&model) {
        body["reasoning"] = json!({"effort": e});
    }
    if let Some(t) = c.opt_u64("xai", "code_execution_max_turns").filter(|t| *t > 0) {
        body["max_turns"] = json!(t);
    }
    body
}

/// (content, citations, output types) from a Responses payload.
pub fn parse(v: &Value) -> Result<(String, Vec<String>, Vec<String>), String> {
    let (texts, anns) = xai::output_blocks(v);
    let content = if texts.is_empty() { v.get("output_text").and_then(Value::as_str).unwrap_or("").to_string() } else { texts.join("") };
    if content.trim().is_empty() {
        return Err("xAI code execution failed: no answer text returned; try a simpler request".into());
    }
    let mut citations: Vec<String> = Vec::new();
    let urls = v.get("citations").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(String::from).chain(anns.iter().filter(|a| a.get("type").and_then(Value::as_str) == Some("url_citation")).filter_map(|a| a.get("url").and_then(Value::as_str).map(String::from)));
    for u in urls.take(1000) {
        if let Some(u) = xai::citation_url(&u) {
            if !citations.contains(&u) && citations.len() < 20 {
                citations.push(u);
            }
        }
    }
    let mut types: Vec<String> = Vec::new();
    for t in v.get("output").and_then(Value::as_array).into_iter().flatten().filter_map(|o| o.get("type").and_then(Value::as_str)) {
        if !types.iter().any(|x| x == t) {
            types.push(t.to_string());
        }
    }
    Ok((content, citations, types))
}

fn enabled(c: &WebCtx) -> bool {
    c.opt_bool("xai", "code_execution").unwrap_or(true)
}

impl Tool for CodeExecution {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "code_execution".into(),
            description: "Run sandboxed Python analysis with xAI. Use for calculations, tabulation, summaries, and chart-style analysis without local machine access.".into(),
            input_schema: json!({"type":"object","required":["task"],"additionalProperties":false,"properties":{
                "task":{"type":"string","description":"The full analysis task for xAI's remote Python sandbox. Include any data to analyze directly in the task."}}}),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let c = WebCtx::from_tool(self.cfg.clone(), self.env.clone(), ctx);
        vec![Effect::Net { dest: host_of(&xai::base(&c)), payload: input.get("task").and_then(Value::as_str).unwrap_or("").to_string() }]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let c = WebCtx::from_tool(self.cfg.clone(), self.env.clone(), ctx);
        if !enabled(&c) {
            return ToolOutput::err("code_execution is disabled ([web.providers.xai] code_execution = false).");
        }
        let task = match input.get("task").and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty()) {
            Some(t) => t.to_string(),
            None => return ToolOutput::err(json!({"error": "invalid_arguments", "message": "task required"}).to_string()),
        };
        let Some(key) = c.key("xai", xai::ENV) else {
            return ToolOutput::err(json!({"error": "missing_xai_api_key", "message": MISSING_KEY, "docs": "https://docs.x.ai/docs/guides/tools/code-execution-tool"}).to_string());
        };
        let model = model(&c);
        let timeout = c.opt_u64("xai", "code_execution_timeout_seconds").unwrap_or(30).clamp(1, 600);
        let started = Instant::now();
        let v = match xai::responses(&c, &key, &request_body(&c, &task), timeout, "xAI code execution") {
            Ok(v) => v,
            Err(e) => return ToolOutput::err(json!({"error": "provider_error", "message": e, "provider": "xai", "tool": "code_execution"}).to_string()),
        };
        match parse(&v) {
            Ok((content, citations, types)) => {
                let out = json!({"task": task, "provider": "xai", "model": model, "tookMs": started.elapsed().as_millis() as u64, "content": content, "citations": citations, "usedCodeExecution": types.iter().any(|t| t == "code_interpreter_call"), "outputTypes": types});
                ToolOutput::ok(wrap(&serde_json::to_string_pretty(&out).unwrap_or_default(), "code_execution", false))
            }
            Err(e) => ToolOutput::err(json!({"error": "provider_error", "message": e, "provider": "xai", "tool": "code_execution"}).to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::ctx;
    use crate::web::testutil::{env_of, FakeServer};

    fn tool(cfg: Value, env: &[(&str, &str)]) -> CodeExecution {
        CodeExecution { cfg: Arc::new(WebConfig::from_value(cfg).unwrap()), env: env_of(env) }
    }

    #[test]
    fn request_shape_result_and_errors_against_a_fake_xai() {
        let reply = json!({"output":[{"type":"code_interpreter_call","code":"print(sum(range(10)))"},{"type":"message","content":[{"type":"output_text","text":"The sum is 45.","annotations":[{"type":"url_citation","url":"https://docs.python.org/3/"}]}]}]}).to_string();
        let s = FakeServer::start(vec![("POST /responses", 200, "application/json", reply)]);
        let t = tool(json!({"providers":{"xai":{"base_url": s.url, "code_execution_max_turns": 3}}}), &[("XAI_API_KEY", "xai-test")]);
        let c = ctx("xaicode");
        assert_eq!(t.effects(&c, &json!({"task":"sum 0..9"})), vec![Effect::Net { dest: "127.0.0.1".into(), payload: "sum 0..9".into() }]);
        let o = t.call(&c, json!({"task":"sum 0..9"}));
        assert!(!o.is_error, "{}", o.content);
        let req = s.last();
        assert_eq!(req.header("authorization").as_deref(), Some("Bearer xai-test"));
        assert_eq!(req.json(), json!({"model":"grok-4.7","input":[{"role":"user","content":"sum 0..9"}],"tools":[{"type":"code_interpreter"}],"store":false,"reasoning":{"effort":"low"},"max_turns":3}));
        assert!(o.content.contains("\"content\": \"The sum is 45.\"") && o.content.contains("\"usedCodeExecution\": true") && o.content.contains("https://docs.python.org/3/"), "{}", o.content);
        assert!(o.content.contains("\"outputTypes\"") && o.content.contains("\"code_interpreter_call\"") && o.content.contains("\"message\""), "{}", o.content);

        let missing = tool(json!({}), &[]).call(&c, json!({"task":"x"}));
        assert!(missing.is_error && missing.content.contains("missing_xai_api_key"));
        assert!(t.call(&c, json!({"task":"  "})).is_error);
        let off = tool(json!({"providers":{"xai":{"code_execution": false}}}), &[("XAI_API_KEY", "k")]);
        assert!(off.call(&c, json!({"task":"x"})).content.contains("disabled"));
        let bad = FakeServer::start(vec![("POST /responses", 401, "application/json", r#"{"error":"bad key xai-test"}"#.into())]);
        let t = tool(json!({"providers":{"xai":{"base_url": bad.url, "code_execution_model": "xai/grok-4.5"}}}), &[("XAI_API_KEY", "xai-test")]);
        let o = t.call(&c, json!({"task":"x"}));
        assert!(o.is_error && o.content.contains("HTTP 401") && !o.content.contains("xai-test"), "key redacted: {}", o.content);
        assert_eq!(bad.last().json()["model"], "grok-4.5");
        assert!(bad.last().json().get("reasoning").is_none(), "grok-4.5 takes no tool reasoning");
        assert!(parse(&json!({"output":[]})).is_err());
    }
}
