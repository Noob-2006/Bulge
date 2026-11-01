use ark_core::tool::{arg_opt_bool, arg_opt_str, arg_str};
use ark_core::tool::SpawnRequest;
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Value};

pub struct Spawn;

impl Tool for Spawn {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "spawn".into(),
            description: "Delegate a self-contained task to a sub-agent and get its final answer. Use fork=true to give it this conversation.".into(),
            input_schema: json!({"type":"object","properties":{
                "task":{"type":"string","description":"Complete brief: goal, context, what to return"},
                "model":{"type":"string","description":"Optional model override (e.g. a cheaper one)"},
                "fork":{"type":"boolean","default":false},
                "tools":{"type":"array","items":{"type":"string"},"description":"Restrict the child's tools"}},
                "required":["task"]}),
            parallel_safe: true,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        vec![Effect::Spawn]
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        crate::util::alias(&mut input, "task", &["instruction", "instructions", "prompt", "goal", "description", "message"]);
        let task = match arg_str(&input, "task") {
            Ok(t) if !t.trim().is_empty() => t.to_string(),
            Ok(_) => return ToolOutput::err("task must not be empty"),
            Err(e) => return ToolOutput::err(e),
        };
        let tools = match input.get("tools") {
            None | Some(Value::Null) => None,
            Some(Value::Array(a)) => match a.iter().map(|v| v.as_str().map(String::from)).collect::<Option<Vec<_>>>() {
                Some(t) => Some(t),
                None => return ToolOutput::err("`tools` must be an array of tool names"),
            },
            Some(_) => return ToolOutput::err("`tools` must be an array of tool names"),
        };
        let req = SpawnRequest {
            task,
            model: arg_opt_str(&input, "model").map(String::from),
            fork: arg_opt_bool(&input, "fork").unwrap_or(false),
            tools,
        };
        match ctx.host.spawn_agent(req, &ctx.cancel) {
            Ok(answer) => ToolOutput::ok(answer),
            Err(e) => ToolOutput::err(format!("sub-agent failed: {e}")),
        }
    }
}

pub struct AskUser;

impl Tool for AskUser {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "ask_user".into(),
            description: "Ask the user a question and wait for the answer. Only when you are truly blocked on their decision.".into(),
            input_schema: json!({"type":"object","properties":{"question":{"type":"string"}},"required":["question"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: true,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, mut input: Value) -> ToolOutput {
        crate::util::alias(&mut input, "question", &["prompt", "message", "text"]);
        match arg_str(&input, "question") {
            Ok(q) if !q.trim().is_empty() => match ctx.host.ask_user(q) {
                Ok(a) => ToolOutput::ok(a),
                Err(e) => ToolOutput::err(format!("could not ask the user: {e}. Proceed with your best judgment and state the assumption.")),
            },
            Ok(_) => ToolOutput::err("question must not be empty"),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ctx_with, tmpdir, FakeHost};
    use std::sync::Arc;

    #[test]
    fn spawn_forwards_request() {
        let host = Arc::new(FakeHost::default());
        let c = ctx_with(tmpdir("spawn"), host.clone());
        let o = Spawn.call(&c, json!({"task":"count files","model":"cheap","fork":true,"tools":["glob"]}));
        assert_eq!(o.content, "done: count files");
        let got = host.spawned.lock().unwrap();
        assert_eq!(got[0].model.as_deref(), Some("cheap"));
        assert!(got[0].fork);
        assert_eq!(got[0].tools.as_deref(), Some(&["glob".to_string()][..]));
        assert_eq!(Spawn.effects(&c, &json!({})), vec![Effect::Spawn]);
    }

    #[test]
    fn spawn_failures() {
        let c = ctx_with(tmpdir("spawnf"), Arc::new(FakeHost { fail: true, ..Default::default() }));
        assert!(!Spawn.call(&c, json!({"instruction":"count lines"})).content.contains("missing"), "instruction → task");
        let o = Spawn.call(&c, json!({"task":"x"}));
        assert!(o.is_error && o.content.contains("exceeded budget"));
        assert!(Spawn.call(&c, json!({})).is_error);
        assert!(Spawn.call(&c, json!({"task":" "})).is_error);
        assert!(Spawn.call(&c, json!({"task":"x","tools":"glob"})).is_error);
        assert!(Spawn.call(&c, json!({"task":"x","tools":[1]})).is_error);
    }

    #[test]
    fn ask_user_paths() {
        let c = ctx_with(tmpdir("ask"), Arc::new(FakeHost::default()));
        assert_eq!(AskUser.call(&c, json!({"question":"which?"})).content, "answer to which?");
        assert!(AskUser.call(&c, json!({})).is_error);
        assert!(AskUser.call(&c, json!({"question":""})).is_error);
        let c = ctx_with(tmpdir("askf"), Arc::new(FakeHost { fail: true, ..Default::default() }));
        let o = AskUser.call(&c, json!({"question":"q"}));
        assert!(o.is_error && o.content.contains("headless"));
    }
}
