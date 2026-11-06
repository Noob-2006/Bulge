//! The `spawn` tool: hand a self-contained task to a sub-agent and return its final answer
//! (OpenClaw `sessions_spawn`, Hermes `agent/delegate`). Budget and depth are enforced by the
//! kernel host, not here.

use seagent_core::tool::{arg_opt_bool, arg_opt_str, arg_str};
use seagent_core::tool::SpawnRequest;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
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
                "tools":{"type":"array","items":{"type":"string"},"description":"Restrict the child's tools"},
                "worktree":{"type":"boolean","description":"Run the sub-agent in its own git worktree (isolated branch); its work is kept on that branch"}},
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
            worktree: arg_opt_bool(&input, "worktree"),
        };
        match ctx.host.spawn_agent(req, &ctx.cancel) {
            Ok(answer) => ToolOutput::ok(answer),
            Err(e) => ToolOutput::err(format!("sub-agent failed: {e}")),
        }
    }
}

pub struct AskUser;

/// `options` / `choices`: distinct, non-empty labels. Two at least (one is not a choice).
fn ask_options(input: &Value) -> Result<Option<Vec<String>>, String> {
    let raw = match input.get("options").filter(|v| !v.is_null()).or_else(|| input.get("choices").filter(|v| !v.is_null())) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Array(a)) if a.is_empty() => return Ok(None),
        Some(Value::Array(a)) => a,
        Some(_) => return Err("`options` must be an array of strings".into()),
    };
    if raw.len() < 2 {
        return Err("`options` needs at least 2 choices (omit it for a free-text question)".into());
    }
    if raw.len() > 12 {
        return Err("`options` supports at most 12 choices".into());
    }
    let mut out: Vec<String> = Vec::new();
    for v in raw {
        let s = v.as_str().map(str::trim).filter(|s| !s.is_empty()).ok_or("each `option` must be a non-empty string")?;
        if out.iter().any(|o| o.eq_ignore_ascii_case(s)) {
            return Err("`options` must be distinct".into());
        }
        out.push(s.to_string());
    }
    Ok(Some(out))
}

fn ask_multi(input: &Value) -> bool {
    ["multi_select", "multiSelect", "multiple"].iter().any(|k| input.get(*k).and_then(Value::as_bool).unwrap_or(false))
}

/// Map a typed reply (`2`, a label, `1, 3`, or free text) back onto the offered choices.
/// The kernel's clarify path already does this; the fallback for plain hosts does it here.
fn map_choice(raw: &str, choices: &[String], multi: bool) -> String {
    if choices.is_empty() {
        return raw.to_string();
    }
    let t = raw.trim();
    if t.is_empty() {
        return t.to_string();
    }
    let pick = |tok: &str| -> Option<String> {
        let tok = tok.trim();
        if let Ok(n) = tok.trim_end_matches('.').parse::<usize>() {
            return n.checked_sub(1).and_then(|i| choices.get(i)).cloned();
        }
        choices.iter().find(|c| c.eq_ignore_ascii_case(tok)).cloned()
    };
    if multi {
        let parts: Vec<&str> = if let Ok(Value::Array(a)) = serde_json::from_str::<Value>(t) {
            return a.iter().filter_map(|v| v.as_str()).map(|s| pick(s).unwrap_or_else(|| s.trim().to_string())).collect::<Vec<_>>().join(", ");
        } else {
            t.split(',').collect()
        };
        let picked: Option<Vec<String>> = parts.iter().map(|p| pick(p)).collect();
        if let Some(v) = picked {
            return v.join(", ");
        }
        return t.to_string();
    }
    if let Some(c) = pick(t) {
        return c;
    }
    // The reply may be a full sentence containing a label; only an exact match is a choice.
    t.to_string()
}

impl Tool for AskUser {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "ask_user".into(),
            description: "Ask the user a question and wait for the answer. Only when you are truly blocked on their decision. Pass `options` for a multiple-choice question; channels with buttons show them natively, others get a numbered list.".into(),
            input_schema: json!({"type":"object","properties":{
                "question":{"type":"string"},
                "options":{"type":"array","items":{"type":"string"},"description":"Optional 2-12 choices; the user picks one (or types their own)"},
                "multi_select":{"type":"boolean","default":false,"description":"With options: allow several choices"}},
                "required":["question"]}),
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
        let options = match ask_options(&input) {
            Ok(o) => o,
            Err(e) => return ToolOutput::err(e),
        };
        let multi = ask_multi(&input);
        match arg_str(&input, "question") {
            Ok(q) if !q.trim().is_empty() => {
                let r = match &options {
                    Some(c) => ctx.host.ask_user_choice(q, c, multi),
                    None => ctx.host.ask_user(q),
                };
                match r {
                    Ok(a) => ToolOutput::ok(match &options {
                        Some(c) => map_choice(&a, c, multi),
                        None => a,
                    }),
                    Err(e) => ToolOutput::err(format!("could not ask the user: {e}. Proceed with your best judgment and state the assumption.")),
                }
            }
            Ok(_) => ToolOutput::err("question must not be empty"),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ctx_with, tmpdir, FakeHost};
    use seagent_core::ToolHost;
    use std::sync::{Arc, Mutex};

    #[test]
    fn spawn_forwards_request() {
        let host = Arc::new(FakeHost::default());
        let c = ctx_with(tmpdir("spawn"), host.clone());
        let o = Spawn.call(&c, json!({"task":"count files","model":"cheap","fork":true,"tools":["glob"],"worktree":true}));
        assert_eq!(o.content, "done: count files");
        let got = host.spawned.lock().unwrap();
        assert_eq!(got[0].model.as_deref(), Some("cheap"));
        assert!(got[0].fork);
        assert_eq!(got[0].worktree, Some(true));
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

    struct ChoiceHost {
        reply: String,
        asked: Mutex<Vec<String>>,
    }

    impl ToolHost for ChoiceHost {
        fn spawn_agent(&self, _: seagent_core::tool::SpawnRequest, _: &seagent_core::Cancel) -> Result<String, String> {
            Err("no".into())
        }
        fn ask_user(&self, q: &str) -> Result<String, String> {
            self.asked.lock().unwrap().push(q.to_string());
            Ok(self.reply.clone())
        }
    }

    fn choice_host(tag: &str, reply: &str) -> (ToolCtx, Arc<ChoiceHost>) {
        let h = Arc::new(ChoiceHost { reply: reply.into(), asked: Mutex::new(vec![]) });
        let c = ctx_with(tmpdir(tag), h.clone());
        (c, h)
    }

    #[test]
    fn ask_user_options_render_a_numbered_fallback_and_map_the_answer() {
        let (c, h) = choice_host("askopt", "2");
        assert_eq!(AskUser.call(&c, json!({"question":"Deploy where?","options":["staging","prod"]})).content, "prod");
        let asked = h.asked.lock().unwrap().join("\n");
        assert!(asked.contains("Deploy where?") && asked.contains("1. staging") && asked.contains("2. prod") && asked.contains("3. Other"), "{asked}");
        // Labels and free text are accepted too.
        let (c, _) = choice_host("asklabel", "staging");
        assert_eq!(AskUser.call(&c, json!({"question":"q","options":["staging","prod"]})).content, "staging");
        let (c, _) = choice_host("askother", "canary");
        assert_eq!(AskUser.call(&c, json!({"question":"q","options":["staging","prod"]})).content, "canary");
        // Multi-select maps a numbered list.
        let (c, h) = choice_host("askmany", "1, 2");
        assert_eq!(AskUser.call(&c, json!({"question":"q","options":["a","b","c"],"multi_select":true})).content, "a, b");
        // The fallback advertises the multi-select reply form.
        assert!(h.asked.lock().unwrap()[0].contains("one or more numbers"));
        // `choices` is the accepted alias.
        let (c, _) = choice_host("askalias", "3");
        assert_eq!(AskUser.call(&c, json!({"question":"q","choices":["a","b","c"]})).content, "c");
    }

    #[test]
    fn ask_user_rejects_bad_options() {
        let c = ctx_with(tmpdir("askbad"), Arc::new(FakeHost::default()));
        for input in [
            json!({"question":"q","options":["only one"]}),
            json!({"question":"q","options":["a","a"]}),
            json!({"question":"q","options":["a",""]}),
            json!({"question":"q","options":[1,2]}),
            json!({"question":"q","options":"a,b"}),
            json!({"question":"q","options":(0..13).map(|i| format!("c{i}")).collect::<Vec<_>>()}),
        ] {
            assert!(AskUser.call(&c, input.clone()).is_error, "must reject {input}");
        }
    }
}
