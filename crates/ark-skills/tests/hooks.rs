//! End-to-end proof that the kernel really drives the skills lifecycle hooks.
//!
//! The unit tests in `core::usage` call `tool_settled` directly, which only proves the counter
//! logic. This test builds a real kernel, registers the skills host the way the binary does
//! (`ark_skills::host::tools` + `host::attach`), lets a scripted model call tools, and asserts the
//! tool loop fed `.usage.json` — the `Lifecycle::tool_settled` call in `kernel.rs`.

use ark_core::*;
use ark_kernel::config::{Config, Paths};
use ark_kernel::kernel::{Kernel, Resolver};
use ark_skills::core::{settings::Store, usage};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// One scripted model step per request.
struct Scripted(Mutex<VecDeque<Vec<Block>>>);

impl Provider for Scripted {
    fn id(&self) -> &str {
        "fake"
    }
    fn caps(&self, _: &str) -> ModelCaps {
        ModelCaps { context_window: 200_000, max_output: 8192, tools: true, vision: false, explicit_cache: false }
    }
    fn complete(&self, _req: &ModelRequest, _on_event: &mut dyn FnMut(StreamEvent), _cancel: &Cancel) -> Result<ModelResponse, ProviderError> {
        let content = self.0.lock().unwrap().pop_front().unwrap_or_else(|| vec![Block::text("done")]);
        let stop = if content.iter().any(|b| matches!(b, Block::ToolUse { .. })) { StopReason::ToolUse } else { StopReason::EndTurn };
        Ok(ModelResponse { message: Message { role: Role::Assistant, content }, stop, usage: Usage::default(), model: "m".into() })
    }
}

struct Res(Arc<Scripted>);
impl Resolver for Res {
    fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
        Ok(self.0.clone())
    }
}

/// A reader tool the skills code knows nothing about: any counter it moves comes from the kernel
/// hook alone, which is what isolates the `tool_settled` path.
struct ReadOnly(&'static str);

impl Tool for ReadOnly {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: self.0.into(), description: "read a skill".into(), input_schema: serde_json::json!({"type": "object", "properties": {"name": {"type": "string"}}}), parallel_safe: false, idempotent: true, pinned: false }
    }
    fn effects(&self, _: &ToolCtx, _: &serde_json::Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, _: &ToolCtx, input: serde_json::Value) -> ToolOutput {
        match input.get("name").and_then(|n| n.as_str()) {
            Some(n) => ToolOutput::ok(format!("body of {n}")),
            None => ToolOutput::err("missing name"),
        }
    }
}

fn build(paths: &Paths, ws: &std::path::Path, steps: Vec<Vec<Block>>) -> Kernel {
    let mut cfg = Config::default();
    cfg.model.default = "fake/m".into();
    cfg.checkpoint.enabled = false;
    cfg.runner.max_retries = 1;
    let scripted = Arc::new(Scripted(Mutex::new(steps.into_iter().collect())));
    let mut tools = ark_skills::host::tools(&cfg, paths, ws);
    assert!(tools.iter().any(|t| t.spec().name == "skill"), "the `skill` tool is registered");
    tools.push(Arc::new(ReadOnly("skill_view")));
    let k = ark_kernel::kernel::new_kernel(cfg, paths.clone(), Arc::new(Res(scripted)), tools, Arc::new(ark_kernel::vault::Vault::empty()), Arc::new(ark_kernel::approver::Policy { allow_privilege: true, allow_egress: true }));
    ark_skills::host::attach(&k, ws);
    k
}

fn call(name: &str, input: serde_json::Value) -> Vec<Block> {
    vec![Block::ToolUse { id: format!("tu_{}", ark_kernel::util::random_hex(4)), name: name.into(), input }]
}

fn turn(k: &Kernel, ws: &std::path::Path, prompt: &str) -> String {
    let id = k.create_session(ws, None, None, None).unwrap();
    k.submit(&id, prompt, "test").unwrap();
    k.run(&id, Default::default()).unwrap().text
}

#[test]
fn kernel_tool_settled_feeds_skill_usage() {
    let root = std::env::temp_dir().join(format!("ark-skhooks-{}", ark_kernel::util::random_hex(8)));
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
    std::fs::create_dir_all(&paths.data).unwrap();
    let st = Store::new(&paths);
    std::fs::create_dir_all(st.skills.join("deploy")).unwrap();
    std::fs::write(st.skills.join("deploy/SKILL.md"), "---\nname: deploy\ndescription: Ship it\n---\ndeploy body").unwrap();

    let k = build(
        &paths,
        &ws,
        vec![
            // 1: a reader tool only the kernel hook understands.
            call("skill_view", serde_json::json!({"name": "deploy"})),
            vec![Block::text("loaded")],
            // 2: the real `skill` tool.
            call("skill", serde_json::json!({"action": "view", "name": "deploy"})),
            vec![Block::text("done")],
            // 3: a failed call is not activity.
            call("skill", serde_json::json!({"action": "view", "name": "nope"})),
            vec![Block::text("done")],
        ],
    );

    assert_eq!(turn(&k, &ws, "read deploy"), "loaded");
    let rec = usage::get(&st, "deploy");
    assert_eq!(rec["view_count"].as_i64(), Some(1), "the kernel's tool_settled hook fed the counter: {rec}");
    assert!(rec["last_viewed_at"].as_i64().is_some() && usage::activity_count(&rec) == 1, "{rec}");

    assert_eq!(turn(&k, &ws, "load the deploy skill"), "done");
    let rec = usage::get(&st, "deploy");
    assert!(rec["view_count"].as_i64().unwrap_or(0) >= 2, "the real `skill` tool's view was counted too: {rec}");
    assert!(rec["use_count"].as_i64().unwrap_or(0) >= 1, "{rec}");

    let before = rec["view_count"].as_i64().unwrap_or(0);
    assert_eq!(turn(&k, &ws, "load a missing skill"), "done");
    assert_eq!(usage::get(&st, "deploy")["view_count"].as_i64().unwrap_or(0), before, "a failed view is not counted");
    let _ = std::fs::remove_dir_all(&root);
}
