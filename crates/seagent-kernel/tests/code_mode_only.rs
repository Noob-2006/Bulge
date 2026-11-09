//! `[exec.code] run_code_only`: the model sees exactly one tool (`run`), while tools called
//! from inside the script still execute through the kernel's nested-call path.

use seagent_core::{Block, Cancel, Message, ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError, Role, StopReason, StreamEvent, Tool, ToolCtx, ToolOutput, ToolSpec, Usage};
use seagent_kernel::approver::Policy;
use seagent_kernel::config::{Config, Paths};
use seagent_kernel::kernel::{new_kernel, Kernel, Resolver, RunOpts};
use seagent_kernel::vault::Vault;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

struct Step(Block);
impl Step {
    fn text(s: &str) -> Step {
        Step(Block::text(s))
    }
    fn call(name: &str, input: Value) -> Step {
        Step(Block::ToolUse { id: "tu1".into(), name: name.into(), input })
    }
}

struct Scripted {
    steps: Mutex<VecDeque<Step>>,
    seen: Mutex<Vec<ModelRequest>>,
}

impl Provider for Scripted {
    fn id(&self) -> &str {
        "p"
    }
    fn caps(&self, _: &str) -> ModelCaps {
        ModelCaps { context_window: 100_000, max_output: 4096, tools: true, vision: false, explicit_cache: false }
    }
    fn complete(&self, req: &ModelRequest, on: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
        self.seen.lock().unwrap().push(req.clone());
        let block = self.steps.lock().unwrap().pop_front().map(|s| s.0).unwrap_or_else(|| Block::text("done"));
        let stop = if matches!(block, Block::ToolUse { .. }) { StopReason::ToolUse } else { StopReason::EndTurn };
        let text = match &block {
            Block::Text { text } => text.clone(),
            _ => String::new(),
        };
        if !text.is_empty() {
            on(StreamEvent::TextDelta(text));
        }
        Ok(ModelResponse { message: Message { role: Role::Assistant, content: vec![block] }, stop, usage: Usage { input_tokens: 10, output_tokens: 2, ..Default::default() }, model: req.model.clone() })
    }
}

struct Res(Arc<Scripted>);
impl Resolver for Res {
    fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
        Ok(self.0.clone())
    }
}

struct Echo;
impl Tool for Echo {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "echo".into(), description: "echo text".into(), input_schema: json!({"type":"object","properties":{"text":{"type":"string"}}}), parallel_safe: true, idempotent: true, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<seagent_core::Effect> {
        vec![]
    }
    fn call(&self, _: &ToolCtx, input: Value) -> ToolOutput {
        ToolOutput::ok(input["text"].as_str().unwrap_or("").to_string())
    }
}

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        seagent_kernel::coderun::configure(Default::default());
    }
}

#[test]
fn run_code_only_exposes_run_and_nested_calls_still_work() {
    let root = seagent_core::tmp::TempDir::new("seagent-code-only");
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
    let mut cfg = Config::default();
    cfg.model.default = "p/m".into();
    cfg.checkpoint.enabled = false;
    let p = Arc::new(Scripted {
        steps: Mutex::new(VecDeque::from([
            Step::call(
                "run",
                // Unix: the call socket is a unix socket. Windows: `tcp:127.0.0.1:<port>` + the
                // same token (Python has no AF_UNIX there).
                if cfg!(windows) {
                    json!({"script": "python3 - <<'PY'\nimport os,socket,json\nh,p=os.environ['SEAGENT_CALL_SOCK'][4:].rsplit(':',1); s=socket.create_connection((h,int(p)))\ns.sendall((json.dumps({'token':os.environ['SEAGENT_CALL_TOKEN'],'tool':'echo','input':{'text':'from nested'}})+'\\n').encode())\nprint(s.makefile().readline().strip())\nPY"})
                } else {
                    json!({"script": "python3 - <<'PY'\nimport os,socket,json\ns=socket.socket(socket.AF_UNIX); s.connect(os.environ['SEAGENT_CALL_SOCK'])\ns.sendall((json.dumps({'token':os.environ['SEAGENT_CALL_TOKEN'],'tool':'echo','input':{'text':'from nested'}})+'\\n').encode())\nprint(s.makefile().readline().strip())\nPY"})
                },
            ),
            Step::text("done"),
        ])),
        seen: Mutex::new(vec![]),
    });
    let k: Kernel = new_kernel(cfg, paths, Arc::new(Res(p.clone())), vec![Arc::new(Echo)], Arc::new(Vault::empty()), Arc::new(Policy { allow_privilege: false, allow_egress: true }));
    seagent_kernel::coderun::configure(seagent_kernel::coderun::CodeConfig { run_code_only: true, ..Default::default() });
    let _reset = Reset;
    let id = k.create_session(&ws, None, None, None).unwrap();
    k.submit(&id, "get it", "user").unwrap();
    let o = k.run(&id, RunOpts::default()).unwrap();
    assert_eq!(o.text, "done");

    let reqs = p.seen.lock().unwrap().clone();
    let names: Vec<&str> = reqs[0].tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, vec!["run"], "only run_code is callable: {names:?}");
    assert!(!reqs[0].system_text().contains("- echo:"), "no tool index for hidden tools: {}", reqs[0].system_text());
    let nested: Vec<String> = reqs[1]
        .messages
        .iter()
        .flat_map(|m| m.content.iter())
        .filter_map(|b| match b {
            Block::ToolResult { tool_use_id, content, .. } if tool_use_id == "tu1" => Some(content.clone()),
            _ => None,
        })
        .collect();
    assert!(nested.iter().any(|c| c.contains("from nested") && !c.contains("unknown tool")), "{nested:?}");
}
