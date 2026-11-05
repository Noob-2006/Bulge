//! Context engines (OpenClaw `ContextEngine`, MIT): something outside the kernel that
//! keeps its own view of a conversation and decides what the model sees. The kernel
//! still owns the event log; an engine only shapes requests and, if it says so, writes
//! the compaction summaries. Selected with `context_engine = "<plugin>"`.

use seagent_core::Message;
use std::sync::Arc;

/// What `assemble` returns: the messages to send instead of the projected history.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Assembled {
    pub messages: Vec<Message>,
    /// Extra system text for this request only (OC `systemPromptAddition`).
    pub system_addition: Option<String>,
}

/// What `compact` returns when the engine compacted.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Compacted {
    pub summary: String,
    /// Most recent messages to keep verbatim (default: `[compaction] keep_messages`).
    pub keep_messages: Option<usize>,
}

pub trait ContextEngine: Send + Sync {
    fn name(&self) -> String;
    /// The engine writes summaries itself (OC `info.ownsCompaction`).
    fn owns_compaction(&self) -> bool;
    /// A message was appended to the session (fire and forget).
    fn ingest(&self, session: &str, message: &Message);
    /// `Ok(None)`: use the kernel's own history. `Err`: the engine failed (the kernel warns
    /// and falls back).
    fn assemble(&self, session: &str, workspace: &str, messages: &[Message], token_budget: u64, model: &str, prompt: &str) -> Result<Option<Assembled>, String>;
    /// `Ok(None)`: nothing compacted.
    fn compact(&self, session: &str, messages: &[Message], token_budget: u64, current_tokens: u64, force: bool) -> Result<Option<Compacted>, String>;
    /// Tools this engine brings with it (Hermes `ContextEngine.get_tool_schemas` /
    /// `handle_tool_call`): the kernel shows them to the model next to the builtin tools
    /// and dispatches calls to them, so an engine can serve e.g. its own memory lookup.
    /// Default: none.
    fn tools(&self) -> Vec<Arc<dyn seagent_core::Tool>> {
        Vec::new()
    }
}

/// An assembled history must still be a valid conversation: non-empty, starting and
/// ending with the user (tool results ride in user messages).
pub fn valid(messages: &[Message]) -> bool {
    use seagent_core::Role;
    matches!((messages.first(), messages.last()), (Some(f), Some(l)) if f.role == Role::User && l.role == Role::User)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembled_history_must_start_and_end_with_the_user() {
        assert!(!valid(&[]));
        assert!(valid(&[Message::user("hi")]));
        assert!(!valid(&[Message::user("hi"), Message::assistant("yo")]));
        assert!(!valid(&[Message::assistant("yo"), Message::user("hi")]));
    }

    // ───────── engine-provided tools (Hermes `get_tool_schemas` / `handle_tool_call`) ─────────

    use seagent_core::{Block, Cancel, Effect, ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError, Role, StopReason, StreamEvent, Tool, ToolCtx, ToolOutput, ToolSpec, Usage};
    use crate::config::{Config, Paths};
    use crate::kernel::{new_kernel, Resolver, RunOpts};
    use serde_json::{json, Value};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    /// A tool that only exists because the engine brings it.
    struct EngineEcho;
    impl Tool for EngineEcho {
        fn spec(&self) -> ToolSpec {
            ToolSpec {
                name: "engine_echo".into(),
                description: "Echo text back through the context engine's own tool.".into(),
                input_schema: json!({"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}),
                parallel_safe: true,
                idempotent: true,
                pinned: true,
            }
        }
        fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
            vec![]
        }
        fn call(&self, _: &ToolCtx, input: Value) -> ToolOutput {
            ToolOutput::ok(format!("engine saw: {}", input["text"].as_str().unwrap_or("")))
        }
    }

    /// Minimal engine: borrows the test tool, does nothing else.
    struct WithTool(Arc<dyn Tool>);
    impl ContextEngine for WithTool {
        fn name(&self) -> String {
            "with-tool".into()
        }
        fn owns_compaction(&self) -> bool {
            false
        }
        fn ingest(&self, _: &str, _: &Message) {}
        fn assemble(&self, _: &str, _: &str, _: &[Message], _: u64, _: &str, _: &str) -> Result<Option<Assembled>, String> {
            Ok(None)
        }
        fn compact(&self, _: &str, _: &[Message], _: u64, _: u64, _: bool) -> Result<Option<Compacted>, String> {
            Ok(None)
        }
        fn tools(&self) -> Vec<Arc<dyn Tool>> {
            vec![self.0.clone()]
        }
    }

    /// An engine that does not override `tools()`: adds nothing.
    struct Bare;
    impl ContextEngine for Bare {
        fn name(&self) -> String {
            "bare".into()
        }
        fn owns_compaction(&self) -> bool {
            false
        }
        fn ingest(&self, _: &str, _: &Message) {}
        fn assemble(&self, _: &str, _: &str, _: &[Message], _: u64, _: &str, _: &str) -> Result<Option<Assembled>, String> {
            Ok(None)
        }
        fn compact(&self, _: &str, _: &[Message], _: u64, _: u64, _: bool) -> Result<Option<Compacted>, String> {
            Ok(None)
        }
    }

    /// Calls `engine_echo` once, then answers with text.
    struct Scripted {
        steps: Mutex<VecDeque<Block>>,
        seen: Mutex<Vec<ModelRequest>>,
    }
    impl Provider for Scripted {
        fn id(&self) -> &str {
            "fake"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 100_000, max_output: 4096, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            self.seen.lock().unwrap().push(req.clone());
            let mut steps = self.steps.lock().unwrap();
            let content = match steps.pop_front() {
                Some(b) => vec![b],
                None => vec![Block::text("done")],
            };
            drop(steps);
            let stop = if content.iter().any(|b| matches!(b, Block::ToolUse { .. })) { StopReason::ToolUse } else { StopReason::EndTurn };
            Ok(ModelResponse { message: Message { role: Role::Assistant, content }, stop, usage: Usage::default(), model: req.model.clone() })
        }
    }
    struct Res(Arc<Scripted>);
    impl Resolver for Res {
        fn provider(&self, _: &str) -> Result<Arc<dyn Provider>, String> {
            Ok(self.0.clone())
        }
    }

    fn kernel_with(cfg_mut: impl FnOnce(&mut Config), engine: Option<Arc<dyn ContextEngine>>) -> (crate::kernel::Kernel, Arc<Scripted>, Paths) {
        let root = seagent_core::tmp::scratch_path(format!("seagent-engine-tools-{}", crate::util::random_hex(8)));
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        std::fs::create_dir_all(&paths.data).unwrap();
        let mut cfg = Config::default();
        cfg.model.default = "fake/m".into();
        cfg.checkpoint.enabled = false;
        cfg_mut(&mut cfg);
        let p = Arc::new(Scripted { steps: Mutex::new(VecDeque::new()), seen: Mutex::new(vec![]) });
        let k = new_kernel(cfg, paths.clone(), Arc::new(Res(p.clone())), vec![], Arc::new(crate::vault::Vault::empty()), Arc::new(crate::approver::Policy { allow_privilege: true, allow_egress: true }));
        if let Some(e) = engine {
            k.set_context_engine(e);
        }
        (k, p, paths)
    }

    #[test]
    fn engine_tools_are_model_visible_and_dispatchable() {
        assert!(Bare.tools().is_empty(), "the default adds no tools");
        assert!(WithTool(Arc::new(EngineEcho)).tools().len() == 1);

        let (k, p, paths) = kernel_with(|_| {}, Some(Arc::new(WithTool(Arc::new(EngineEcho)))));
        assert!(k.specs().iter().any(|s| s.name == "engine_echo"), "the engine's tool is in the model-visible list");
        p.steps.lock().unwrap().push_back(Block::ToolUse { id: "tu1".into(), name: "engine_echo".into(), input: json!({"text": "hi"}) });
        let ws = paths.data.parent().unwrap().join("ws");
        let id = k.create_session(&ws, None, None, None).unwrap();
        k.submit(&id, "use the engine tool", "user").unwrap();
        k.run(&id, RunOpts::default()).unwrap();
        let reqs = p.seen.lock().unwrap().clone();

        assert!(reqs[0].tools.iter().any(|t| t.name == "engine_echo"), "shipped to the model: {:?}", reqs[0].tools.iter().map(|t| &t.name).collect::<Vec<_>>());
        let second = reqs.last().unwrap();
        let results: Vec<&str> = second.messages.iter().flat_map(|m| m.content.iter()).filter_map(|b| match b {
            Block::ToolResult { content, .. } => Some(content.as_str()),
            _ => None,
        }).collect();
        assert_eq!(results, ["engine saw: hi"], "the engine's tool ran and its output went back to the model");

        // `tools.disabled` still wins over the engine.
        let (off, _, _) = kernel_with(|c| c.tools.disabled = vec!["engine_echo".into()], Some(Arc::new(WithTool(Arc::new(EngineEcho)))));
        assert!(off.specs().iter().all(|s| s.name != "engine_echo"), "a disabled tool stays hidden");
    }
}
