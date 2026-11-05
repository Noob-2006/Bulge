//! `fake/*` models: deterministic stand-ins that let the whole evaluation pipeline run offline
//! (load → run → grade → report) without a key, a network or a bill.
//!
//! | model         | behaviour |
//! |---------------|-----------|
//! | `fake/oracle` | follows the task's `fake` script: one shell tool call per command (when the harness offers `shell` or `terminal`), then the scripted answer; with no script it answers generically. When the system prompt carries a professional-role block, the answer also restates that block's rules — so "with guidelines" beats "without", and removing a rule removes what it contributed (the role ablation is observable). |
//! | `fake/blank`  | always answers that it does not know, never calls a tool (a floor for reports). |
//!
//! `seagent distill` prompts carry a `[seagent-distill:<stage>]` marker; the oracle answers those with
//! structured output built from the prompt itself (see [`crate::ops::distill::fake_reply`]).
//! Token counts are `chars / 4` of what was sent and returned, so token and cost columns fill in.

use super::FakeScript;
use seagent_core::{Block, Cancel, Message, ModelCaps, ModelRequest, ModelResponse, Provider, ProviderError, Role, StopReason, StreamEvent, Usage};
use serde_json::json;
use std::sync::{Arc, Mutex};

pub const PROVIDER: &str = "fake";

pub fn is_fake(model: &str) -> bool {
    model.split_once('/').map(|(p, _)| p == PROVIDER).unwrap_or(false)
}

#[derive(Default)]
pub struct Fake {
    scripts: Mutex<Vec<(String, FakeScript)>>,
}

impl Fake {
    pub fn new() -> Arc<Fake> {
        Arc::new(Fake::default())
    }
    /// Script the oracle for a prompt (matched as a substring of the first user message, so
    /// harness wrappers around the prompt do not break the match).
    pub fn register(&self, prompt: &str, s: FakeScript) {
        let mut v = self.scripts.lock().unwrap();
        v.retain(|(p, _)| p != prompt);
        v.push((prompt.to_string(), s));
    }
    fn script_for(&self, user: &str) -> Option<FakeScript> {
        let v = self.scripts.lock().unwrap();
        // longest registered prompt that matches wins (a prompt may contain another)
        v.iter().filter(|(p, _)| !p.is_empty() && user.contains(p.as_str())).max_by_key(|(p, _)| p.len()).map(|(_, s)| s.clone())
    }
}

/// Rule lines (`- …`) of the professional-role block in a system prompt.
pub fn role_rules(system: &str) -> Vec<String> {
    let mut on = false;
    let mut out = vec![];
    for l in system.lines() {
        if l.starts_with("# ") {
            on = l.starts_with("# Professional role");
            continue;
        }
        if on {
            if let Some(r) = l.trim_start().strip_prefix("- ") {
                out.push(r.trim().to_string());
            }
        }
    }
    out
}

fn tokens(s: &str) -> u64 {
    (s.chars().count() as u64).div_ceil(4)
}

impl Provider for Fake {
    fn id(&self) -> &str {
        PROVIDER
    }
    fn caps(&self, _: &str) -> ModelCaps {
        ModelCaps { context_window: 200_000, max_output: 8192, tools: true, vision: false, explicit_cache: false }
    }
    fn complete(&self, req: &ModelRequest, on: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
        let variant = req.model.rsplit('/').next().unwrap_or("oracle").to_string();
        let first_user = req.messages.iter().find(|m| m.role == Role::User).map(Message::text).unwrap_or_default();
        let system = req.system_text();
        let sent = system.chars().count() + req.messages.iter().map(|m| m.text().chars().count()).sum::<usize>();
        let done = req.messages.iter().flat_map(|m| m.content.iter()).filter(|b| matches!(b, Block::ToolResult { .. })).count();
        let shell = req.tools.iter().map(|t| t.name.as_str()).find(|n| *n == "shell" || *n == "terminal").map(String::from);
        let message = match variant.as_str() {
            "blank" => Message::assistant("我不知道。"),
            _ => {
                let script = self.script_for(&first_user);
                match (&script, &shell) {
                    (Some(s), Some(tool)) if done < s.commands.len() => Message {
                        role: Role::Assistant,
                        content: vec![Block::ToolUse { id: format!("fake{done}"), name: tool.clone(), input: json!({"command": s.commands[done]}) }],
                    },
                    _ => {
                        let mut text = if let Some(r) = crate::ops::distill::fake_reply(&first_user) {
                            r
                        } else {
                            script.as_ref().map(|s| s.answer.clone()).filter(|a| !a.is_empty()).unwrap_or_else(|| "我會先釐清狀況與影響範圍，再提出處理方式。".to_string())
                        };
                        let rules = role_rules(&system);
                        if !rules.is_empty() {
                            text.push_str("\n\n依照角色準則：\n");
                            for r in rules {
                                text.push_str(&format!("- {r}\n"));
                            }
                        }
                        Message::assistant(text)
                    }
                }
            }
        };
        let out_text = message.text();
        if !out_text.is_empty() {
            on(StreamEvent::TextDelta(out_text.clone()));
        }
        Ok(ModelResponse {
            stop: if message.content.iter().any(|b| matches!(b, Block::ToolUse { .. })) { StopReason::ToolUse } else { StopReason::EndTurn },
            usage: Usage { input_tokens: tokens(&"x".repeat(sent)), output_tokens: tokens(&out_text).max(1), ..Default::default() },
            model: req.model.clone(),
            message,
        })
    }
}

/// Resolves `fake` to the stand-in and everything else to the user's configured providers
/// (built only when a real model was named).
pub struct EvalResolver {
    pub fake: Arc<Fake>,
    pub real: Option<Arc<dyn seagent_kernel::kernel::Resolver>>,
}

impl seagent_kernel::kernel::Resolver for EvalResolver {
    fn provider(&self, id: &str) -> Result<Arc<dyn Provider>, String> {
        if id == PROVIDER {
            return Ok(self.fake.clone());
        }
        match &self.real {
            Some(r) => r.provider(id),
            None => Err(format!("provider `{id}` is not configured for this run")),
        }
    }
}

/// Wraps a provider and adds up the usage of every call made through it (one per attempt).
pub struct Meter {
    pub inner: Arc<dyn Provider>,
    pub usage: Mutex<Usage>,
    pub calls: Mutex<u64>,
}

impl Meter {
    pub fn new(inner: Arc<dyn Provider>) -> Arc<Meter> {
        Arc::new(Meter { inner, usage: Mutex::new(Usage::default()), calls: Mutex::new(0) })
    }
    pub fn total(&self) -> (Usage, u64) {
        (*self.usage.lock().unwrap(), *self.calls.lock().unwrap())
    }
}

impl Provider for Meter {
    fn id(&self) -> &str {
        self.inner.id()
    }
    fn caps(&self, m: &str) -> ModelCaps {
        self.inner.caps(m)
    }
    fn complete(&self, req: &ModelRequest, on: &mut dyn FnMut(StreamEvent), c: &Cancel) -> Result<ModelResponse, ProviderError> {
        let r = self.inner.complete(req, on, c)?;
        let mut u = self.usage.lock().unwrap();
        u.input_tokens += r.usage.input_tokens;
        u.output_tokens += r.usage.output_tokens;
        u.cache_read_tokens += r.usage.cache_read_tokens;
        u.cache_write_tokens += r.usage.cache_write_tokens;
        *self.calls.lock().unwrap() += 1;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_core::{SystemSegment, ToolSchema};

    fn req(model: &str, system: &str, msgs: Vec<Message>, tools: bool) -> ModelRequest {
        ModelRequest {
            model: model.into(),
            system: vec![SystemSegment { id: "s".into(), text: system.into(), cache: false }],
            messages: msgs,
            tools: if tools { vec![ToolSchema { name: "shell".into(), description: String::new(), input_schema: json!({}) }] } else { vec![] },
            max_tokens: 100,
            ..Default::default()
        }
    }

    #[test]
    fn oracle_runs_the_script_then_answers_and_echoes_role_rules() {
        let f = Fake::new();
        f.register("fix it", FakeScript { commands: vec!["echo a".into()], answer: "done".into() });
        let r = f.complete(&req("fake/oracle", "", vec![Message::user("please fix it now")], true), &mut |_| {}, &Cancel::new()).unwrap();
        assert!(matches!(&r.message.content[0], Block::ToolUse { name, input, .. } if name == "shell" && input["command"] == "echo a"));
        let msgs = vec![Message::user("please fix it now"), r.message.clone(), Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: "fake0".into(), content: "a".into(), is_error: false }] }];
        let r = f.complete(&req("fake/oracle", "", msgs, true), &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "done");
        assert!(r.usage.input_tokens > 0 && r.usage.output_tokens > 0);
        // role block → rules restated; other headings end the block
        let sys = "# Professional conduct\n- core rule\n# Professional role: x [role:x]\n## A\n- rule one\n- rule two\n";
        assert_eq!(role_rules(sys), vec!["rule one", "rule two"]);
        let r = f.complete(&req("fake/oracle", sys, vec![Message::user("q")], false), &mut |_| {}, &Cancel::new()).unwrap();
        assert!(r.message.text().contains("- rule two") && !r.message.text().contains("core rule"));
        let r = f.complete(&req("fake/blank", sys, vec![Message::user("q")], true), &mut |_| {}, &Cancel::new()).unwrap();
        assert_eq!(r.message.text(), "我不知道。");
        assert!(is_fake("fake/x") && !is_fake("openai/gpt") && !is_fake("fake"));
    }
}
