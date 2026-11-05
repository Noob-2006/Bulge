//! Context-usage benchmark (srv-041): how many tokens each model request carries, averaged
//! over a recorded session, with and without the retrieval-based trimming
//! (`[compaction] max_tool_result_chars` + `context_fetch`). `ark index bench <session>` runs
//! it on a real session; the test below drives the kernel with a scripted model so the
//! numbers are reproducible and a regression shows up as a failing assertion.

use crate::config::Config;
use crate::event::{Event, EventKind};
use crate::projection::project;
use ark_core::{estimate_request_tokens, ModelRequest, Role};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Bench {
    /// Model requests found in the log (one per assistant message).
    pub requests: usize,
    /// Average / peak / total estimated input tokens (system + conversation) per request,
    /// as the history stands (`raw`) and after clipping old tool results (`trimmed`).
    pub avg_raw: u64,
    pub avg_trimmed: u64,
    pub max_raw: u64,
    pub max_trimmed: u64,
    pub total_raw: u64,
    pub total_trimmed: u64,
}

impl Bench {
    pub fn saved_pct(&self) -> f64 {
        if self.total_raw == 0 {
            0.0
        } else {
            100.0 * (self.total_raw.saturating_sub(self.total_trimmed)) as f64 / self.total_raw as f64
        }
    }
    pub fn render(&self) -> String {
        format!(
            "requests: {}\navg tokens/request: {} untrimmed → {} with retrieval trimming ({:.1}% less)\npeak: {} → {}\ntotal: {} → {}",
            self.requests,
            self.avg_raw,
            self.avg_trimmed,
            self.saved_pct(),
            self.max_raw,
            self.max_trimmed,
            self.total_raw,
            self.total_trimmed
        )
    }
}

fn tokens(view: &crate::projection::View, messages: Vec<ark_core::Message>) -> u64 {
    estimate_request_tokens(&ModelRequest { model: String::new(), system: view.system.clone(), messages, tools: vec![], max_tokens: 0, temperature: None, cache_after_message: None, reasoning: None, options: Default::default() })
}

/// Replay a session log: for every assistant message, rebuild the history the request that
/// produced it saw and measure it untrimmed and trimmed under `cfg`.
pub fn replay(events: &[Event], cfg: &Config) -> Bench {
    let mut b = Bench::default();
    for (i, e) in events.iter().enumerate() {
        let EventKind::Message { message, .. } = &e.kind else { continue };
        if message.role != Role::Assistant {
            continue;
        }
        let view = project(&events[..i]);
        let raw = tokens(&view, view.messages.clone());
        let mut msgs = view.messages.clone();
        crate::context::trim_old_tool_results(&mut msgs, cfg.compaction.max_tool_result_chars, cfg.compaction.keep_tool_results);
        let trimmed = tokens(&view, msgs);
        b.requests += 1;
        b.total_raw += raw;
        b.total_trimmed += trimmed;
        b.max_raw = b.max_raw.max(raw);
        b.max_trimmed = b.max_trimmed.max(trimmed);
    }
    if b.requests > 0 {
        b.avg_raw = b.total_raw / b.requests as u64;
        b.avg_trimmed = b.total_trimmed / b.requests as u64;
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Paths;
    use crate::kernel::{new_kernel, Resolver, RunOpts};
    use ark_core::{Block, Cancel, Effect, Message, ModelCaps, ModelResponse, Provider, ProviderError, StopReason, StreamEvent, Tool, ToolCtx, ToolOutput, ToolSpec, Usage};
    use serde_json::{json, Value};
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    /// A build/test log of a given size with a needle per call (what agents read most).
    struct BigOut;
    impl Tool for BigOut {
        fn spec(&self) -> ToolSpec {
            ToolSpec { name: "bigout".into(), description: "print a long log".into(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"size":{"type":"integer"}}}), parallel_safe: true, idempotent: true, pinned: true }
        }
        fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
            vec![]
        }
        fn call(&self, _: &ToolCtx, input: Value) -> ToolOutput {
            let n = input["n"].as_u64().unwrap_or(0);
            let size = input["size"].as_u64().unwrap_or(1000) as usize;
            let mut s = String::new();
            let mut i = 0;
            let mut planted = false;
            while s.len() < size {
                if !planted && s.len() >= size / 2 {
                    planted = true;
                    s.push_str(&format!("warning: needle-{n} unused variable in src/mod_{n}.rs\n"));
                }
                s.push_str(&format!("   Compiling crate-{n}-{i} v0.{i}.0 (/work/crates/crate-{n}-{i})\n"));
                i += 1;
            }
            ToolOutput::ok(s)
        }
    }

    /// Scripted model: plays `steps`, records the estimated size of every request.
    struct Scripted {
        steps: Mutex<VecDeque<Block>>,
        sizes: Mutex<Vec<u64>>,
        last: Mutex<Option<ModelRequest>>,
    }
    impl Provider for Scripted {
        fn id(&self) -> &str {
            "fake"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps { context_window: 1_000_000, max_output: 4096, tools: true, vision: false, explicit_cache: false }
        }
        fn complete(&self, req: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            let mut r = req.clone();
            r.tools.clear(); // schemas are identical in both runs; measure system + conversation
            self.sizes.lock().unwrap().push(estimate_request_tokens(&r));
            *self.last.lock().unwrap() = Some(req.clone());
            let content = match self.steps.lock().unwrap().pop_front() {
                Some(b) => vec![b],
                None => vec![Block::text("done")],
            };
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

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The recorded conversation: 30 tool calls with mixed output sizes, then a
    /// `context_fetch` of an early output, a search over all of them, then the answer.
    const SIZES: [u64; 6] = [300, 4_000, 12_000, 1_500, 9_000, 15_000];
    const CALLS: u64 = 30;

    fn run(max_tool_result_chars: usize) -> (Vec<u64>, ModelRequest, Vec<Event>, Config, Dir) {
        let root = std::env::temp_dir().join(format!("ark-ctxbench-{}", crate::util::random_hex(8)));
        let dir = Dir(root.clone());
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
        std::fs::create_dir_all(&paths.data).unwrap();
        let mut cfg = Config::default();
        cfg.model.default = "fake/m".into();
        cfg.checkpoint.enabled = false;
        cfg.compaction.max_tool_result_chars = max_tool_result_chars;
        let mut steps: VecDeque<Block> = (0..CALLS).map(|n| Block::ToolUse { id: format!("t{n}"), name: "bigout".into(), input: json!({"n": n, "size": SIZES[n as usize % SIZES.len()]}) }).collect();
        steps.push_back(Block::ToolUse { id: "fetch".into(), name: "context_fetch".into(), input: json!({"id": "t2", "query": "needle-2"}) });
        steps.push_back(Block::ToolUse { id: "find".into(), name: "context_fetch".into(), input: json!({"query": "needle-5"}) });
        let p = Arc::new(Scripted { steps: Mutex::new(steps), sizes: Mutex::new(vec![]), last: Mutex::new(None) });
        let k = new_kernel(cfg.clone(), paths.clone(), Arc::new(Res(p.clone())), vec![Arc::new(BigOut)], Arc::new(crate::vault::Vault::empty()), Arc::new(crate::approver::Policy { allow_privilege: true, allow_egress: true }));
        let id = k.create_session(&ws, None, None, None).unwrap();
        k.submit(&id, "build everything and tell me which modules warn", "user").unwrap();
        k.run(&id, RunOpts::default()).unwrap();
        let sizes = p.sizes.lock().unwrap().clone();
        let last = p.last.lock().unwrap().clone().unwrap();
        let events = k.store.read(&id).unwrap();
        (sizes, last, events, cfg, dir)
    }

    fn avg(v: &[u64]) -> u64 {
        v.iter().sum::<u64>() / v.len().max(1) as u64
    }

    fn results(req: &ModelRequest) -> Vec<(String, String)> {
        req.messages
            .iter()
            .flat_map(|m| m.content.iter())
            .filter_map(|b| match b {
                Block::ToolResult { tool_use_id, content, .. } => Some((tool_use_id.clone(), content.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn context_usage_benchmark_before_and_after_retrieval_trimming() {
        let (before, _, events_before, cfg_before, _d1) = run(0);
        let (after, last, events_after, cfg_after, _d2) = run(Config::default().compaction.max_tool_result_chars);
        assert_eq!(before.len(), after.len(), "same conversation, same number of requests");
        let (b, a) = (avg(&before), avg(&after));
        let (pb, pa) = (*before.iter().max().unwrap(), *after.iter().max().unwrap());
        eprintln!("ctxbench: {} requests; avg tokens/request {b} -> {a} ({:.1}% less); peak {pb} -> {pa}", before.len(), 100.0 * (b - a) as f64 / b as f64);
        assert!(a * 100 < b * 60, "retrieval trimming must cut the average request by >=40%: {b} -> {a}");
        assert!(pa * 100 < pb * 55, "and the peak by >=45%: {pb} -> {pa}");

        // Nothing is lost: the clipped output comes back through context_fetch.
        let r = results(&last);
        let fetched = &r.iter().find(|(id, _)| id == "fetch").unwrap().1;
        assert!(fetched.contains("needle-2 unused variable"), "fetch by id + query: {fetched}");
        let found = &r.iter().find(|(id, _)| id == "find").unwrap().1;
        assert!(found.contains("id t5") && found.contains("needle-5"), "search over earlier tool outputs: {found}");
        let early = &r.iter().find(|(id, _)| id == "t2").unwrap().1;
        assert!(early.contains("context_fetch {\"id\":\"t2\"}"), "the clip marker names the tool and the id: {early}");
        assert!(!early.contains("needle-2"), "…and the needle itself was clipped out of the old result");

        // The replay over the recorded log agrees with what the model was sent.
        let rb = replay(&events_before, &cfg_before);
        let ra = replay(&events_after, &cfg_after);
        assert_eq!(rb.requests, before.len());
        assert_eq!(rb.avg_raw, rb.avg_trimmed, "max_tool_result_chars = 0 is the untrimmed baseline");
        assert!(ra.avg_trimmed * 100 < ra.avg_raw * 60, "{}", ra.render());
        eprintln!("ctxbench replay:\n{}", ra.render());
    }
}
