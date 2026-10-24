//! How every agent of a session is assembled — the head, its leads, workers
//! and reviewers alike. The safety settings (guard rules, autonomy, review
//! gate, completion gate) live here once, so a new kind of agent cannot be
//! built without them.

use std::sync::Arc;

use bulge_core::driver::{CompletionConfig, ContextConfig, Driver, GuardConfig, Sampling};
use bulge_core::hooks::{HookRunner, HookedDispatcher};
use bulge_core::ToolDispatcher;
use bulge_guard::Ruleset;
use bulge_llm::{LlmBackend, ToolSchema};
use bulge_store::Autonomy;

/// What all of a session's agents share.
#[derive(Clone)]
pub struct DriverRecipe {
    pub backend: Arc<dyn LlmBackend>,
    /// The baseline plus the real-world rules (which come last, so they win).
    pub guard_rules: Ruleset,
    pub autonomy: Autonomy,
    pub context_window: u32,
    /// Vet every mutating call with the reviewer model.
    pub auto_review: bool,
}

impl DriverRecipe {
    /// A driver with this recipe's guard, completion gate, context window and
    /// review gate; it spends from `ledger`. Callers add the handlers their
    /// kind of agent has (delegation, recall, …).
    pub fn driver(&self, dispatcher: Arc<dyn ToolDispatcher>, tools: Vec<ToolSchema>, system_prompt: String, sampling: Sampling, ledger: Arc<bulge_core::ledger::Ledger>) -> Driver {
        Driver::new(self.backend.clone(), dispatcher, tools, system_prompt)
            .with_guard(GuardConfig { rules: self.guard_rules.clone(), autonomy: self.autonomy, loop_detection: true })
            .with_completion_gate(CompletionConfig::default())
            .with_context(ContextConfig { window: u64::from(self.context_window), ..ContextConfig::default() })
            .with_sampling(sampling)
            .with_review(self.auto_review)
            .with_ledger(ledger)
    }
}

/// `base` with the user's lifecycle hooks around it (as is, when there are none).
pub fn with_hooks(base: Arc<dyn ToolDispatcher>, hooks: &Arc<HookRunner>) -> Arc<dyn ToolDispatcher> {
    if hooks.is_empty() { base } else { Arc::new(HookedDispatcher::new(base, hooks.clone())) }
}
