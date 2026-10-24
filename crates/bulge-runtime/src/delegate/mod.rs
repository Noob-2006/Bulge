//! Sub-agent delegation: a host-handled `delegate` tool that runs a focused
//! sub-task in a fresh nested agent loop and returns ONLY its final summary.
//!
//! The parent agent is the organization's head (lead): every delegation names a
//! role from the role library, runs a child AS that role (charter as system
//! prompt, tool allowlist, model/reasoning override), and records the work as a
//! ticket on a persistent board. The child's result comes back as an org-bus
//! Report (threat-scanned and redacted) and the head can ask for a model-free
//! situation report at any time.
//!
//! The child runs in the parent's VM but gets its own VM workspace slot: a
//! private overlay, uid and namespace, so concurrent children can edit the same
//! paths without stepping on each other. Hooks and the review gate still apply;
//! MCP tools are deliberately filtered out of the child's tool list because MCP
//! servers run on the host, outside any slot. The child runs a separate
//! conversation with its own store job and a smaller budget.
//! The child is given every tool EXCEPT `delegate` and `org_status`, so
//! delegation is naturally capped at one level (no runaway recursion). The
//! parent transcript never sees the child's intermediate steps — only the
//! delegate call and the structured [`bulge_core::driver::DelegateReport`] —
//! matching the deepseek/Hermes "parent sees the summary, not the child's
//! reasoning" model.
//!
//! Children of one parent run concurrently (up to
//! [`MAX_CONCURRENT_SUBAGENTS`] from a tree-wide slot pool), are charged to the
//! parent's [`Ledger`](bulge_core::ledger::Ledger) so delegating can never spend
//! past the job's own budget, and all instances of one role share a stable
//! charter prompt so their requests share a cached prefix.
//!
//! The driver calls this through [`bulge_core::driver::DelegateHandler`]: the
//! child runs a nested driver whose future is `!Send` (it schedules tool calls on
//! the current thread), so delegation is handled inside the driver loop, not in a
//! `Send` dispatcher.

mod factory;
mod governance;
mod policy;
mod ticket;
mod vm_slots;
mod worker;

pub use factory::*;
pub use governance::*;
pub use policy::*;
pub use vm_slots::*;
pub use worker::*;

/// Most sub-agents that may run at once across one delegation tree (the parent
/// root ledger's slot pool). A call beyond this fails with `SLOTS_FULL` rather
/// than queueing, so the model can adapt instead of hanging.
pub const MAX_CONCURRENT_SUBAGENTS: usize = 8;

/// Deepest level a delegated agent may occupy. The head is depth 0, so leads
/// may sit at depths 1 and 2 and their workers at depth 3.
pub const MAX_DEPTH: u32 = 3;

/// Steps a sub-agent may take before its loop must stop and summarize.
const CHILD_MAX_STEPS: u64 = 80;

/// Tokens a sub-agent may spend (further clamped to what the parent has left
/// and to the role's share of it).
const CHILD_MAX_TOKENS: u64 = 800_000;

/// Wall-clock seconds a sub-agent may run (never later than the parent deadline).
const CHILD_MAX_WALL_SECS: u64 = 1_800;

/// The report/board reason used when a ticket changed files but no reviewer exists.
const NO_REVIEWER: &str = "no reviewer role is defined; changes were not merged";

#[cfg(test)]
mod tests;
