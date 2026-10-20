//! Context-window management: estimate tokens, prune stale tool results, and
//! choose a compaction range. Keeping the request's leading bytes stable
//! preserves the provider's prefix cache (and the local model's KV reuse), so
//! pruning rewrites only the *middle* and compaction replaces a *prefix* with
//! one summary message.
//! MARK: M18 — transcribed by dsh; see marks/M18-context.md.

use bulge_llm::{ContentBlock, Message, Role};

/// Rough token estimate: chars/4 plus a small per-block overhead (DSH token-meter).
pub fn estimate_tokens(messages: &[Message]) -> u64 {
    let _ = messages;
    todo!("M18")
}

/// Pruning configuration.
#[derive(Debug, Clone, Copy)]
pub struct PruneConfig {
    /// Prune only when estimated tokens exceed this fraction of the window.
    pub pressure_ratio: f64,
    /// Tool results longer than this many chars are trimmed.
    pub max_tool_result_chars: usize,
    /// Kept head chars when trimming.
    pub head_chars: usize,
    /// Kept tail chars when trimming.
    pub tail_chars: usize,
}

impl Default for PruneConfig {
    fn default() -> Self {
        Self { pressure_ratio: 0.3, max_tool_result_chars: 8192, head_chars: 4096, tail_chars: 1024 }
    }
}

/// Return a pruned copy of `messages` when over pressure, else the input as-is.
/// Never touches the last `keep_recent` messages, never the leading system
/// message, and never a tool-call/tool-result pairing. A trimmed result keeps
/// head + a marker (with the omitted char count) + tail.
pub fn prune(messages: &[Message], window: u64, keep_recent: usize, config: &PruneConfig) -> Vec<Message> {
    let _ = (messages, window, keep_recent, config);
    todo!("M18")
}

/// Index range `[start, end)` into `messages` to compact into one summary, and
/// the index from which to keep messages verbatim. Returns `None` when
/// compaction is not warranted. Never splits a call/result pair; keeps a tail of
/// at least `retain_ratio` of the budget; starts after the leading system message.
pub fn compaction_range(messages: &[Message], window: u64, reserve: u64, retain_ratio: f64) -> Option<CompactionRange> {
    let _ = (messages, window, reserve, retain_ratio);
    todo!("M18")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionRange {
    /// First message index to summarize (after any system message).
    pub start: usize,
    /// One past the last message to summarize; also the first kept index.
    pub kept_from: usize,
}

/// The fixed summary template (DSH compaction-basic): the sections the summary
/// must fill. Used as the final user instruction of the summary request.
pub const SUMMARY_TEMPLATE: &str = "\
Summarize the conversation so far into a compact briefing that lets you continue \
without the earlier messages. Use these sections exactly:\n\
## Primary Request\n## Key Concepts\n## Files and Code\n## Errors and Fixes\n\
## Pending Jobs\n## Current Work\n## Next Step\n## Critical Context\n\
Be specific: keep identifiers, paths, and decisions; drop chatter.";

/// Build the message that carries a compaction summary back into context.
pub fn summary_message(summary: &str) -> Message {
    Message {
        role: Role::User,
        content: vec![ContentBlock::Text { text: format!("<compacted-summary>\n{summary}\n</compacted-summary>") }],
        tool_call_id: None,
        is_error: None,
        source_model: None,
    }
}
