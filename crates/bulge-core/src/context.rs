//! Context-window management: estimate tokens, prune stale tool results, and
//! choose a compaction range. Keeping the request's leading bytes stable
//! preserves the provider's prefix cache (and the local model's KV reuse), so
//! pruning rewrites only the *middle* and compaction replaces a *prefix* with
//! one summary message.
//! MARK: M18 — transcribed by dsh; see marks/M18-context.md.

use bulge_llm::{ContentBlock, Message, Role};

/// Fixed text density used until exact tokenization is needed.
const CHARS_PER_TOKEN: u64 = 4;

/// Per-block framing overhead (type tags and JSON structure).
const BLOCK_OVERHEAD: u64 = 4;

/// Role-field framing overhead added to every message.
const ROLE_OVERHEAD: u64 = 4;

/// Content characters that contribute to the heuristic price of one block.
///
/// Provider replay metadata (`ToolCall::id`, `Reasoning::signature`) is omitted:
/// it is not model-visible content. Image payloads are included because they are
/// genuinely sent to the provider.
fn block_chars(block: &ContentBlock) -> u64 {
    match block {
        ContentBlock::Text { text } => char_count(text),
        ContentBlock::Reasoning { text, .. } => char_count(text),
        ContentBlock::ToolCall {
            name, arguments, ..
        } => char_count(name) + char_count(arguments),
        ContentBlock::Image { media_type, data } => char_count(media_type) + char_count(data),
        ContentBlock::ToolAddition { name } | ContentBlock::ToolRemoval { name } => {
            char_count(name)
        }
    }
}

fn char_count(text: &str) -> u64 {
    text.chars().count() as u64
}

/// Heuristic price of one message: content chars / 4, plus one block overhead
/// per block and one role overhead (DSH token-meter).
fn message_tokens(message: &Message) -> u64 {
    let chars: u64 = message.content.iter().map(block_chars).sum();
    let blocks = message.content.len() as u64;
    chars.div_ceil(CHARS_PER_TOKEN) + blocks * BLOCK_OVERHEAD + ROLE_OVERHEAD
}

/// Rough token estimate: chars/4 plus a small per-block overhead (DSH token-meter).
pub fn estimate_tokens(messages: &[Message]) -> u64 {
    messages.iter().map(message_tokens).sum()
}

/// The fixed tail of the marker a trimmed tool result carries
/// (`[... N chars pruned ...]`); recognised by cache-break diagnosis.
pub const PRUNE_MARKER_TAIL: &str = " chars pruned ...]";

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
    /// The prune boundary (end of the trimmable span) only advances in multiples
    /// of this many messages. A boundary that slid by one message every turn would
    /// rewrite a message just behind the cached prefix on every request; stepping
    /// it breaks the prefix once per `boundary_step` turns instead. `1` = slide.
    pub boundary_step: usize,
}

impl Default for PruneConfig {
    fn default() -> Self {
        Self {
            pressure_ratio: 0.3,
            max_tool_result_chars: 8192,
            head_chars: 4096,
            tail_chars: 1024,
            boundary_step: 8,
        }
    }
}

/// Return a pruned copy of `messages` when over pressure, else the input as-is.
/// Never touches the last `keep_recent` messages, never the leading system
/// message, and never a tool-call/tool-result pairing. A trimmed result keeps
/// head + a marker (with the omitted char count) + tail. The trimmable span ends
/// at a multiple of `boundary_step`, so successive requests share their prefix.
pub fn prune(
    messages: &[Message],
    window: u64,
    keep_recent: usize,
    config: &PruneConfig,
) -> Vec<Message> {
    let estimated = estimate_tokens(messages) as f64;
    if estimated <= window as f64 * config.pressure_ratio {
        return messages.to_vec();
    }

    let mut pruned = messages.to_vec();
    // A leading system message is the stable prefix cache: always leave it alone.
    let start = usize::from(
        messages
            .first()
            .is_some_and(|message| message.role == Role::System),
    );
    let step = config.boundary_step.max(1);
    let end = messages.len().saturating_sub(keep_recent) / step * step;
    if start >= end {
        return pruned;
    }

    for message in &mut pruned[start..end] {
        if message.role != Role::Tool {
            continue;
        }
        for block in &mut message.content {
            let ContentBlock::Text { text } = block else {
                continue;
            };
            if let Some(trimmed) = trim_tool_text(text, config) {
                *text = trimmed;
            }
        }
    }
    pruned
}

/// Trim one over-budget tool-result text on Unicode char boundaries.
///
/// Returns `None` when the text is within budget or the configured head+tail
/// budgets leave nothing to omit.
fn trim_tool_text(text: &str, config: &PruneConfig) -> Option<String> {
    let total = text.chars().count();
    if total <= config.max_tool_result_chars {
        return None;
    }
    let head = config.head_chars.min(total);
    let tail = config.tail_chars.min(total - head);
    let omitted = total - head - tail;
    if omitted == 0 {
        return None;
    }
    let head_text: String = text.chars().take(head).collect();
    let tail_text: String = text.chars().skip(total - tail).collect();
    Some(format!(
        "{head_text}\n[... {omitted}{PRUNE_MARKER_TAIL}\n{tail_text}"
    ))
}

/// Index range `[start, end)` into `messages` to compact into one summary, and
/// the index from which to keep messages verbatim. Returns `None` when
/// compaction is not warranted. Never splits a call/result pair; keeps a tail of
/// at least `retain_ratio` of the budget; starts after the leading system message.
pub fn compaction_range(
    messages: &[Message],
    window: u64,
    reserve: u64,
    retain_ratio: f64,
) -> Option<CompactionRange> {
    let tokens: Vec<u64> = messages.iter().map(message_tokens).collect();
    let total = tokens.iter().copied().sum::<u64>();
    if total.saturating_add(reserve) <= window {
        return None;
    }

    // The first non-system message; a leading system prompt is never summarized.
    let start = messages
        .iter()
        .position(|message| message.role != Role::System)?;

    // Walk back from the tail until the retained budget reaches the ratio.
    let retain_tokens = window as f64 * retain_ratio;
    let mut accumulated = 0_u64;
    let mut kept_from = 0_usize;
    for index in (0..messages.len()).rev() {
        accumulated = accumulated.saturating_add(tokens[index]);
        kept_from = index;
        if accumulated as f64 >= retain_tokens {
            break;
        }
    }

    // A kept tool result needs the assistant tool-call that produced it kept too.
    while let Some(call_index) = first_split_call(messages, kept_from) {
        kept_from = call_index;
    }

    if kept_from <= start {
        return None;
    }
    Some(CompactionRange { start, kept_from })
}

/// Find the paired assistant tool-call index for any kept tool result, when that
/// assistant message would otherwise be summarized.
fn first_split_call(messages: &[Message], kept_from: usize) -> Option<usize> {
    for (index, message) in messages.iter().enumerate().skip(kept_from) {
        if message.role != Role::Tool {
            continue;
        }
        let Some(call_id) = message.tool_call_id.as_deref() else {
            continue;
        };
        if let Some(call_index) = assistant_call_index(messages, index, call_id)
            && call_index < kept_from
        {
            return Some(call_index);
        }
    }
    None
}

/// Index of the latest assistant message before `before` that carries `call_id`.
fn assistant_call_index(messages: &[Message], before: usize, call_id: &str) -> Option<usize> {
    (0..before).rev().find(|&index| {
        messages[index].role == Role::Assistant
            && messages[index]
                .content
                .iter()
                .any(|block| matches!(block, ContentBlock::ToolCall { id, .. } if id == call_id))
    })
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
        content: vec![ContentBlock::Text {
            text: format!("<compacted-summary>\n{summary}\n</compacted-summary>"),
        }],
        tool_call_id: None,
        is_error: None,
        source_model: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_blocks(role: Role, content: Vec<ContentBlock>) -> Message {
        Message {
            role,
            content,
            tool_call_id: None,
            is_error: None,
            source_model: None,
        }
    }

    fn tool_call_block(call_id: &str) -> ContentBlock {
        ContentBlock::ToolCall {
            id: call_id.to_owned(),
            name: "read".to_owned(),
            arguments: "{\"path\":\"x\"}".to_owned(),
        }
    }

    fn text_of(block: &ContentBlock) -> &str {
        match block {
            ContentBlock::Text { text } => text,
            other => panic!("expected a text block, got {other:?}"),
        }
    }

    fn prune_config() -> PruneConfig {
        PruneConfig {
            pressure_ratio: 0.3,
            max_tool_result_chars: 100,
            head_chars: 20,
            tail_chars: 10,
            boundary_step: 1,
        }
    }

    #[test]
    fn estimate_prices_known_content_and_grows_monotonically() {
        // 4 chars => 1 token, one block => 4, role => 4.
        let short = [Message::text(Role::User, "abcd")];
        assert_eq!(estimate_tokens(&short), 9);

        let long = [Message::text(Role::User, "abcdefgh")];
        assert_eq!(estimate_tokens(&long), 10);
        assert!(estimate_tokens(&long) > estimate_tokens(&short));

        // 8 chars => 2 tokens, two blocks => 8, role => 4.
        let two_blocks = [with_blocks(
            Role::User,
            vec![
                ContentBlock::Text {
                    text: "abcd".to_owned(),
                },
                ContentBlock::Text {
                    text: "efgh".to_owned(),
                },
            ],
        )];
        assert_eq!(estimate_tokens(&two_blocks), 14);

        // Tool-call content is name + arguments: 4 + 12 = 16 chars => 4 tokens.
        let call = [with_blocks(
            Role::Assistant,
            vec![tool_call_block("call-1")],
        )];
        assert_eq!(estimate_tokens(&call), 12);

        // Reasoning text is priced like text.
        let reasoning = [with_blocks(
            Role::Assistant,
            vec![ContentBlock::Reasoning {
                text: "abcdef".to_owned(),
                signature: None,
            }],
        )];
        assert_eq!(estimate_tokens(&reasoning), 10);

        // Empty messages still carry role framing.
        let empty = [with_blocks(Role::User, Vec::new())];
        assert_eq!(estimate_tokens(&empty), 4);
    }

    #[test]
    fn prune_below_pressure_returns_input_unchanged() {
        let messages = vec![
            Message::text(Role::System, "system prompt"),
            Message::tool_result("call-1", "x".repeat(400), false),
        ];
        let pruned = prune(&messages, 1_000_000, 0, &prune_config());
        assert_eq!(pruned, messages);
    }

    #[test]
    fn prune_trims_only_old_long_tool_results() {
        let long_tool = "a".repeat(400);
        let long_user = "u".repeat(400);
        let messages = vec![
            Message::text(Role::System, "system prompt"),
            Message::text(Role::Assistant, "older"),
            Message::tool_result("call-1", long_tool.clone(), false),
            Message::text(Role::User, long_user.clone()),
            Message::text(Role::Assistant, "done"),
            Message::tool_result("call-2", long_tool.clone(), false),
        ];

        let pruned = prune(&messages, 100, 2, &prune_config());

        assert_eq!(pruned.len(), messages.len());
        assert_eq!(pruned[0], messages[0], "system message must not change");
        assert_eq!(pruned[1], messages[1], "assistant message must not change");
        assert_eq!(pruned[3], messages[3], "user message must not change");
        assert_eq!(pruned[4], messages[4], "recent tail must not change");
        assert_eq!(pruned[5], messages[5], "recent tail must not change");
        assert_eq!(pruned[2].role, Role::Tool);
        assert_eq!(pruned[2].tool_call_id.as_deref(), Some("call-1"));

        let trimmed = text_of(&pruned[2].content[0]);
        assert!(trimmed.chars().count() < long_tool.chars().count());
        assert!(trimmed.starts_with(&"a".repeat(20)));
        assert!(trimmed.ends_with(&"a".repeat(10)));
        assert!(trimmed.contains("[... 370 chars pruned ...]"));
        assert!(estimate_tokens(&pruned) < estimate_tokens(&messages));
    }

    #[test]
    fn prune_marker_counts_multibyte_chars_and_keeps_boundaries() {
        let text = format!("{}{}", "漢".repeat(60), "🙂".repeat(40));
        assert_eq!(text.chars().count(), 100);
        let messages = vec![
            Message::text(Role::System, "sys"),
            Message::tool_result("call-1", text, false),
            Message::text(Role::User, "recent"),
        ];
        let config = PruneConfig {
            pressure_ratio: 0.3,
            max_tool_result_chars: 10,
            head_chars: 5,
            tail_chars: 3,
            boundary_step: 1,
        };

        let pruned = prune(&messages, 100, 1, &config);
        let trimmed = text_of(&pruned[1].content[0]);

        // 100 chars total minus 5 head and 3 tail leaves 92 omitted.
        assert!(trimmed.contains("[... 92 chars pruned ...]"));
        assert!(trimmed.starts_with("漢漢漢漢漢"));
        assert!(trimmed.ends_with("🙂🙂🙂"));
        assert_eq!(
            trimmed.chars().count(),
            5 + "\n[... 92 chars pruned ...]\n".chars().count() + 3
        );
        assert!(pruned[2] == messages[2]);
    }

    #[test]
    fn stepped_boundary_keeps_successive_requests_prefix_stable() {
        // Growing history: each turn appends a long tool result. With a sliding
        // boundary every turn trims one more message; with a stepped boundary the
        // previous request stays a byte-exact prefix of the next one except at
        // step crossings.
        let config = PruneConfig { boundary_step: 4, ..prune_config() };
        let mut messages = vec![Message::text(Role::System, "sys")];
        let mut previous: Vec<Message> = Vec::new();
        let mut breaks = 0;
        for turn in 0..16 {
            messages.push(Message::tool_result(format!("call-{turn}"), "a".repeat(400), false));
            let pruned = prune(&messages, 100, 2, &config);
            let end = (messages.len() - 2) / 4 * 4;
            for (index, message) in pruned.iter().enumerate() {
                let trimmed = text_of(&message.content[0]).contains("chars pruned");
                assert_eq!(trimmed, index >= 1 && index < end, "turn {turn} index {index}");
            }
            if !previous.is_empty() && pruned[..previous.len()] != previous[..] {
                breaks += 1;
            }
            previous = pruned;
        }
        // 16 turns, boundary at len 6, 10, 14 (end = 4, 8, 12): three breaks, where a
        // sliding boundary would break on every turn past the first.
        assert_eq!(breaks, 3, "prefix should break only when the boundary steps");
    }

    #[test]
    fn compaction_is_not_needed_under_pressure() {
        let messages = vec![
            Message::text(Role::System, "sys"),
            Message::text(Role::User, "hello"),
        ];
        assert_eq!(compaction_range(&messages, 10_000, 100, 0.5), None);
    }

    #[test]
    fn compaction_starts_after_system_and_keeps_the_tool_pair_and_tail() {
        let messages = vec![
            Message::text(Role::System, "sys"),
            Message::text(Role::User, "old question"),
            with_blocks(Role::Assistant, vec![tool_call_block("call-1")]),
            Message::tool_result("call-1", "r".repeat(400), false),
            Message::text(Role::Assistant, "ok"),
            Message::text(Role::User, "y".repeat(128)),
        ];

        let range = compaction_range(&messages, 200, 20, 0.5).expect("compaction is warranted");

        assert_eq!(
            range.start, 1,
            "the leading system message is never summarized"
        );
        assert!(
            messages[..range.start]
                .iter()
                .all(|message| message.role == Role::System)
        );

        // The tail budget alone lands on the tool result; the paired assistant
        // tool call must be pulled into the kept side as well.
        assert_eq!(range.kept_from, 2);
        assert_eq!(messages[range.kept_from].role, Role::Assistant);
        assert!(matches!(
            &messages[range.kept_from].content[0],
            ContentBlock::ToolCall { id, .. } if id == "call-1"
        ));
        assert_eq!(messages[3].role, Role::Tool);
        assert_eq!(messages[3].tool_call_id.as_deref(), Some("call-1"));

        // At least retain_ratio (0.5 * 200 = 100) of the window is kept verbatim.
        assert!(estimate_tokens(&messages[range.kept_from..]) >= 100);
    }

    #[test]
    fn compaction_declines_when_keeping_the_pair_reaches_the_start() {
        let messages = vec![
            Message::text(Role::System, "sys"),
            with_blocks(Role::Assistant, vec![tool_call_block("call-1")]),
            Message::tool_result("call-1", "r".repeat(400), false),
        ];
        // The only kept tool result pulls its assistant call back to the first
        // non-system index, so there is nothing left to summarize.
        assert_eq!(compaction_range(&messages, 100, 10, 1.0), None);
    }
}
