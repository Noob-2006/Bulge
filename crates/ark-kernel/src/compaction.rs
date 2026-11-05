//! Two-stage context compaction: prune old tool outputs first (cheap, no model
//! call), then summarise older history with the aux model. The summary passes a
//! quality check or falls back to a deterministic digest — compaction never fails.

use crate::projection::{View, PRUNED_STUB};
use ark_core::{Block, Cancel, Message, ModelRequest, Provider, Role, SystemSegment};

pub const HEADINGS: &[&str] = &["## Goal", "## Progress", "## Key facts", "## Files", "## Next steps"];
const PRUNE_MIN_BYTES: usize = 400;

/// Tool results eligible for pruning: all but the newest `keep`, bigger than a stub.
pub fn prune_candidates(view: &View, keep: usize) -> Vec<String> {
    let mut results: Vec<(&str, usize)> = Vec::new();
    for m in &view.messages {
        for b in &m.content {
            if let Block::ToolResult { tool_use_id, content, .. } = b {
                if !content.starts_with(PRUNED_STUB) {
                    results.push((tool_use_id, content.len()));
                }
            }
        }
    }
    let n = results.len().saturating_sub(keep);
    results[..n].iter().filter(|(_, len)| *len >= PRUNE_MIN_BYTES).map(|(id, _)| id.to_string()).collect()
}

/// Index of the first message kept verbatim. The kept tail must not begin with
/// a tool result (its tool_use would be summarised away).
pub fn cut_index(messages: &[Message], keep: usize) -> Option<usize> {
    if messages.len() < 3 {
        return None;
    }
    let start = messages.len().saturating_sub(keep).max(1);
    (1..=start).rev().find(|&i| {
        let m = &messages[i];
        m.role == Role::Assistant || !m.content.iter().any(|b| matches!(b, Block::ToolResult { .. }))
    })
}

/// Boundary for a partial ("up to here") compaction: the index of the first message kept
/// verbatim, i.e. the start of the `keep_last`-th user turn counted from the end. The tail
/// therefore always begins on a user turn, so the summary plus the kept conversation keeps the
/// user↔assistant alternation providers validate.
///
/// `None` when the split would keep everything (no user turn, or only one exchange in the
/// history): callers fall back to a full compaction instead of rotating the session for a no-op.
/// Port of Hermes `split_history_for_partial_compress`.
pub fn partial_cut_index(messages: &[Message], keep_last: usize) -> Option<usize> {
    let keep_last = keep_last.max(1);
    let mut boundary = None;
    let mut seen = 0;
    for idx in (0..messages.len()).rev() {
        if crate::projection::is_user_turn(&messages[idx]) {
            boundary = Some(idx);
            seen += 1;
            if seen >= keep_last {
                break;
            }
        }
    }
    match boundary {
        // `0` keeps everything: nothing older than the first ask would be summarised.
        Some(0) | None => None,
        Some(i) => Some(i),
    }
}

pub fn render_transcript(messages: &[Message], per_block: usize) -> String {
    let mut out = String::new();
    for m in messages {
        let who = if m.role == Role::User { "USER" } else { "ASSISTANT" };
        for b in &m.content {
            let line = match b {
                Block::Text { text } => format!("{who}: {text}"),
                Block::Image { media_type, .. } => format!("{who}: [image {media_type}]"),
                Block::Thinking { .. } => continue,
                Block::ToolUse { name, input, .. } => format!("{who} called {name}({})", crate::util::head_tail(&input.to_string(), per_block).0),
                Block::ToolResult { content, is_error, .. } => format!("TOOL{}: {}", if *is_error { " ERROR" } else { "" }, crate::util::head_tail(content, per_block).0),
            };
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

pub fn summary_prompt(transcript: &str) -> String {
    format!(
        "Summarise the conversation below so an agent can continue the work with no other context. \
Use exactly these markdown headings: {}. Keep concrete details: file paths, commands, \
decisions, error messages, numbers, and what the user asked for in their own words. \
Do not invent anything.\n\n<conversation>\n{transcript}\n</conversation>",
        HEADINGS.join(", ")
    )
}

/// Quality gate for a model-written summary.
pub fn summary_ok(summary: &str, source_len: usize) -> bool {
    let found = HEADINGS.iter().filter(|h| summary.contains(**h)).count();
    let len = summary.trim().len();
    found >= 3 && len >= 80 && (len < source_len || source_len < 500)
}

/// Deterministic fallback: every user request plus the latest assistant text.
pub fn fallback_summary(messages: &[Message]) -> String {
    let mut s = String::from("## Goal\n");
    for m in messages.iter().filter(|m| m.role == Role::User) {
        let t = m.text();
        if !t.trim().is_empty() {
            s.push_str(&format!("- {}\n", crate::util::head_tail(&t, 600).0));
        }
    }
    s.push_str("\n## Progress\n(automatic digest — the model summary was unavailable)\n");
    if let Some(a) = messages.iter().rev().find(|m| m.role == Role::Assistant && !m.text().trim().is_empty()) {
        s.push_str(&crate::util::head_tail(&a.text(), 2000).0);
    }
    let files: std::collections::BTreeSet<String> = messages
        .iter()
        .flat_map(|m| m.tool_uses().filter_map(|(_, _, i)| i.get("path").and_then(|p| p.as_str()).map(String::from)).collect::<Vec<_>>())
        .collect();
    s.push_str("\n\n## Files\n");
    for f in files {
        s.push_str(&format!("- {f}\n"));
    }
    s
}

/// Ask the aux model for a summary; one retry; deterministic fallback.
/// Returns (summary, used_fallback).
pub fn summarise(provider: &dyn Provider, model: &str, messages: &[Message], cancel: &Cancel) -> (String, bool) {
    let transcript = render_transcript(messages, 2000);
    let req = ModelRequest {
        model: model.to_string(),
        system: vec![SystemSegment { id: "summariser".into(), text: "You write faithful, dense handoff summaries.".into(), cache: false }],
        messages: vec![Message::user(summary_prompt(&transcript))],
        tools: vec![],
        max_tokens: 4096,
        temperature: None,
        cache_after_message: None,
        reasoning: None,
        options: Default::default(),
    };
    for _ in 0..2 {
        if cancel.is_cancelled() {
            break;
        }
        if let Ok(r) = provider.complete(&req, &mut |_| {}, cancel) {
            let text = r.message.text();
            if summary_ok(&text, transcript.len()) {
                return (text, false);
            }
        }
    }
    (fallback_summary(messages), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::{ModelCaps, ModelResponse, ProviderError, ProviderErrorKind, StopReason, StreamEvent, Usage};
    use serde_json::json;
    use std::sync::Mutex;

    fn tr(id: &str, n: usize) -> Message {
        Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: id.into(), content: "x".repeat(n), is_error: false }] }
    }
    fn tu(id: &str) -> Message {
        Message { role: Role::Assistant, content: vec![Block::ToolUse { id: id.into(), name: "read".into(), input: json!({"path":"src/a.rs"}) }] }
    }

    #[test]
    fn prune_keeps_recent_and_small() {
        let view = View { messages: vec![Message::user("go"), tu("1"), tr("1", 1000), tu("2"), tr("2", 10), tu("3"), tr("3", 1000), tu("4"), tr("4", 1000)], ..Default::default() };
        assert_eq!(prune_candidates(&view, 2), vec!["1"]);
        assert!(prune_candidates(&view, 10).is_empty());
    }

    #[test]
    fn cut_never_orphans_a_tool_result() {
        let msgs = vec![Message::user("go"), tu("1"), tr("1", 5), tu("2"), tr("2", 5), Message::assistant("done")];
        let i = cut_index(&msgs, 2).unwrap();
        assert!(!matches!(msgs[i].content[0], Block::ToolResult { .. }));
        assert_eq!(i, 3, "lands on the assistant tool_use, not its result");
        assert_eq!(cut_index(&msgs[..2], 1), None, "too short to compact");
        // Keep larger than history → still leaves at least the first message summarised.
        assert_eq!(cut_index(&msgs, 100), Some(1));
    }

    struct Fake(Mutex<Vec<Result<String, ()>>>);
    impl Provider for Fake {
        fn id(&self) -> &str {
            "fake"
        }
        fn caps(&self, _: &str) -> ModelCaps {
            ModelCaps::default()
        }
        fn complete(&self, _: &ModelRequest, _: &mut dyn FnMut(StreamEvent), _: &Cancel) -> Result<ModelResponse, ProviderError> {
            match self.0.lock().unwrap().remove(0) {
                Ok(t) => Ok(ModelResponse { message: Message::assistant(t), stop: StopReason::EndTurn, usage: Usage::default(), model: "f".into() }),
                Err(()) => Err(ProviderError::new(ProviderErrorKind::Server, "boom")),
            }
        }
    }

    fn good() -> String {
        format!("{}\nfix bug\n{}\nedited a.rs, tests pass now\n{}\nuses cargo\n{}\nsrc/a.rs\n{}\nnone", HEADINGS[0], HEADINGS[1], HEADINGS[2], HEADINGS[3], HEADINGS[4])
    }
    fn long_history() -> Vec<Message> {
        vec![Message::user("please fix the parser bug in src/a.rs ".repeat(40)), tu("1"), tr("1", 3000), Message::assistant("fixed it")]
    }

    #[test]
    fn partial_cut_lands_on_a_user_turn_or_falls_back() {
        let ask = |t: &str| Message::user(t);
        let msgs = vec![ask("one"), Message::assistant("a1"), ask("two"), tu("1"), tr("1", 5), Message::assistant("a2"), ask("three"), Message::assistant("a3")];
        // Keep the last exchange: the boundary is the third ask.
        assert_eq!(partial_cut_index(&msgs, 1), Some(6));
        assert_eq!(partial_cut_index(&msgs, 2), Some(2), "tool results are not turn starts");
        // As many exchanges as the history has: everything would be kept.
        assert_eq!(partial_cut_index(&msgs, 3), None);
        assert_eq!(partial_cut_index(&msgs, 99), None);
        assert_eq!(partial_cut_index(&[ask("only"), Message::assistant("a")], 1), None);
        assert_eq!(partial_cut_index(&[Message::assistant("a"), Message::assistant("b")], 1), None, "no user turns");
        // Tool results are not turn starts: the tail still begins on an ask.
        let only_results = vec![ask("go"), Message::assistant("a"), tr("9", 5)];
        assert_eq!(partial_cut_index(&only_results, 1), None, "the single ask is the whole tail");
    }

    #[test]
    fn summarise_accepts_good_summary() {
        let p = Fake(Mutex::new(vec![Ok(good())]));
        let (s, fb) = summarise(&p, "m", &long_history(), &Cancel::new());
        assert!(!fb);
        assert!(s.contains("## Progress"));
    }

    #[test]
    fn summarise_retries_bad_then_falls_back() {
        let p = Fake(Mutex::new(vec![Ok("too short".into()), Err(())]));
        let (s, fb) = summarise(&p, "m", &long_history(), &Cancel::new());
        assert!(fb);
        assert!(s.contains("please fix the parser bug") && s.contains("src/a.rs") && s.contains("fixed it"));
        let p = Fake(Mutex::new(vec![Err(()), Ok(good())]));
        assert!(!summarise(&p, "m", &long_history(), &Cancel::new()).1, "second attempt succeeds");
    }

    #[test]
    fn cancelled_summary_falls_back_without_calling() {
        let c = Cancel::new();
        c.cancel();
        let p = Fake(Mutex::new(vec![]));
        assert!(summarise(&p, "m", &long_history(), &c).1);
    }
}
