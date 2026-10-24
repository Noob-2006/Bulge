//! Building model requests: the logged view, collapsed earlier reviews,
//! side requests sharing the cached prefix, and tool-less calls.

use std::sync::Mutex;
use bulge_llm::assemble::{Assembled, Assembler};
use bulge_llm::{ContentBlock, FinishReason, GenerateRequest, LlmBackend, Message, Purpose, Role, TokenUsage};
use crate::cache_watch::{CacheBreak, CacheWatch, Fingerprint};
use bulge_store::{JobEvent, JobHandle};
use futures::StreamExt;
use tokio_util::sync::CancellationToken;
use crate::complete;
use crate::context;
use super::{ContextConfig, HARNESS_NOTE_OPEN, RequestPrefix, assistant_text, harness_note};

/// The job event for a detected cache break.
pub fn cache_break_event(found: &CacheBreak) -> JobEvent {
    JobEvent::CacheBreak { expected: found.expected, cached: found.cached, cause: found.cause.tag().to_string(), detail: found.cause.describe() }
}

/// Record one call against `cache`; the event to log if it broke the prefix.
pub fn watch_call(cache: &Mutex<CacheWatch>, print: Fingerprint, usage: &TokenUsage) -> Option<JobEvent> {
    let found = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).record(print, usage)?;
    Some(cache_break_event(&found))
}

/// The messages a loop request carries: the system prompt, the latest compaction
/// summary (if any) in place of the messages it replaced, then the live history
/// tail — pruned so long old tool results are trimmed.
pub(crate) fn request_messages(system_prompt: &str, context: &ContextConfig, job: &JobHandle) -> Vec<Message> {
    context::pair_tool_results(logged_view(system_prompt, context, job))
}

/// The request view exactly as logged: one message per history message, so a
/// view index maps back to a history index (compaction relies on this).
/// [`request_messages`] then repairs call/result pairing for sending.
pub(crate) fn logged_view(system_prompt: &str, context: &ContextConfig, job: &JobHandle) -> Vec<Message> {
    let state = job.state();
    let mut messages = Vec::with_capacity(state.history.len() + 2);
    messages.push(Message::text(Role::System, system_prompt.to_string()));
    let base = match &state.compaction {
        Some(compaction) => {
            messages.push(context::summary_message(&compaction.summary));
            compaction.kept_from.min(state.history.len())
        }
        None => 0,
    };
    messages.extend(state.history[base..].iter().cloned());
    collapse_earlier_reviews(&mut messages);
    context::prune(&messages, context.window, context.keep_recent, &context.prune)
}

/// Self-reviews are harness bookkeeping for the turn they close. Left in
/// later turns' context they read as examples, and models start appending a
/// review checklist to their answers. Reviews before the newest user turn are
/// collapsed to one line each, and images from earlier turns become a line of
/// text (the message count stays, for compaction).
pub(crate) fn collapse_earlier_reviews(messages: &mut [Message]) {
    let is_review = |m: &Message| m.role == Role::User && m.joined_text().starts_with(&format!("{HARNESS_NOTE_OPEN}\n{}", complete::SELF_REVIEW_OPENING));
    let is_user_turn = |m: &Message| m.role == Role::User && !m.joined_text().starts_with(HARNESS_NOTE_OPEN) && m.content.iter().any(|b| matches!(b, ContentBlock::Text { .. }));
    let Some(newest_turn) = messages.iter().rposition(is_user_turn) else { return };
    // Images viewed in earlier turns are not re-sent with every request.
    for message in &mut messages[..newest_turn] {
        for block in &mut message.content {
            if matches!(block, ContentBlock::Image { .. }) {
                *block = ContentBlock::Text { text: "(an image viewed earlier; call view_image again to look at it)".into() };
            }
        }
    }
    for i in 0..newest_turn {
        if !is_review(&messages[i]) {
            continue;
        }
        messages[i] = harness_note("(The self-review of the answer above was done.)");
        if let Some(j) = (i + 1..newest_turn).find(|&j| messages[j].role == Role::Assistant) {
            messages[j] = Message::text(Role::Assistant, "(reviewed)");
        }
    }
}

/// A text-only side call over a job (e.g. post-job learning): exactly the loop's
/// request prefix — same system prompt, same tools, same pruned/compacted
/// history — plus `instruction` as the final user message, so only the
/// instruction and the reply are uncached. Send it with [`stream_toolless`].
pub fn side_request(prefix: &RequestPrefix, job: &JobHandle, instruction: &str, purpose: Purpose) -> GenerateRequest {
    let mut messages = request_messages(&prefix.system_prompt, &prefix.context, job);
    messages.push(Message::text(Role::User, instruction.to_string()));
    GenerateRequest {
        model: job.state().spec.model.model.clone(),
        messages,
        tools: prefix.tools.clone(),
        max_tokens: None,
        temperature: None,
        stop: Vec::new(),
        reasoning_effort: None,
        purpose,
    }
}

pub(crate) async fn collect(backend: &dyn LlmBackend, request: GenerateRequest, cancel: CancellationToken) -> Assembled {
    let model = request.model.clone();
    let mut stream = backend.stream(request, cancel);
    let mut assembler = Assembler::new();
    while let Some(chunk) = stream.next().await {
        assembler.push(&chunk);
    }
    assembler.finish(&model)
}

/// Send a request that must be answered in text, while keeping its tool list.
///
/// The tool definitions are part of the provider's cached prefix (DeepSeek
/// renders them right after the system prompt), and dropping them — or sending
/// `tool_choice: "none"`, which DeepSeek treats the same way (measured: 0 cache
/// hits) — invalidates everything after the system prompt. So the request goes
/// out byte-identical to a loop request, the instruction says not to call tools,
/// and any tool call the model makes anyway is stripped (it never ran, so it must
/// not reach the log unanswered). Only if nothing but tool calls came back is the
/// request retried without tools; the returned usage covers both attempts.
pub async fn stream_toolless(backend: &dyn LlmBackend, request: GenerateRequest, cancel: CancellationToken) -> Assembled {
    let retry = (!request.tools.is_empty()).then(|| GenerateRequest { tools: Vec::new(), ..request.clone() });
    let mut assembled = collect(backend, request, cancel.clone()).await;
    let before = assembled.message.content.len();
    assembled.message.content.retain(|block| !matches!(block, ContentBlock::ToolCall { .. }));
    if assembled.message.content.len() == before {
        return assembled;
    }
    if assembled.finish == FinishReason::ToolCalls {
        assembled.finish = FinishReason::Stop;
    }
    match retry {
        Some(retry) if assistant_text(&assembled.message).is_none() => {
            let first = assembled.usage;
            let mut second = collect(backend, retry, cancel).await;
            second.usage = first.plus(second.usage);
            second
        }
        _ => assembled,
    }
}

/// After this many failed summaries in a row the backoff stops growing: one
/// attempt every 2^N steps.
pub(crate) const COMPACT_BACKOFF_MAX_DOUBLINGS: u32 = 5;

/// Leads the compaction request's final user message (the summarizer now shares
/// the loop's system prompt, so its role is stated here instead).
pub(crate) const COMPACT_INSTRUCTION: &str = "Stop working on the task for a moment: you are compacting this long agent transcript into a briefing that lets the agent continue. Do not call tools.";
