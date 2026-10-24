//! Rolling the context forward: summarize the oldest messages when the
//! window would overflow.

use bulge_llm::{FinishReason, GenerateRequest, Message, Purpose, Role, TokenUsage};
use crate::cache_watch;
use bulge_store::{JobEvent, JobHandle, StoreError};
use tokio_util::sync::CancellationToken;
use crate::context;
use super::{COMPACT_INSTRUCTION, Driver, assistant_text, logged_view, stream_toolless, watch_call};

impl Driver {
    /// When the live context would overflow the window, summarize its oldest span
    /// into one checkpoint and log a `Compacted` event. Returns the summary call's
    /// token usage (also logged as a `Usage` event) so the caller can charge the
    /// budget — also when the summary failed, since the call was still billed.
    /// Zero when no compaction was needed.
    /// Returns the call's usage and whether a summary was attempted
    /// (`None`: not needed) and produced (`Some(true)`).
    pub(super) async fn maybe_compact(&self, job: &mut JobHandle, cancel: &CancellationToken) -> Result<(TokenUsage, Option<bool>), StoreError> {
        let model = job.state().spec.model.model.clone();

        // The view the model currently sees: system, the existing summary (if
        // any), then the live tail. Compaction ranges are indices into this view,
        // which has one message per history message (pruning keeps the count).
        // For a well-formed log it is exactly the request the loop sends, so the
        // summary call reuses the provider's cached prefix.
        let view = logged_view(&self.system_prompt, &self.context, job);
        let (base, tail_start) = match &job.state().compaction {
            Some(compaction) => (compaction.kept_from.min(job.state().history.len()), 2),
            None => (0, 1),
        };

        let Some(range) = context::compaction_range(&view, self.context.window, self.context.reserve, self.context.retain_ratio) else {
            return Ok((TokenUsage::default(), None));
        };

        // `range.start` is the first message after the system prompt, so
        // system + this span is a byte-exact prefix of the last loop request.
        let to_summarize = context::pair_tool_results(view[range.start..range.kept_from].to_vec());
        let (summary, usage, broke) = self.summarize(to_summarize, &model, cancel.clone()).await;

        let mut events = Vec::with_capacity(3);
        let produced = summary.is_some();
        if let Some(summary) = summary {
            // Map the view index back to an absolute index into the stored history.
            let new_kept_from = base + range.kept_from.saturating_sub(tail_start);
            events.push(JobEvent::Compacted { kept_from: new_kept_from, summary });
        }
        events.push(JobEvent::Usage { model, usage });
        events.extend(broke);
        job.append(events)?;
        Ok((usage, Some(produced)))
    }

    /// Run one non-tool model call that condenses `slice` into a briefing using
    /// the fixed summary template. Returns the summary text (`None` if the model
    /// errored or produced no text) and the call's token usage either way.
    pub(super) async fn summarize(&self, slice: Vec<Message>, model: &str, cancel: CancellationToken) -> (Option<String>, TokenUsage, Option<JobEvent>) {
        let mut messages = Vec::with_capacity(slice.len() + 2);
        // Same system prompt and tools as the loop (calls forbidden) so the
        // provider's cached prefix covers the whole span being summarized.
        messages.push(Message::text(Role::System, self.system_prompt.clone()));
        messages.extend(slice);
        messages.push(Message::text(Role::User, format!("{COMPACT_INSTRUCTION}\n\n{}", context::SUMMARY_TEMPLATE)));
        let request = GenerateRequest {
            model: model.to_string(),
            messages,
            tools: self.tools.clone(),
            max_tokens: None,
            temperature: None,
            stop: Vec::new(),
            reasoning_effort: None,
            purpose: Purpose::Compaction,
        };
        let print = cache_watch::fingerprint(&request);
        let assembled = stream_toolless(self.backend.as_ref(), request, cancel).await;
        let broke = watch_call(&self.cache, print, &assembled.usage);
        let summary = if matches!(assembled.finish, FinishReason::Error(_) | FinishReason::Aborted) {
            None
        } else {
            assistant_text(&assembled.message).filter(|summary| !summary.trim().is_empty())
        };
        (summary, assembled.usage, broke)
    }
}
