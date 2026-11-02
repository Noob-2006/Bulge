//! Context engines (OpenClaw `ContextEngine`, MIT): something outside the kernel that
//! keeps its own view of a conversation and decides what the model sees. The kernel
//! still owns the event log; an engine only shapes requests and, if it says so, writes
//! the compaction summaries. Selected with `context_engine = "<plugin>"`.

use ark_core::Message;

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
}

/// An assembled history must still be a valid conversation: non-empty, starting and
/// ending with the user (tool results ride in user messages).
pub fn valid(messages: &[Message]) -> bool {
    use ark_core::Role;
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
}
