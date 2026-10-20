//! Incremental SSE framing (WHATWG event-stream rules).
//! MARK: M4 — transcribed by dsh; see marks/M4-sse.md.

use crate::protocol::SseEvent;

/// Push-based parser: feed arbitrary byte chunks, get complete events.
/// An unterminated trailing event is never emitted.
#[derive(Debug, Default)]
pub struct SseParser {
    // M4: internal state
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed bytes. Returns complete events in order. Comment lines (`:`) are
    /// reported by incrementing the returned `comments` count (idle watchdog pulse).
    pub fn push(&mut self, bytes: &[u8]) -> SsePush {
        let _ = bytes;
        todo!("M4")
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SsePush {
    pub events: Vec<SseEvent>,
    pub comments: usize,
}
