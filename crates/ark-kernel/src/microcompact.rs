//! Hermes micro-compaction state: after each turn the oldest un-absorbed exchange is
//! folded into a rolling summary; once that summary grows past
//! `micro_compact_defrag_threshold_tokens` it is re-summarised. This module holds the
//! per-session bookkeeping and the pure decisions; the kernel does the model calls.

use ark_core::estimate_tokens;

/// Per-session micro-compaction state (kept in `CtxState::micro`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MicroState {
    /// The rolling summary of absorbed exchanges.
    pub summary: String,
    /// Number of leading messages already folded into `summary`.
    pub absorbed: usize,
    /// Turns since the last micro pass.
    pub turns_since: u32,
    /// Completed passes (folds + defrags).
    pub passes: u32,
}

impl MicroState {
    /// Count a finished turn; true when a pass is due (`every_n` of 0 is treated as 1).
    pub fn tick(&mut self, every_n: u32) -> bool {
        self.turns_since += 1;
        if self.turns_since >= every_n.max(1) {
            self.turns_since = 0;
            true
        } else {
            false
        }
    }

    /// Fold an exchange summary covering `messages` more messages into the rolling summary.
    pub fn absorb(&mut self, exchange_summary: &str, messages: usize) {
        let s = exchange_summary.trim();
        if !s.is_empty() {
            if !self.summary.is_empty() {
                self.summary.push('\n');
            }
            self.summary.push_str(s);
        }
        self.absorbed += messages;
        self.passes += 1;
    }

    /// The rolling summary has grown past `threshold` tokens and should be re-summarised.
    pub fn needs_defrag(&self, threshold: u64) -> bool {
        threshold > 0 && !self.summary.is_empty() && estimate_tokens(&self.summary) >= threshold
    }

    /// Replace the rolling summary with its re-summarised form.
    pub fn defrag(&mut self, condensed: &str) {
        self.summary = condensed.trim().to_string();
        self.passes += 1;
    }

    /// Compaction or a rewind changed the history: start over.
    pub fn reset(&mut self) {
        *self = MicroState::default();
    }
}

/// The next exchange to absorb: from `absorbed` up to (not including) the next user
/// message after it, never touching the last `keep` messages. Takes per-message
/// "is a user prompt" flags; returns the half-open range.
pub fn next_exchange(is_user_prompt: &[bool], absorbed: usize, keep: usize) -> Option<(usize, usize)> {
    let limit = is_user_prompt.len().saturating_sub(keep);
    if absorbed >= limit {
        return None;
    }
    let end = (absorbed + 1..limit).find(|&i| is_user_prompt[i])?;
    Some((absorbed, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_respects_every_n() {
        let mut s = MicroState::default();
        assert!(s.tick(0));
        assert!(!s.tick(2));
        assert!(s.tick(2));
        assert_eq!(s.turns_since, 0);
    }

    #[test]
    fn absorb_defrag_reset() {
        let mut s = MicroState::default();
        s.absorb("user asked X; did Y", 2);
        s.absorb("  ", 1);
        s.absorb("then Z", 2);
        assert_eq!(s.summary, "user asked X; did Y\nthen Z");
        assert_eq!((s.absorbed, s.passes), (5, 3));
        assert!(s.needs_defrag(1));
        assert!(!s.needs_defrag(0));
        assert!(!s.needs_defrag(10_000));
        s.defrag(" short ");
        assert_eq!(s.summary, "short");
        s.reset();
        assert_eq!(s, MicroState::default());
    }

    #[test]
    fn next_exchange_stops_before_kept_tail() {
        // u a u a u a
        let f = [true, false, true, false, true, false];
        assert_eq!(next_exchange(&f, 0, 2), Some((0, 2)));
        assert_eq!(next_exchange(&f, 2, 2), None); // next prompt (4) is inside the kept tail
        assert_eq!(next_exchange(&f, 2, 0), Some((2, 4)));
        assert_eq!(next_exchange(&f, 6, 0), None);
    }
}
