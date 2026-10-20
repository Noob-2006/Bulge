//! Retry policy: exponential backoff with jitter, honouring provider retry-after.
//! MARK: M7 — transcribed by dsh; see marks/M7-retry.md.

use std::time::Duration;

use crate::error::LlmError;

#[derive(Debug, Clone, PartialEq)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    /// 0.0..=1.0
    pub jitter_ratio: f64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(30),
            jitter_ratio: 0.2,
        }
    }
}

impl RetryPolicy {
    /// Delay before retry number `retry` (1-based), or `None` if the error is
    /// not retryable or retries are exhausted. `random` is in [0, 1).
    pub fn delay_for(&self, retry: u32, error: &LlmError, random: f64) -> Option<Duration> {
        let _ = (retry, error, random);
        todo!("M7")
    }
}
