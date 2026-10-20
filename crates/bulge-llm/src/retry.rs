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
        if !error.code.retryable() || retry == 0 || retry > self.max_retries {
            return None;
        }

        // Provider retry-after wins verbatim when it fits within the cap; an
        // over-cap instruction is delegated upwards instead of waiting too long.
        if let Some(ms) = error.retry_after_ms.filter(|ms| *ms > 0) {
            if ms as f64 > self.max_delay.as_secs_f64() * 1000.0 {
                return None;
            }
            return Some(Duration::from_millis(ms));
        }

        Some(self.local_delay(retry, random))
    }

    fn local_delay(&self, retry: u32, random: f64) -> Duration {
        let initial_ms = self.initial_delay.as_secs_f64() * 1000.0;
        let max_ms = self.max_delay.as_secs_f64() * 1000.0;

        // Cap the exponent so `2^exponent` cannot grow without bound; a huge
        // value simply saturates at `max_delay`.
        let exponent = (retry - 1).min(1024);
        let exponential = if initial_ms > 0.0 {
            (initial_ms * 2f64.powi(exponent as i32)).min(max_ms)
        } else {
            0.0
        };

        let jitter = sanitize_unit(self.jitter_ratio);
        let random = sanitize_unit(random);
        let factor = 1.0 - jitter + 2.0 * jitter * random;

        let delay_ms = (exponential * factor).clamp(0.0, max_ms);
        Duration::from_secs_f64(delay_ms / 1000.0)
    }
}

/// Treat a non-finite or out-of-range sample as the low bound rather than
/// allowing a NaN to reach `Duration::from_secs_f64`, which would panic.
fn sanitize_unit(value: f64) -> f64 {
    if value.is_finite() {
        value.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    fn error(code: ErrorCode) -> LlmError {
        LlmError::new(code, "boom")
    }

    fn error_with_retry_after(code: ErrorCode, ms: u64) -> LlmError {
        let mut error = error(code);
        error.retry_after_ms = Some(ms);
        error
    }

    fn policy() -> RetryPolicy {
        RetryPolicy {
            max_retries: 5,
            initial_delay: Duration::from_millis(1000),
            max_delay: Duration::from_secs(30),
            jitter_ratio: 0.2,
        }
    }

    #[test]
    fn non_retryable_codes_have_no_delay() {
        for code in [
            ErrorCode::Auth,
            ErrorCode::Quota,
            ErrorCode::ContextWindowExceeded,
            ErrorCode::InvalidRequest,
            ErrorCode::Http(418),
            ErrorCode::MalformedResponse,
            ErrorCode::EmptyResponse,
            ErrorCode::UnsupportedContent,
            ErrorCode::UnsupportedReasoningEffort,
            ErrorCode::Aborted,
        ] {
            assert_eq!(policy().delay_for(1, &error(code), 0.5), None, "{code:?}");
        }
    }

    #[test]
    fn zero_or_exhausted_retry_has_no_delay() {
        let error = error(ErrorCode::Server);
        assert_eq!(policy().delay_for(0, &error, 0.5), None);
        assert_eq!(policy().delay_for(5, &error, 0.5), Some(Duration::from_millis(16_000)));
        assert_eq!(policy().delay_for(6, &error, 0.5), None);
    }

    #[test]
    fn jitter_bounds_match_the_exponential_curve() {
        let error = error(ErrorCode::Server);

        assert_eq!(policy().delay_for(1, &error, 0.0), Some(Duration::from_millis(800)));
        assert_eq!(policy().delay_for(1, &error, 0.5), Some(Duration::from_millis(1000)));

        let high = policy().delay_for(1, &error, 1.0 - 1e-9).expect("within budget");
        assert!(high <= Duration::from_millis(1200), "{high:?}");
        assert!(high >= Duration::from_millis(1199), "{high:?}");
    }

    #[test]
    fn jitter_ratio_zero_is_deterministic() {
        let policy = RetryPolicy { jitter_ratio: 0.0, ..policy() };
        let error = error(ErrorCode::Server);
        for random in [0.0, 0.5, 0.999_999] {
            assert_eq!(policy.delay_for(1, &error, random), Some(Duration::from_millis(1000)));
        }
    }

    #[test]
    fn delay_doubles_per_retry_and_saturates_at_max() {
        let error = error(ErrorCode::Server);
        let cases = [
            (2, 2000),
            (3, 4000),
            (4, 8000),
            (5, 16_000),
        ];
        for (retry, expected) in cases {
            assert_eq!(
                policy().delay_for(retry, &error, 0.5),
                Some(Duration::from_millis(expected)),
                "retry {retry}"
            );
        }

        let capped = RetryPolicy { max_retries: u32::MAX, ..policy() };
        assert_eq!(
            capped.delay_for(u32::MAX, &error, 0.5),
            Some(Duration::from_secs(30))
        );
    }

    #[test]
    fn jitter_is_applied_before_the_max_cap() {
        let policy = RetryPolicy {
            initial_delay: Duration::from_millis(1000),
            max_delay: Duration::from_millis(1500),
            ..policy()
        };
        let error = error(ErrorCode::Server);
        assert_eq!(policy.delay_for(2, &error, 0.5), Some(Duration::from_millis(1500)));
        assert_eq!(policy.delay_for(2, &error, 0.0), Some(Duration::from_millis(1200)));
    }

    #[test]
    fn retry_after_below_local_delay_is_used_verbatim() {
        let error = error_with_retry_after(ErrorCode::RateLimit, 250);
        assert_eq!(policy().delay_for(1, &error, 0.5), Some(Duration::from_millis(250)));
    }

    #[test]
    fn retry_after_above_local_delay_is_used_verbatim() {
        let error = error_with_retry_after(ErrorCode::RateLimit, 2500);
        assert_eq!(policy().delay_for(1, &error, 0.0), Some(Duration::from_millis(2500)));
        assert_eq!(policy().delay_for(1, &error, 1.0), Some(Duration::from_millis(2500)));
    }

    #[test]
    fn retry_after_at_or_over_max_is_bounded_or_delegated() {
        let at_cap = error_with_retry_after(ErrorCode::RateLimit, 30_000);
        assert_eq!(policy().delay_for(1, &at_cap, 0.5), Some(Duration::from_secs(30)));

        let over_cap = error_with_retry_after(ErrorCode::RateLimit, 30_001);
        assert_eq!(policy().delay_for(1, &over_cap, 0.5), None);
    }

    #[test]
    fn zero_retry_after_falls_back_to_local_delay() {
        let error = error_with_retry_after(ErrorCode::RateLimit, 0);
        assert_eq!(policy().delay_for(1, &error, 0.0), Some(Duration::from_millis(800)));
    }

    #[test]
    fn retry_after_does_not_override_the_retryable_check() {
        let error = error_with_retry_after(ErrorCode::Auth, 100);
        assert_eq!(policy().delay_for(1, &error, 0.5), None);
    }

    #[test]
    fn retry_after_is_ignored_when_retries_are_exhausted() {
        let error = error_with_retry_after(ErrorCode::RateLimit, 100);
        assert_eq!(policy().delay_for(0, &error, 0.5), None);
        assert_eq!(policy().delay_for(6, &error, 0.5), None);
    }
}
