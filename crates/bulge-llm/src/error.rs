//! Provider-neutral failure classification consumed by retry and the agent loop.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    Auth,
    Quota,
    RateLimit,
    ContextWindowExceeded,
    InvalidRequest,
    Server,
    /// Other HTTP status not covered above.
    Http(u16),
    Network,
    StreamClosed,
    StreamIdle,
    MalformedResponse,
    EmptyResponse,
    UnsupportedContent,
    UnsupportedReasoningEffort,
    Aborted,
}

impl ErrorCode {
    /// Codes the default retry policy retries.
    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimit | Self::Server | Self::Network | Self::StreamClosed | Self::StreamIdle
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmError {
    pub code: ErrorCode,
    pub message: String,
    pub status: Option<u16>,
    pub request_id: Option<String>,
    /// Provider `retry-after`, already converted to milliseconds.
    pub retry_after_ms: Option<u64>,
}

impl LlmError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), status: None, request_id: None, retry_after_ms: None }
    }

    pub fn malformed(detail: impl fmt::Display) -> Self {
        Self::new(ErrorCode::MalformedResponse, format!("malformed response: {detail}"))
    }

    pub fn unsupported(detail: impl fmt::Display) -> Self {
        Self::new(ErrorCode::UnsupportedContent, format!("cannot represent {detail}"))
    }
}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for LlmError {}

/// Classify a provider failure from an HTTP status and/or a decoded error
/// envelope (`{"error": {"type", "code", "message"}}`, also used in-band).
/// Never trusts fields beyond type/code/message.
/// MARK: M5 — transcribed by dsh; see marks/M5-error-map.md.
pub fn classify_http(
    status: Option<u16>,
    body: &serde_json::Value,
    retry_after: Option<&str>,
    request_id: Option<&str>,
) -> LlmError {
    let error = match body {
        serde_json::Value::Object(envelope) => {
            envelope.get("error").filter(|value| value.is_object())
        }
        _ => None,
    };
    let field = |name: &str| {
        error
            .and_then(|value| value.get(name))
            .and_then(serde_json::Value::as_str)
    };
    let type_ = field("type").unwrap_or("");
    let provider_code = field("code").unwrap_or("");
    let message = field("message").map_or_else(
        || match status {
            Some(status) => format!("request failed ({status})"),
            None => "request failed (stream error)".to_owned(),
        },
        str::to_owned,
    );
    // Only the provider-controlled type, code, and message participate in
    // classification; no other envelope fields are trusted.
    let detail = format!("{type_} {provider_code} {message}");

    let code = if matches!(status, Some(401 | 403))
        || matches!(type_, "authentication_error" | "permission_error")
    {
        ErrorCode::Auth
    } else if is_quota_exceeded_error(&detail) || status == Some(402) {
        ErrorCode::Quota
    } else if status == Some(429) || type_ == "rate_limit_error" {
        ErrorCode::RateLimit
    } else if is_context_window_exceeded_error(&detail) {
        ErrorCode::ContextWindowExceeded
    } else if matches!(status, Some(400 | 413)) || type_ == "invalid_request_error" {
        ErrorCode::InvalidRequest
    } else if status.is_some_and(|status| status >= 500)
        || matches!(type_, "api_error" | "overloaded_error")
    {
        ErrorCode::Server
    } else {
        match status {
            Some(status) => ErrorCode::Http(status),
            None => ErrorCode::Server,
        }
    };

    LlmError {
        code,
        message,
        status,
        request_id: request_id.filter(|id| !id.is_empty()).map(str::to_owned),
        retry_after_ms: retry_after.and_then(parse_retry_after),
    }
}

#[derive(Debug, Clone, Copy)]
struct Word<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

/// Split lowercased text into ASCII word tokens, retaining apostrophes so
/// possessive forms such as `model's` stay together.
fn words(text: &str) -> Vec<Word<'_>> {
    let mut words = Vec::new();
    let mut start = None;
    for (index, ch) in text.char_indices() {
        let word_char = ch.is_ascii_alphanumeric() || ch == '\'';
        if word_char {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take() {
            words.push(Word { text: &text[begin..index], start: begin, end: index });
        }
    }
    if let Some(begin) = start {
        words.push(Word { text: &text[begin..], start: begin, end: text.len() });
    }
    words
}

fn is_quota_exceeded_error(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    let words = words(&lower);
    let token = |index: usize| words.get(index).map(|word| word.text);
    for index in 0..words.len() {
        match token(index) {
            Some("insufficient") => {
                if matches!(
                    token(index + 1),
                    Some("quota" | "balance" | "credit" | "credits")
                ) {
                    return true;
                }
            }
            Some("quota") => {
                if matches!(
                    token(index + 1),
                    Some("exceeded" | "exhausted" | "reached")
                ) {
                    return true;
                }
            }
            Some("usage") => {
                if token(index + 1) == Some("limit")
                    && matches!(
                        token(index + 2),
                        Some("exceeded" | "exhausted" | "reached")
                    )
                {
                    return true;
                }
            }
            Some("exceed" | "exceeded" | "exceeds") => {
                let mut next = index + 1;
                if matches!(token(next), Some("your" | "the")) {
                    next += 1;
                }
                if token(next) == Some("current") {
                    next += 1;
                }
                if token(next) == Some("quota") {
                    return true;
                }
            }
            Some("balance" | "credit" | "credits") => {
                if matches!(token(index + 1), Some("exhausted" | "depleted")) {
                    return true;
                }
            }
            Some("out")
                if token(index + 1) == Some("of")
                    && matches!(token(index + 2), Some("credit" | "credits" | "budget")) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn is_context_window_exceeded_error(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    let words = words(&lower);
    let token = |index: usize| words.get(index).map(|word| word.text);

    for index in 0..words.len() {
        // context_length_exceeded / context-window-overflowed / context window limit exceeded.
        if token(index) == Some("context")
            && matches!(token(index + 1), Some("length" | "window"))
            && (matches!(
                token(index + 2),
                Some("exceed" | "exceeded" | "exceeds" | "overflow" | "overflowed")
            ) || (token(index + 2) == Some("limit") && token(index + 3) == Some("exceeded")))
        {
            return true;
        }

        // maximum [allowed|supported] context length/window.
        if matches!(token(index), Some("max" | "maximum")) {
            let mut next = index + 1;
            if matches!(token(next), Some("allowed" | "supported")) {
                next += 1;
            }
            if token(next) == Some("context")
                && matches!(token(next + 1), Some("length" | "window"))
            {
                return true;
            }
        }

        // request too large for [the] [model's] context [window].
        if matches!(
            token(index),
            Some("request" | "prompt" | "input" | "message" | "messages")
        ) {
            let mut next = index + 1;
            if matches!(token(next), Some("is" | "are")) {
                next += 1;
            }
            if token(next) == Some("too") {
                next += 1;
                if matches!(token(next), Some("large" | "long")) && token(next + 1) == Some("for") {
                    next += 2;
                    if matches!(token(next), Some("this" | "the")) {
                        next += 1;
                    }
                    if matches!(token(next), Some("model" | "model's")) {
                        next += 1;
                    }
                    if token(next) == Some("context") {
                        return true;
                    }
                }
            }
        }

        // input too long for this model (capacity wording without "context").
        if matches!(token(index), Some("input" | "prompt" | "request")) {
            let mut next = index + 1;
            if token(next) == Some("is") {
                next += 1;
            }
            if token(next) == Some("too")
                && matches!(token(next + 1), Some("long" | "large"))
                && token(next + 2) == Some("for")
                && matches!(token(next + 3), Some("this" | "the"))
                && token(next + 4) == Some("model")
            {
                return true;
            }
        }
    }

    exceeds_model_context(&words)
}

/// Match `input/prompt/request/messages` ... `exceed(s|ed)|overflow(s|ed)|is
/// larger than` ... `[the] [model['s]] context` with the reference's bounded
/// 40-character windows between the three parts.
fn exceeds_model_context(words: &[Word<'_>]) -> bool {
    for (index, word) in words.iter().enumerate() {
        if !matches!(word.text, "input" | "prompt" | "request" | "message" | "messages") {
            continue;
        }
        for trigger in index + 1..words.len() {
            let gap = words[trigger].start.saturating_sub(word.end);
            if gap > 40 {
                break;
            }
            let trigger_end = if matches!(
                words[trigger].text,
                "exceed" | "exceeds" | "exceeded" | "overflow" | "overflows" | "overflowed"
            ) {
                Some(words[trigger].end)
            } else if words[trigger].text == "is"
                && words.get(trigger + 1).is_some_and(|next| next.text == "larger")
                && words.get(trigger + 2).is_some_and(|next| next.text == "than")
            {
                Some(words[trigger + 2].end)
            } else {
                None
            };
            let Some(trigger_end) = trigger_end else {
                continue;
            };
            let context_limit = trigger_end.saturating_add(40 + 16);
            for candidate in words.iter().skip(trigger + 1) {
                if candidate.start > context_limit {
                    break;
                }
                if candidate.text == "context" {
                    return true;
                }
            }
        }
    }
    false
}

fn parse_retry_after(value: &str) -> Option<u64> {
    if is_decimal_seconds(value) {
        let seconds = value.parse::<f64>().ok()?;
        let millis = seconds * 1000.0;
        if millis.is_finite() && millis > 0.0 && millis <= u64::MAX as f64 {
            Some(millis as u64)
        } else {
            None
        }
    } else {
        let target_ms = parse_imf_fixdate(value)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_millis() as i128;
        let delay = target_ms - now_ms;
        if delay > 0 {
            u64::try_from(delay).ok()
        } else {
            None
        }
    }
}

fn is_decimal_seconds(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(integer) = parts.next() else {
        return false;
    };
    let fraction = parts.next();
    if parts.next().is_some() {
        return false;
    }
    if integer.is_empty() || !integer.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    match fraction {
        None => true,
        Some(fraction) => {
            !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit())
        }
    }
}

/// Parse the IMF-fixdate form used by `Retry-After`, e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`, into milliseconds since the Unix epoch.
fn parse_imf_fixdate(value: &str) -> Option<i128> {
    let mut parts = value.split_whitespace();
    let _weekday = parts.next()?;
    let day: u32 = parts.next()?.parse().ok()?;
    let month = match parts.next()?.to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let year: i64 = parts.next()?.parse().ok()?;
    if !(1970..=9999).contains(&year) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let mut clock = parts.next()?.split(':');
    let hour: u32 = clock.next()?.parse().ok()?;
    let minute: u32 = clock.next()?.parse().ok()?;
    let second: u32 = clock.next()?.parse().ok()?;
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    if !parts.next()?.eq_ignore_ascii_case("GMT") || parts.next().is_some() {
        return None;
    }

    let days = days_from_civil(year, month, day);
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i128::from(hour) * 3_600 + i128::from(minute) * 60 + i128::from(second))?;
    seconds.checked_mul(1_000)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i128 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_from_march = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(day) - 1;
    let day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i128::from(era * 146_097 + day_of_era - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn envelope(kind: Option<&str>, code: Option<&str>, message: Option<&str>) -> serde_json::Value {
        let mut error = serde_json::Map::new();
        if let Some(kind) = kind {
            error.insert("type".to_owned(), json!(kind));
        }
        if let Some(code) = code {
            error.insert("code".to_owned(), json!(code));
        }
        if let Some(message) = message {
            error.insert("message".to_owned(), json!(message));
        }
        json!({ "error": error })
    }

    fn classify(status: Option<u16>, body: serde_json::Value) -> LlmError {
        classify_http(status, &body, None, None)
    }

    #[test]
    fn classifies_auth_and_permission_failures() {
        let error = classify(Some(401), json!({}));
        assert_eq!(error.code, ErrorCode::Auth);
        assert_eq!(error.status, Some(401));
        assert!(error.message.contains("401"));

        let error = classify(Some(200), envelope(Some("permission_error"), None, Some("no access")));
        assert_eq!(error.code, ErrorCode::Auth);
        assert_eq!(error.message, "no access");
    }

    #[test]
    fn classifies_quota_failures_before_rate_limits() {
        let error = classify(Some(402), json!({}));
        assert_eq!(error.code, ErrorCode::Quota);

        let error = classify(
            Some(429),
            envelope(None, Some("insufficient_quota"), Some("You exceeded your current quota")),
        );
        assert_eq!(error.code, ErrorCode::Quota);
    }

    #[test]
    fn classifies_rate_limits() {
        assert_eq!(classify(Some(429), json!({})).code, ErrorCode::RateLimit);
        assert_eq!(
            classify(Some(400), envelope(Some("rate_limit_error"), None, Some("slow down"))).code,
            ErrorCode::RateLimit
        );
    }

    #[test]
    fn classifies_context_window_overflows() {
        for message in [
            "context_length_exceeded maximum context length",
            "context-window-overflowed",
            "This model maximum context length is 128000 tokens",
            "input is too long for this model",
            "request too large for model context",
            "input exceeds the model context window limit",
        ] {
            let error = classify(Some(400), envelope(None, None, Some(message)));
            assert_eq!(error.code, ErrorCode::ContextWindowExceeded, "{message}");
        }

        for message in [
            "invalid request: malformed tool arguments",
            "invalid input: temperature exceeds maximum allowed value",
            "input exceeds maximum allowed value",
            "context window size must be positive",
        ] {
            let error = classify(Some(400), envelope(None, None, Some(message)));
            assert_eq!(error.code, ErrorCode::InvalidRequest, "{message}");
        }
    }

    #[test]
    fn classifies_invalid_requests() {
        assert_eq!(classify(Some(400), json!({})).code, ErrorCode::InvalidRequest);
        assert_eq!(classify(Some(413), json!({})).code, ErrorCode::InvalidRequest);
        assert_eq!(
            classify(Some(422), envelope(Some("invalid_request_error"), None, Some("bad"))).code,
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn classifies_server_and_other_http_failures() {
        assert_eq!(classify(Some(500), json!({})).code, ErrorCode::Server);
        assert_eq!(
            classify(None, envelope(Some("api_error"), None, Some("boom"))).code,
            ErrorCode::Server
        );
        assert_eq!(
            classify(Some(418), envelope(Some("overloaded_error"), None, Some("busy"))).code,
            ErrorCode::Server
        );
        assert_eq!(classify(None, json!({})).code, ErrorCode::Server);
        assert_eq!(classify(Some(418), json!({})).code, ErrorCode::Http(418));
    }

    #[test]
    fn uses_the_neutral_default_message() {
        let error = classify(Some(503), json!({}));
        assert_eq!(error.message, "request failed (503)");
        let error = classify(None, json!({}));
        assert_eq!(error.message, "request failed (stream error)");
    }

    #[test]
    fn ignores_non_object_or_malformed_error_envelopes() {
        for body in [serde_json::Value::Null, json!([]), json!("boom"), json!(42)] {
            let error = classify_http(Some(401), &body, None, None);
            assert_eq!(error.code, ErrorCode::Auth);
            assert_eq!(error.message, "request failed (401)");
        }

        let body = json!({
            "error": {
                "type": 7,
                "code": false,
                "message": null,
                "untrusted": "context_length_exceeded"
            }
        });
        let error = classify(Some(400), body);
        assert_eq!(error.code, ErrorCode::InvalidRequest);
        assert_eq!(error.message, "request failed (400)");
    }

    #[test]
    fn parses_numeric_retry_after_as_seconds() {
        let body = json!({ "error": { "message": "busy" } });
        let error = classify_http(Some(429), &body, Some("2"), None);
        assert_eq!(error.retry_after_ms, Some(2_000));

        let error = classify_http(Some(429), &body, Some("1.5"), None);
        assert_eq!(error.retry_after_ms, Some(1_500));

        for value in ["0", "-1", "1.", ".5", "1.2.3", " 1", "garbage"] {
            let error = classify_http(Some(429), &body, Some(value), None);
            assert_eq!(error.retry_after_ms, None, "{value}");
        }
    }

    #[test]
    fn parses_http_date_retry_after() {
        let body = json!({ "error": { "message": "busy" } });
        let past = classify_http(
            Some(429),
            &body,
            Some("Sun, 06 Nov 1994 08:49:37 GMT"),
            None,
        );
        assert_eq!(past.retry_after_ms, None);

        let future = classify_http(
            Some(429),
            &body,
            Some("Sun, 06 Nov 2094 08:49:37 GMT"),
            None,
        );
        assert!(future.retry_after_ms.is_some());
    }

    #[test]
    fn carries_request_id_when_present() {
        let body = json!({});
        let error = classify_http(Some(500), &body, None, Some("req-1"));
        assert_eq!(error.request_id.as_deref(), Some("req-1"));
        let error = classify_http(Some(500), &body, None, Some(""));
        assert_eq!(error.request_id, None);
    }
}


