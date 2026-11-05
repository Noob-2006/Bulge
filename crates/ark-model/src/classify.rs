//! Map HTTP status codes and vendor error bodies onto `ProviderErrorKind`.

use ark_core::{ProviderError, ProviderErrorKind as K};
use serde_json::Value;
use std::time::Duration;

const OVERFLOW: &[&str] = &[
    "context length",
    "context_length",
    "context window",
    "maximum context",
    "too many tokens",
    "prompt is too long",
    "input is too long",
    "reduce the length",
    "token limit",
    "tokens exceeds",
    "input token count",
    "exceeds the maximum number of tokens",
    "maximum number of tokens",
    "string too long",
    "range of input length",
];

pub fn mentions_overflow(text: &str) -> bool {
    let t = text.to_lowercase();
    OVERFLOW.iter().any(|p| t.contains(p))
}

/// Pull a human-readable message out of the usual `{"error":{"message":..}}` shapes.
pub fn error_message(body: &str) -> String {
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        let e = v.get("error").unwrap_or(&v);
        if let Some(m) = e.get("message").and_then(Value::as_str) {
            return m.to_string();
        }
        if let Some(m) = e.as_str() {
            return m.to_string();
        }
    }
    let mut s = body.trim().to_string();
    if s.len() > 500 {
        let mut cut = 500;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
    }
    s
}

pub fn from_status(status: u16, retry_after: Option<Duration>, body: &str) -> ProviderError {
    let msg = error_message(body);
    let lower = body.to_lowercase();
    let kind = match status {
        429 if lower.contains("insufficient_quota") || lower.contains("billing") => K::Auth,
        429 => K::RateLimited {
            retry_after: retry_after.or_else(|| gemini_retry_delay(body)),
        },
        503 | 529 => K::Overloaded,
        500..=599 => K::Server,
        401..=403 => K::Auth, // 402: out of credit — another provider may still work
        400 | 404 | 413 | 422 if mentions_overflow(body) => K::ContextOverflow,
        408 => K::Timeout,
        _ => K::BadRequest,
    };
    ProviderError::new(kind, msg).with_status(status)
}

/// Classify an error object delivered inside a 200 stream (Anthropic `event: error`,
/// OpenAI `{"error":..}`, Responses `response.failed`, Gemini `{"error":..}`).
pub fn from_stream_error(err: &Value) -> ProviderError {
    let e = err.get("error").unwrap_or(err);
    let msg = e
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("stream error")
        .to_string();
    let tag = [e.get("type"), e.get("code"), e.get("status")]
        .iter()
        .filter_map(|x| {
            x.and_then(|v| {
                v.as_str()
                    .map(str::to_string)
                    .or_else(|| v.as_u64().map(|n| n.to_string()))
            })
        })
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let lmsg = msg.to_lowercase();
    let kind = if mentions_overflow(&msg) || tag.contains("context_length") {
        K::ContextOverflow
    } else if tag.contains("insufficient_quota")
        || tag.contains("billing")
        || lmsg.contains("no credits")
        || lmsg.contains("insufficient balance")
    {
        K::Auth // out of credit: retrying is pointless, another provider may work
    } else if tag.contains("overloaded")
        || tag.contains("503")
        || tag.contains("529")
        || tag.contains("unavailable")
    {
        K::Overloaded
    } else if tag.contains("rate_limit")
        || tag.contains("429")
        || tag.contains("resource_exhausted")
    {
        K::RateLimited { retry_after: None }
    } else if tag.contains("authentication")
        || tag.contains("permission")
        || tag.contains("401")
        || tag.contains("403")
    {
        K::Auth
    } else if tag.contains("invalid_request")
        || tag.contains("invalid_argument")
        || tag.contains("400")
    {
        K::BadRequest
    } else {
        K::Server
    };
    ProviderError::new(kind, msg)
}

/// Gemini reports `"retryDelay": "30s"` in the body instead of a header.
fn gemini_retry_delay(body: &str) -> Option<Duration> {
    let i = body.find("\"retryDelay\"")?;
    let rest = &body[i + 12..];
    let start = rest.find('"')? + 1;
    let end = rest[start..].find('"')? + start;
    let secs: f64 = rest[start..end].trim_end_matches('s').parse().ok()?;
    Some(Duration::from_secs_f64(secs))
}

pub fn parse_retry_after(v: &str) -> Option<Duration> {
    v.trim()
        .parse::<f64>()
        .ok()
        .filter(|s| *s >= 0.0)
        .map(Duration::from_secs_f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn status_mapping() {
        assert_eq!(
            from_status(429, Some(Duration::from_secs(3)), "").kind,
            K::RateLimited {
                retry_after: Some(Duration::from_secs(3))
            }
        );
        assert_eq!(
            from_status(429, None, r#"{"error":{"type":"insufficient_quota"}}"#).kind,
            K::Auth
        );
        assert_eq!(from_status(529, None, "").kind, K::Overloaded);
        assert_eq!(
            from_status(502, None, "<html>bad gateway</html>").kind,
            K::Server
        );
        assert_eq!(from_status(401, None, "").kind, K::Auth);
        assert_eq!(from_status(402, None, "Insufficient Balance").kind, K::Auth);
        assert_eq!(
            from_status(400, None, r#"{"error":{"message":"bad tool schema"}}"#).kind,
            K::BadRequest
        );
        assert_eq!(
            from_status(404, None, "model not found").kind,
            K::BadRequest
        );
        assert_eq!(from_status(400, None, "").status, Some(400));
    }

    #[test]
    fn overflow_wording_per_vendor() {
        for body in [
            r#"{"error":{"message":"This model's maximum context length is 128000 tokens","code":"context_length_exceeded"}}"#,
            r#"{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 210000 tokens > 200000 maximum"}}"#,
            r#"{"error":{"code":400,"message":"The input token count (1200000) exceeds the maximum number of tokens allowed (1048576).","status":"INVALID_ARGUMENT"}}"#,
            r#"{"error":{"message":"This model's maximum context length is 65536 tokens. However, you requested 70000 tokens. Please reduce the length of the messages."}}"#,
            r#"{"error":{"message":"Range of input length should be [1, 98304]"}}"#,
        ] {
            assert_eq!(
                from_status(400, None, body).kind,
                K::ContextOverflow,
                "{body}"
            );
        }
    }

    #[test]
    fn gemini_retry_delay_from_body() {
        let b = r#"{"error":{"code":429,"details":[{"retryDelay":"7s"}]}}"#;
        assert_eq!(
            from_status(429, None, b).kind,
            K::RateLimited {
                retry_after: Some(Duration::from_secs(7))
            }
        );
    }

    #[test]
    fn stream_errors() {
        assert_eq!(
            from_stream_error(
                &json!({"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}})
            )
            .kind,
            K::Overloaded
        );
        assert_eq!(
            from_stream_error(
                &json!({"error":{"message":"Rate limit reached","type":"rate_limit_error"}})
            )
            .kind,
            K::RateLimited { retry_after: None }
        );
        assert_eq!(
            from_stream_error(
                &json!({"error":{"code":"context_length_exceeded","message":"too long"}})
            )
            .kind,
            K::ContextOverflow
        );
        assert_eq!(
            from_stream_error(
                &json!({"error":{"code":500,"message":"internal","status":"INTERNAL"}})
            )
            .kind,
            K::Server
        );
        assert_eq!(
            from_stream_error(&json!({"error":{"type":"invalid_request_error","message":"bad"}}))
                .kind,
            K::BadRequest
        );
        assert_eq!(from_stream_error(&json!({"error":{"code":"insufficient_quota","message":"You have no credits remaining."}})).kind, K::Auth);
        assert_eq!(
            from_stream_error(
                &json!({"error":{"message":"You have no credits remaining. Add credits"}})
            )
            .kind,
            K::Auth
        );
        assert_eq!(from_stream_error(&json!({"weird":true})).kind, K::Server);
    }

    #[test]
    fn retry_after_parsing_and_message_truncation() {
        assert_eq!(parse_retry_after(" 2 "), Some(Duration::from_secs(2)));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
        assert_eq!(parse_retry_after("-1"), None);
        let long = "错".repeat(400);
        assert!(error_message(&long).len() <= 500);
    }
}
