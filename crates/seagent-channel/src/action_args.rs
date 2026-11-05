//! Argument readers shared by the per-channel `Channel::message_action` implementations
//! (OpenClaw `readStringParam` & co.). Keys are tried in order; ids may arrive as numbers.

use crate::{ChannelError, ChannelErrorKind as K};
use serde_json::Value;

/// A bad or missing argument: the model must fix the call, retrying cannot help.
pub fn bad(msg: impl Into<String>) -> ChannelError {
    ChannelError::new(K::Fatal, msg)
}

/// The action is not in this channel's vocabulary.
pub fn unknown(provider: &str, action: &str) -> ChannelError {
    ChannelError::new(K::Unsupported, format!("Action {action} is not supported for provider {provider}."))
}

/// First non-empty (trimmed) string or number under `keys`.
pub fn s(a: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| match &a[*k] {
        Value::String(v) if !v.trim().is_empty() => Some(v.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

/// Like `s` but untrimmed and allowing the empty string (message bodies).
pub fn text(a: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| a[*k].as_str().map(str::to_string))
}

/// Required string: `"{label} required"` names the first key.
pub fn req(a: &Value, keys: &[&str]) -> Result<String, ChannelError> {
    s(a, keys).ok_or_else(|| bad(format!("{} required", keys[0])))
}

/// Integer (number or numeric string).
pub fn int(a: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter().find_map(|k| match &a[*k] {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)),
        Value::String(v) => v.trim().parse().ok(),
        _ => None,
    })
}

/// Positive integer; a present but non-positive value is an error.
pub fn pos(a: &Value, keys: &[&str]) -> Result<Option<u64>, ChannelError> {
    match int(a, keys) {
        Some(n) if n > 0 => Ok(Some(n as u64)),
        Some(_) => Err(bad(format!("{} must be a positive integer", keys[0]))),
        None => Ok(None),
    }
}

/// Non-negative integer.
pub fn nonneg(a: &Value, keys: &[&str]) -> Result<Option<u64>, ChannelError> {
    match int(a, keys) {
        Some(n) if n >= 0 => Ok(Some(n as u64)),
        Some(_) => Err(bad(format!("{} must be a non-negative integer", keys[0]))),
        None => Ok(None),
    }
}

/// Boolean (`true`/`false` or the strings).
pub fn flag(a: &Value, key: &str) -> Option<bool> {
    match &a[key] {
        Value::Bool(b) => Some(*b),
        Value::String(v) => match v.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// String list: an array, a comma-separated string, or a single value.
pub fn list(a: &Value, keys: &[&str]) -> Vec<String> {
    for k in keys {
        match &a[*k] {
            Value::Array(xs) => {
                let v: Vec<String> = xs.iter().filter_map(|x| x.as_str().map(|t| t.trim().to_string()).or_else(|| x.as_i64().map(|n| n.to_string()))).filter(|t| !t.is_empty()).collect();
                if !v.is_empty() {
                    return v;
                }
            }
            Value::String(v) if !v.trim().is_empty() => return v.split(',').map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect(),
            Value::Number(n) => return vec![n.to_string()],
            _ => {}
        }
    }
    Vec::new()
}

/// The conversation the action addresses (`target`, then OpenClaw's `to` / `channelId` / `chatId`).
pub fn target(a: &Value) -> Option<String> {
    s(a, &["target", "to", "channelId", "chatId"])
}

/// `target` or an error naming it.
pub fn need_target(a: &Value, action: &str) -> Result<String, ChannelError> {
    target(a).ok_or_else(|| bad(format!("{action} requires target (the chat / channel id)")))
}

/// Poll fields after `message::normalize_poll`: (question, options, max selections, duration seconds).
pub fn poll(a: &Value) -> Result<(String, Vec<String>, u64, Option<u64>), ChannelError> {
    let q = s(a, &["question", "pollQuestion"]).ok_or_else(|| bad("poll requires question"))?;
    let opts = list(a, &["options", "answers", "pollOption"]);
    if opts.len() < 2 {
        return Err(bad("poll requires at least 2 options"));
    }
    let max = int(a, &["maxSelections"]).map(|n| n.max(1) as u64).unwrap_or_else(|| if flag(a, "allowMultiselect").or(flag(a, "pollMulti")) == Some(true) { opts.len() as u64 } else { 1 });
    let secs = int(a, &["durationSeconds", "pollDurationSeconds"]).filter(|n| *n > 0).map(|n| n as u64).or_else(|| int(a, &["durationHours", "pollDurationHours"]).filter(|n| *n > 0).map(|h| h as u64 * 3600));
    Ok((q, opts, max, secs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn readers_accept_aliases_numbers_and_lists() {
        let a = json!({"to": " C1 ", "messageId": 42, "limit": "5", "ids": "a, b,", "arr": ["x", 7], "on": "true", "neg": -1});
        assert_eq!(target(&a).as_deref(), Some("C1"));
        assert_eq!(req(&a, &["messageId"]).unwrap(), "42");
        assert!(req(&a, &["userId"]).unwrap_err().message.contains("userId required"));
        assert_eq!(pos(&a, &["limit"]).unwrap(), Some(5));
        assert!(pos(&a, &["neg"]).is_err());
        assert_eq!(list(&a, &["ids"]), vec!["a", "b"]);
        assert_eq!(list(&a, &["arr"]), vec!["x", "7"]);
        assert_eq!(flag(&a, "on"), Some(true));
        assert_eq!(unknown("x", "kick").kind, K::Unsupported);
    }

    #[test]
    fn poll_fields_normalise() {
        let (q, o, m, d) = poll(&json!({"question": "Lunch?", "options": ["a", "b", "c"], "allowMultiselect": true, "durationHours": 2})).unwrap();
        assert_eq!((q.as_str(), o.len(), m, d), ("Lunch?", 3, 3, Some(7200)));
        assert!(poll(&json!({"question": "q", "options": ["a"]})).is_err());
        assert_eq!(poll(&json!({"question": "q", "options": ["a", "b"], "maxSelections": 2, "durationSeconds": 60})).unwrap().2, 2);
    }
}
