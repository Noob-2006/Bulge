//! Secret scrubbing for text that may be logged, shown, or persisted. Exact
//! values registered by the caller are removed first, then known credential
//! shapes and PEM private-key blocks are replaced by short markers.

/// Redacts secret-looking substrings from text.
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    /// Exact secret values to scrub wherever they appear (longest first at scan time).
    values: Vec<String>,
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an exact secret value to always scrub. Empty/very short
    /// (<6 chars) values are ignored.
    pub fn register_value(&mut self, value: impl Into<String>) {
        let value = value.into();
        if value.chars().count() >= 6 {
            self.values.push(value);
        }
    }

    /// Return `text` with registered values and known secret shapes replaced by
    /// `«redacted:KIND»`.
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_string();
        let mut values: Vec<&str> = self.values.iter().map(String::as_str).collect();
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        for value in values {
            if value.len() >= 6 {
                out = out.replace(value, "«redacted:value»");
            }
        }
        let out = redact_private_keys(&out);
        redact_tokens(&out)
    }
}

/// Convenience: redact with the built-in shape patterns only (no registered
/// values).
pub fn redact_secrets(text: &str) -> String {
    Redactor::new().redact(text)
}

const ASSIGNMENT_KEYS: &[&str] = &[
    "apikey",
    "secret",
    "token",
    "password",
    "passwd",
    "accesskey",
    "secretkey",
];

fn is_wrapper(c: char) -> bool {
    matches!(c, '\'' | '"' | ',' | ';')
}

/// Byte range of the token with surrounding quotes/commas/semicolons removed.
fn trimmed_range(token: &str) -> (usize, usize) {
    let start = token
        .char_indices()
        .find(|(_, c)| !is_wrapper(*c))
        .map_or(token.len(), |(i, _)| i);
    let end = token
        .char_indices()
        .rev()
        .find(|(_, c)| !is_wrapper(*c))
        .map_or(start, |(i, c)| i + c.len_utf8());
    (start, end)
}

fn whole_token_kind(token: &str) -> Option<&'static str> {
    let len = token.chars().count();
    if len >= 20
        && (token.starts_with("sk-")
            || token.starts_with("sk_live_")
            || token.starts_with("sk_test_"))
    {
        return Some("openai-key");
    }
    if len >= 20
        && (token.starts_with("ghp_")
            || token.starts_with("gho_")
            || token.starts_with("ghs_")
            || token.starts_with("ghu_")
            || token.starts_with("github_pat_"))
    {
        return Some("github-token");
    }
    if len >= 20 && token.starts_with("glpat-") {
        return Some("gitlab-token");
    }
    if len == 20
        && token.starts_with("AKIA")
        && token
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Some("aws-access-key");
    }
    if token.starts_with("xoxb-") || token.starts_with("xoxp-") || token.starts_with("xoxa-") {
        return Some("slack-token");
    }
    None
}

/// If `token` is `KEY=VALUE`/`KEY:VALUE` with a sensitive key and a long enough
/// value, return the byte offset where the value starts.
fn assignment_value_start(token: &str) -> Option<usize> {
    let sep = token.find(['=', ':'])?;
    let key: String = token[..sep]
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let value = &token[sep + 1..];
    if key.is_empty() || value.chars().count() < 6 {
        return None;
    }
    if ASSIGNMENT_KEYS.iter().any(|suffix| key.ends_with(suffix)) {
        Some(sep + 1)
    } else {
        None
    }
}

fn redact_tokens(text: &str) -> String {
    let mut spans = Vec::new();
    let mut token_start = None;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() {
            if let Some(start) = token_start.take() {
                spans.push((start, i));
            }
        } else if token_start.is_none() {
            token_start = Some(i);
        }
    }
    if let Some(start) = token_start {
        spans.push((start, text.len()));
    }

    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut bearer_next = false;
    for (start, end) in spans {
        out.push_str(&text[cursor..start]);
        let token = &text[start..end];
        let (inner_start, inner_end) = trimmed_range(token);
        let core = &token[inner_start..inner_end];
        let prefix = &token[..inner_start];
        let suffix = &token[inner_end..];

        if bearer_next {
            bearer_next = false;
            if core.chars().count() >= 16 {
                out.push_str(prefix);
                out.push_str("«redacted:bearer»");
                out.push_str(suffix);
            } else {
                out.push_str(token);
            }
        } else if core.eq_ignore_ascii_case("bearer") {
            bearer_next = true;
            out.push_str(token);
        } else if let Some(kind) = whole_token_kind(core) {
            out.push_str(prefix);
            out.push_str(&format!("«redacted:{kind}»"));
            out.push_str(suffix);
        } else if let Some(value_start) = assignment_value_start(core) {
            out.push_str(prefix);
            out.push_str(&core[..value_start]);
            out.push_str("«redacted:assignment»");
            out.push_str(suffix);
        } else {
            out.push_str(token);
        }
        cursor = end;
    }
    out.push_str(&text[cursor..]);
    out
}

fn line_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0;
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            let end = if i > start && text.as_bytes()[i - 1] == b'\r' {
                i - 1
            } else {
                i
            };
            spans.push((start, end));
            start = i + 1;
        }
    }
    if start < text.len() {
        spans.push((start, text.len()));
    }
    spans
}

fn is_private_key_begin(line: &str) -> bool {
    line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----")
}

fn is_private_key_end(line: &str) -> bool {
    line.contains("-----END") && line.contains("PRIVATE KEY-----")
}

/// Replace whole PEM private-key blocks, line-based, with one marker.
fn redact_private_keys(text: &str) -> String {
    let lines = line_spans(text);
    let mut out = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut i = 0;
    while i < lines.len() {
        let (start, end) = lines[i];
        if is_private_key_begin(&text[start..end]) {
            let mut j = i + 1;
            while j < lines.len() && !is_private_key_end(&text[lines[j].0..lines[j].1]) {
                j += 1;
            }
            if j < lines.len() {
                out.push_str(&text[cursor..start]);
                out.push_str("«redacted:private-key»");
                cursor = lines[j].1;
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&text[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::{Redactor, redact_secrets};

    #[test]
    fn openai_keys_redact() {
        for key in [
            "sk-abcdefghijklmnopqrst",
            "sk_live_abcdefghijklmnopqrst",
            "sk_test_abcdefghijklmnopqrst",
        ] {
            assert_eq!(redact_secrets(key), "«redacted:openai-key»", "{key}");
        }
    }

    #[test]
    fn github_and_gitlab_tokens_redact() {
        for key in [
            "ghp_abcdefghijklmnopqrst",
            "gho_abcdefghijklmnopqrst",
            "ghs_abcdefghijklmnopqrst",
            "ghu_abcdefghijklmnopqrst",
            "github_pat_abcdefghijklmnopqrst",
        ] {
            assert_eq!(redact_secrets(key), "«redacted:github-token»", "{key}");
        }
        assert_eq!(
            redact_secrets("glpat-abcdefghijklmnopqrst"),
            "«redacted:gitlab-token»"
        );
    }

    #[test]
    fn aws_and_slack_tokens_redact() {
        assert_eq!(
            redact_secrets("AKIAIOSFODNN7EXAMPLE"),
            "«redacted:aws-access-key»"
        );
        for key in ["xoxb-1234567890", "xoxp-1234567890", "xoxa-1234567890"] {
            assert_eq!(redact_secrets(key), "«redacted:slack-token»", "{key}");
        }
    }

    #[test]
    fn bearer_value_redacts() {
        assert_eq!(
            redact_secrets("Authorization: Bearer abcdefghijklmnopqrstuvwxyz"),
            "Authorization: Bearer «redacted:bearer»"
        );
    }

    #[test]
    fn assignment_keeps_key_and_redacts_value() {
        assert_eq!(
            redact_secrets("api_key=abcdef123456"),
            "api_key=«redacted:assignment»"
        );
        assert_eq!(
            redact_secrets("PASSWORD:hunter2hunter2"),
            "PASSWORD:«redacted:assignment»"
        );
    }

    #[test]
    fn surrounding_punctuation_is_preserved() {
        assert_eq!(
            redact_secrets("\"api_key=abcdef123456\","),
            "\"api_key=«redacted:assignment»\","
        );
    }

    #[test]
    fn private_key_block_is_replaced() {
        let pem = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\nafter";
        assert_eq!(redact_secrets(pem), "before\n«redacted:private-key»\nafter");
    }

    #[test]
    fn registered_value_scrubs_mid_word() {
        let mut redactor = Redactor::new();
        redactor.register_value("hunter2secret");
        assert_eq!(
            redactor.redact("prefixhunter2secretsuffix"),
            "prefix«redacted:value»suffix"
        );
    }

    #[test]
    fn short_registered_values_are_ignored() {
        let mut redactor = Redactor::new();
        redactor.register_value("");
        redactor.register_value("abcde");
        assert_eq!(redactor.redact("abcde"), "abcde");
    }

    #[test]
    fn plain_text_is_unchanged() {
        let text = "The quick brown fox jumps over the lazy dog.";
        assert_eq!(redact_secrets(text), text);
    }
}
