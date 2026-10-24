//! Split long replies into messages an app accepts.

/// Split `text` into parts of at most `limit` characters, preferring to break
/// at a blank line, then a line end, then a space; never inside a character.
/// Parts are trimmed of the whitespace they were split on. Empty text yields
/// one empty part (the caller decides whether to send it).
pub fn split(text: &str, limit: usize) -> Vec<String> {
    let limit = limit.max(1);
    let mut parts = Vec::new();
    let mut rest = text.trim();
    while rest.chars().count() > limit {
        let cut_at = rest.char_indices().nth(limit).map_or(rest.len(), |(i, _)| i);
        let window = &rest[..cut_at];
        let cut = ["\n\n", "\n", " "]
            .iter()
            .filter_map(|sep| window.rfind(sep).filter(|&i| i > 0))
            .next()
            .unwrap_or(cut_at);
        parts.push(rest[..cut].trim_end().to_owned());
        rest = rest[cut..].trim_start();
    }
    parts.push(rest.to_owned());
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_is_one_part() {
        assert_eq!(split("hello", 10), ["hello"]);
    }

    #[test]
    fn prefers_paragraph_then_line_then_space_breaks() {
        assert_eq!(split("aaaa bbbb\n\ncccc", 12), ["aaaa bbbb", "cccc"]);
        assert_eq!(split("aaaa\nbbbb cccc", 11), ["aaaa", "bbbb cccc"]);
        assert_eq!(split("aaaa bbbb cccc", 10), ["aaaa bbbb", "cccc"]);
        assert_eq!(split("aaaa bbbb cccc", 8), ["aaaa", "bbbb", "cccc"]);
    }

    #[test]
    fn hard_splits_long_words_on_char_boundaries() {
        let parts = split(&"字".repeat(25), 10);
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.chars().count() <= 10));
        assert_eq!(parts.concat(), "字".repeat(25));
    }
}
