//! Split long replies to fit a channel's limit, measured in the channel's own
//! unit (Telegram counts UTF-16). Prefers paragraph, then line, then word
//! breaks, and keeps ``` fences balanced across pieces.

use crate::LenUnit;

pub fn len(s: &str, unit: LenUnit) -> usize {
    match unit {
        LenUnit::Chars => s.chars().count(),
        LenUnit::Utf16 => s.encode_utf16().count(),
        LenUnit::Bytes => s.len(),
    }
}

fn clen(c: char, unit: LenUnit) -> usize {
    match unit {
        LenUnit::Chars => 1,
        LenUnit::Utf16 => c.len_utf16(),
        LenUnit::Bytes => c.len_utf8(),
    }
}

/// Pieces of at most `max` units each. Empty or whitespace text yields no pieces.
pub fn split(text: &str, max: usize, unit: LenUnit) -> Vec<String> {
    let max = max.max(16);
    let text = text.trim_end();
    if text.trim().is_empty() {
        return vec![];
    }
    if len(text, unit) <= max {
        return vec![text.to_string()];
    }
    // Reserve room to close and reopen a code fence.
    let budget = max.saturating_sub(8);
    let mut out = Vec::new();
    let mut rest = text;
    let mut open_fence: Option<String> = None;
    while !rest.is_empty() {
        let prefix = open_fence.as_ref().map(|f| format!("{f}\n")).unwrap_or_default();
        let room = budget.saturating_sub(len(&prefix, unit)).max(8);
        let mut units = 0;
        let mut hard = rest.len();
        for (i, c) in rest.char_indices() {
            units += clen(c, unit);
            if units > room {
                hard = i;
                break;
            }
        }
        let cut = if hard == rest.len() {
            hard
        } else {
            let head = &rest[..hard];
            let at = |p: Option<usize>, skip: usize| p.filter(|&i| i > hard / 3).map(|i| i + skip);
            at(head.rfind("\n\n"), 2).or_else(|| at(head.rfind('\n'), 1)).or_else(|| at(head.rfind(' '), 1)).unwrap_or(hard.max(rest.chars().next().map(char::len_utf8).unwrap_or(1)))
        };
        let piece = &rest[..cut];
        rest = rest[cut..].trim_start_matches('\n');
        let mut body = format!("{prefix}{}", piece.trim_end());
        // Track fences inside this piece.
        let mut fence = open_fence.clone();
        for line in piece.lines() {
            let t = line.trim_start();
            if t.starts_with("```") {
                fence = if fence.is_some() { None } else { Some(t.trim_end().to_string()) };
            }
        }
        if fence.is_some() && !rest.is_empty() {
            body.push_str("\n```");
        }
        open_fence = fence.map(|f| if f.len() > 3 { f } else { "```".into() });
        out.push(body);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_untouched_and_empty_dropped() {
        assert_eq!(split("hi", 100, LenUnit::Chars), vec!["hi"]);
        assert!(split("  \n ", 100, LenUnit::Chars).is_empty());
    }

    #[test]
    fn splits_on_paragraphs_lines_words_within_limit() {
        let para = format!("{}\n\n{}", "a".repeat(60), "b".repeat(60));
        let p = split(&para, 100, LenUnit::Chars);
        assert_eq!(p, vec!["a".repeat(60), "b".repeat(60)]);
        let words = "word ".repeat(100);
        for piece in split(&words, 50, LenUnit::Chars) {
            assert!(len(&piece, LenUnit::Chars) <= 50, "{piece}");
            assert!(!piece.starts_with(' '));
        }
        let joined: String = split(&"x".repeat(250), 100, LenUnit::Chars).concat();
        assert_eq!(joined, "x".repeat(250), "no break point: hard cut, nothing lost");
    }

    #[test]
    fn utf16_units_and_fences() {
        let emoji = "😀".repeat(60); // 120 UTF-16 units
        for p in split(&emoji, 50, LenUnit::Utf16) {
            assert!(len(&p, LenUnit::Utf16) <= 50);
        }
        let code = format!("intro\n```rust\n{}\n```\nouter", "let x = 1;\n".repeat(30));
        let parts = split(&code, 120, LenUnit::Chars);
        assert!(parts.len() > 2);
        for p in &parts {
            assert_eq!(p.matches("```").count() % 2, 0, "balanced fences in {p:?}");
            assert!(len(p, LenUnit::Chars) <= 120);
        }
        assert!(parts[1].starts_with("```rust"), "reopened with language: {:?}", parts[1]);
    }
}
