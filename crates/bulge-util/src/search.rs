//! Search terms for the full-text indexes (lessons, chat archive): Latin
//! words lowercased, CJK runs as overlapping bigrams, so Chinese text is
//! searchable without a segmenter.

fn is_cjk(c: char) -> bool {
    matches!(c as u32,
        0x3040..=0x30FF   // Hiragana, Katakana
        | 0x3400..=0x4DBF // CJK Extension A
        | 0x4E00..=0x9FFF // CJK Unified Ideographs
        | 0xAC00..=0xD7AF // Hangul syllables
        | 0xF900..=0xFAFF // CJK Compatibility Ideographs
        | 0x20000..=0x2FFFF)
}

/// Index terms for `text`: lowercase Latin/digit words, and CJK runs split into
/// overlapping bigrams (a lone CJK character is its own term).
pub fn terms(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut run: Vec<char> = Vec::new();
    let flush_run = |run: &mut Vec<char>, out: &mut Vec<String>| {
        match run.len() {
            0 => {}
            1 => out.push(run[0].to_string()),
            _ => out.extend(run.windows(2).map(|pair| pair.iter().collect::<String>())),
        }
        run.clear();
    };
    for c in text.chars() {
        if is_cjk(c) {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            run.push(c);
        } else if c.is_alphanumeric() {
            flush_run(&mut run, &mut out);
            word.extend(c.to_lowercase());
        } else {
            flush_run(&mut run, &mut out);
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
        }
    }
    flush_run(&mut run, &mut out);
    if !word.is_empty() {
        out.push(word);
    }
    out
}

/// An FTS5 query matching any of the query's terms (each quoted, so no term is
/// read as FTS syntax). `None` when the query has no terms.
pub fn match_expression(query: &str) -> Option<String> {
    let mut unique: Vec<String> = Vec::new();
    for term in terms(query) {
        if !unique.contains(&term) {
            unique.push(term);
        }
    }
    (!unique.is_empty()).then(|| unique.iter().map(|t| format!("\"{}\"", t.replace('"', "\"\""))).collect::<Vec<_>>().join(" OR "))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latin_words_and_cjk_bigrams() {
        assert_eq!(terms("Cargo 測試失敗了"), ["cargo", "測試", "試失", "失敗", "敗了"]);
        assert_eq!(terms("單"), ["單"]);
        assert_eq!(match_expression("a \"b a"), Some("\"a\" OR \"b\"".into()));
        assert_eq!(match_expression("!!!"), None);
    }
}
