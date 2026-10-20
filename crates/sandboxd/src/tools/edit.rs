//! Exact-string edit with tolerant matching.
//! MARK: M12 — transcribed by dsh; see marks/M12-edit.md.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditOutcome {
    /// Full new file content, with the file's original line endings and BOM preserved.
    pub content: String,
    pub replacements: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EditError {
    #[error("old_string must not be empty")]
    EmptyOldString,
    #[error("old_string and new_string are identical")]
    NoChange,
    #[error("old_string not found")]
    NotFound,
    #[error("old_string matches {0} locations; add context or set replace_all")]
    Ambiguous(usize),
}

/// Replace `old` with `new` in `content`. Matching tiers, first hit wins:
/// exact -> unicode-normalized -> per-line trailing-whitespace-insensitive.
pub fn apply_edit(
    content: &str,
    old: &str,
    new: &str,
    replace_all: bool,
) -> Result<EditOutcome, EditError> {
    if old.is_empty() {
        return Err(EditError::EmptyOldString);
    }
    if old == new {
        return Err(EditError::NoChange);
    }

    // Keep BOM handling out of the match itself, like the reference does: the
    // BOM is metadata, and at most one is emitted on write.
    let (source, original_bom) = split_bom(content);
    // Strings that differ only in `\r` ask to change line endings themselves,
    // so those edits apply to the exact bytes.
    let endings_only = old.replace('\r', "") == new.replace('\r', "");
    let matches = if endings_only {
        find_occurrences(source, old)
    } else {
        find_matches(source, old)
    };

    if matches.is_empty() {
        return Err(EditError::NotFound);
    }
    if matches.len() > 1 && !replace_all {
        return Err(EditError::Ambiguous(matches.len()));
    }

    let replacement = new.replace("\r\n", "\n");
    let file_ending = line_ending(source, "\n");
    let selected = if replace_all {
        matches.as_slice()
    } else {
        &matches[..1]
    };
    let mut replaced = source.to_owned();
    for range in selected.iter().rev() {
        let text = if endings_only {
            new.to_owned()
        } else {
            let region = &source[range.start..range.end];
            with_region_endings(region, &replacement, line_ending(region, file_ending))
        };
        replaced.replace_range(range.start..range.end, &text);
    }

    if replaced == source {
        return Err(EditError::NoChange);
    }

    let replacement_bom = replaced.starts_with('\u{FEFF}');
    let content = join_bom(&replaced, original_bom || replacement_bom);
    Ok(EditOutcome {
        content,
        replacements: matches.len(),
    })
}

#[derive(Debug, Clone, Copy)]
struct Match {
    start: usize,
    end: usize,
}

/// Replace typographic quotes, dashes and spaces with their ASCII equivalents.
fn normalize_char(character: char) -> Option<char> {
    match character {
        '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}' => Some('\''),
        '\u{201C}' | '\u{201D}' | '\u{201E}' | '\u{201F}' => Some('"'),
        '\u{2010}'..='\u{2015}' | '\u{2212}' => Some('-'),
        '\u{00A0}' | '\u{2002}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}' => Some(' '),
        _ => None,
    }
}

fn normalize_for_match(value: &str) -> String {
    value
        .chars()
        .map(|character| normalize_char(character).unwrap_or(character))
        .collect()
}

/// Normalize while recording, for every byte boundary in the result, the
/// corresponding byte boundary in `value`. Normalization changes UTF-8 byte
/// lengths, so normalized-match offsets cannot be used on the original text
/// without this map.
fn normalize_with_map(value: &str) -> (String, Vec<usize>) {
    let mut normalized = String::with_capacity(value.len());
    let mut map = Vec::with_capacity(value.len() + 1);
    for (start, character) in value.char_indices() {
        let replacement = normalize_char(character).unwrap_or(character);
        let out_start = normalized.len();
        debug_assert_eq!(map.len(), out_start);
        normalized.push(replacement);
        map.push(start);
        for _ in 1..replacement.len_utf8() {
            map.push(start);
        }
    }
    map.push(value.len());
    (normalized, map)
}

fn find_occurrences(content: &str, search: &str) -> Vec<Match> {
    if search.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut offset = 0;
    while let Some(relative) = content[offset..].find(search) {
        let start = offset + relative;
        let end = start + search.len();
        result.push(Match { start, end });
        offset = end;
    }
    result
}

struct LineMatch<'a> {
    start: usize,
    end: usize,
    text: &'a str,
    content_end: usize,
    newline: bool,
}

fn lines(content: &str) -> Vec<LineMatch<'_>> {
    let mut result = Vec::new();
    let mut start = 0;
    for segment in content.split_inclusive('\n') {
        let end = start + segment.len();
        let newline = segment.ends_with('\n');
        let text = if newline {
            &segment[..segment.len() - 1]
        } else {
            segment
        };
        let content_end = start + text.len() - usize::from(text.ends_with('\r'));
        result.push(LineMatch {
            start,
            end,
            text,
            content_end,
            newline,
        });
        start = end;
    }
    result
}

/// Line-based fallback: compare each line after trimming trailing whitespace
/// and normalizing typography. Overlapping candidates keep the first one.
fn find_line_occurrences(content: &str, search: &str) -> Vec<Match> {
    let trailing_newline = search.ends_with('\n');
    let mut expected = search.split('\n').collect::<Vec<_>>();
    if trailing_newline {
        expected.pop();
    }
    let lines = lines(content);
    let mut result: Vec<Match> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let end_index = index + expected.len();
        if end_index > lines.len() {
            continue;
        }
        let actual = &lines[index..end_index];
        let same = actual.iter().zip(expected.iter()).all(|(item, expected)| {
            normalize_for_match(item.text.trim_end()) == normalize_for_match(expected.trim_end())
        });
        if !same {
            continue;
        }
        let last = &actual[actual.len() - 1];
        if trailing_newline && !last.newline {
            continue;
        }
        let candidate = Match {
            start: line.start,
            end: if trailing_newline {
                last.end
            } else {
                last.content_end
            },
        };
        if result
            .iter()
            .any(|found| found.end > candidate.start && found.start < candidate.end)
        {
            continue;
        }
        result.push(candidate);
    }
    result
}

/// The dominant line ending in `text`, or `fallback` when there is none/tied.
fn line_ending<'a>(text: &str, fallback: &'a str) -> &'a str {
    let crlf_count = text.match_indices("\r\n").count();
    let lf_count = text.match_indices('\n').count().saturating_sub(crlf_count);
    if crlf_count == lf_count {
        fallback
    } else if crlf_count > lf_count {
        "\r\n"
    } else {
        "\n"
    }
}

/// Split a region the way `/\r?\n/` does, keeping each line's own ending.
fn split_region(region: &str) -> (Vec<&str>, Vec<&str>) {
    let bytes = region.as_bytes();
    let mut lines = Vec::new();
    let mut endings = Vec::new();
    let mut start = 0;
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'\n' {
            continue;
        }
        let mut end = index;
        let ending = if end > start && bytes[end - 1] == b'\r' {
            end -= 1;
            "\r\n"
        } else {
            "\n"
        };
        lines.push(&region[start..end]);
        endings.push(ending);
        start = index + 1;
    }
    lines.push(&region[start..]);
    (lines, endings)
}

fn flush_alignment(result: &mut [Option<usize>], before: &mut Vec<usize>, after: &mut Vec<usize>) {
    for (index, line) in after.iter().enumerate() {
        result[*line] = before.get(index).copied();
    }
    before.clear();
    after.clear();
}

/// For each replacement line, the source line it keeps (via LCS) or, between
/// kept lines, the line it takes the place of.
fn align_lines(before: &[String], after: &[String]) -> Vec<Option<usize>> {
    let width = after.len() + 1;
    let mut table = vec![0u32; (before.len() + 1) * width];
    let mut i = before.len();
    while i > 0 {
        i -= 1;
        let mut j = after.len();
        while j > 0 {
            j -= 1;
            table[i * width + j] = if before[i] == after[j] {
                table[(i + 1) * width + j + 1] + 1
            } else {
                table[(i + 1) * width + j].max(table[i * width + j + 1])
            };
        }
    }

    let mut result = vec![None; after.len()];
    let mut gap_before = Vec::new();
    let mut gap_after = Vec::new();
    let mut i = 0;
    let mut j = 0;
    while i < before.len() && j < after.len() {
        if before[i] == after[j] {
            flush_alignment(&mut result, &mut gap_before, &mut gap_after);
            result[j] = Some(i);
            i += 1;
            j += 1;
        } else if table[(i + 1) * width + j] >= table[i * width + j + 1] {
            gap_before.push(i);
            i += 1;
        } else {
            gap_after.push(j);
            j += 1;
        }
    }
    while i < before.len() {
        gap_before.push(i);
        i += 1;
    }
    while j < after.len() {
        gap_after.push(j);
        j += 1;
    }
    flush_alignment(&mut result, &mut gap_before, &mut gap_after);
    result
}

/// Join replacement lines with endings taken from the matched source region.
/// Kept and in-place lines reuse their source line's ending; extra lines take
/// `fallback`.
fn with_region_endings(region: &str, replacement: &str, fallback: &str) -> String {
    let (before, endings) = split_region(region);
    let after = replacement.split('\n').collect::<Vec<_>>();
    let before_keys = before
        .iter()
        .map(|line| normalize_for_match(line.trim_end()))
        .collect::<Vec<_>>();
    let after_keys = after
        .iter()
        .map(|line| normalize_for_match(line.trim_end()))
        .collect::<Vec<_>>();
    let source = align_lines(&before_keys, &after_keys);
    let mut result = String::new();
    for (index, line) in after.iter().enumerate() {
        result.push_str(line);
        if index + 1 == after.len() {
            break;
        }
        let ending = source
            .get(index)
            .copied()
            .flatten()
            .and_then(|source_index| endings.get(source_index).copied())
            .unwrap_or(fallback);
        result.push_str(ending);
    }
    result
}

/// Number of sorted positions strictly before `offset`.
fn count_before(positions: &[usize], offset: usize) -> usize {
    positions.partition_point(|position| *position < offset)
}

fn removed_positions(source: &str) -> Vec<usize> {
    source
        .match_indices("\r\n")
        .enumerate()
        .map(|(index, (start, _))| start - index)
        .collect()
}

/// Match on the LF view and map offsets back to source bytes. The view is
/// what Read shows the model; CRLF differences neither block matches nor leak
/// into untouched regions.
fn find_matches(source: &str, old: &str) -> Vec<Match> {
    let view = source.replace("\r\n", "\n");
    let search = old.replace("\r\n", "\n");
    let exact = find_occurrences(&view, &search);
    let view_matches = if !exact.is_empty() {
        exact
    } else {
        let (normalized_view, map) = normalize_with_map(&view);
        let normalized_search = normalize_for_match(&search);
        let normalized = find_occurrences(&normalized_view, &normalized_search)
            .into_iter()
            .map(|found| Match {
                start: map[found.start],
                end: map[found.end],
            })
            .collect::<Vec<_>>();
        if normalized.is_empty() {
            find_line_occurrences(&view, &search)
        } else {
            normalized
        }
    };

    let removed = removed_positions(source);
    view_matches
        .into_iter()
        .map(|found| Match {
            start: found.start + count_before(&removed, found.start),
            end: found.end + count_before(&removed, found.end),
        })
        .collect()
}

fn split_bom(text: &str) -> (&str, bool) {
    let without = text.trim_start_matches('\u{FEFF}');
    (without, without.len() != text.len())
}

fn join_bom(text: &str, bom: bool) -> String {
    let without = text.trim_start_matches('\u{FEFF}');
    if bom {
        format!("\u{FEFF}{without}")
    } else {
        without.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(content: &str, old: &str, new: &str) -> Result<EditOutcome, EditError> {
        apply_edit(content, old, new, false)
    }

    fn edit_all(content: &str, old: &str, new: &str) -> Result<EditOutcome, EditError> {
        apply_edit(content, old, new, true)
    }

    fn edited(content: &str, old: &str, new: &str) -> String {
        edit(content, old, new)
            .expect("edit should succeed")
            .content
    }

    #[test]
    fn rejects_empty_noop_missing_and_ambiguous_edits() {
        assert_eq!(edit("abc", "", "x"), Err(EditError::EmptyOldString));
        assert_eq!(edit("abc", "abc", "abc"), Err(EditError::NoChange));
        assert_eq!(edit("abc", "missing", "x"), Err(EditError::NotFound));
        assert_eq!(
            edit("same same", "same", "after"),
            Err(EditError::Ambiguous(2))
        );
    }

    #[test]
    fn replaces_an_exact_single_occurrence() {
        let outcome = edit("before\nrest\n", "before", "after").expect("exact match");
        assert_eq!(
            outcome,
            EditOutcome {
                content: "after\nrest\n".to_owned(),
                replacements: 1
            }
        );
    }

    #[test]
    fn replace_all_replaces_every_exact_occurrence() {
        let outcome = edit_all("same same same", "same", "after").expect("exact matches");
        assert_eq!(
            outcome,
            EditOutcome {
                content: "after after after".to_owned(),
                replacements: 3
            }
        );
    }

    #[test]
    fn exact_matching_wins_before_unicode_normalization() {
        let outcome = edit(
            "exact - match\nexact − match\n",
            "exact - match",
            "selected",
        )
        .expect("exact match");
        assert_eq!(outcome.content, "selected\nexact − match\n");
    }

    #[test]
    fn normalizes_typographic_quotes_dashes_and_spaces() {
        let content =
            "exact - match\ncurly “quotes”\nminus − one\nspace\u{00A0}here\nexact − match\n";
        let outcome = edit(
            content,
            "curly \"quotes\"\nminus - one\nspace here",
            "normalized",
        )
        .expect("unicode match");
        assert_eq!(
            outcome.content,
            "exact - match\nnormalized\nexact − match\n"
        );
        assert_eq!(
            edited(&outcome.content, "exact - match", "selected"),
            "selected\nnormalized\nexact − match\n"
        );
    }

    #[test]
    fn ignores_trailing_whitespace_only_on_the_fallback_tier() {
        let content = "before  \nmatch  \nnext\t\nafter  \n";
        assert_eq!(
            edited(content, "match\nnext", "changed"),
            "before  \nchanged\nafter  \n"
        );
    }

    #[test]
    fn trailing_whitespace_matches_do_not_overlap_and_preserve_crlf() {
        let overlap = edit_all("a  \na  \na  \n", "a\na", "x").expect("one non-overlapping match");
        assert_eq!(overlap.replacements, 1);
        assert_eq!(overlap.content, "x\na  \n");
        assert_eq!(edited("a  \r\nb\t\r\n", "a\nb", "x"), "x\r\n");
    }

    #[test]
    fn preserves_crlf_and_bom() {
        let outcome =
            edit("\u{FEFF}before\r\nrest\r\n", "before\nrest", "after\nrest").expect("crlf match");
        assert_eq!(outcome.content, "\u{FEFF}after\r\nrest\r\n");
        assert_eq!(
            edited("first\r\nsecond\r\n", "second", "changed"),
            "first\r\nchanged\r\n"
        );
    }

    #[test]
    fn matches_across_mixed_line_endings_and_keeps_each_region_ending() {
        let mut content = edited(
            "head\r\nAAA OLD BBB\ntail\n",
            "AAA OLD BBB",
            "AAA NEW\nLINE2",
        );
        assert_eq!(content, "head\r\nAAA NEW\nLINE2\ntail\n");
        content = edited(&content, "LINE2\ntail", "LINE2\nTAIL");
        assert_eq!(content, "head\r\nAAA NEW\nLINE2\nTAIL\n");

        let mut content = edited(
            "one\r\ntwo\r\nthree\nfour\r\n",
            "o\nthree\nfo",
            "O\nTHREE\nFO",
        );
        assert_eq!(content, "one\r\ntwO\r\nTHREE\nFOur\r\n");
        content = edited(&content, "one", "ONE\nUNO");
        assert_eq!(content, "ONE\r\nUNO\r\ntwO\r\nTHREE\nFOur\r\n");
    }

    #[test]
    fn keeps_unchanged_and_in_place_line_endings_inside_a_multiline_match() {
        let content = "All(item.Sku);\r\n\r\nFind(sku);\r\n\r\nvoid Add()\n{\n  _items[item.Sku] = item;\n}\r\n";
        let old = "All(item.Sku);\n\nFind(sku);\n\nvoid Add()\n{\n  _items[item.Sku] = item;\n}";
        let new = "All(item.Code);\n\nFind(code);\n\nvoid Add()\n{\n  _items[item.Code] = item;\n}\n\nbool Remove(string code)\n{\n}";
        assert_eq!(
            edited(content, old, new),
            "All(item.Code);\r\n\r\nFind(code);\r\n\r\nvoid Add()\n{\n  _items[item.Code] = item;\n}\r\n\r\nbool Remove(string code)\r\n{\r\n}\r\n"
        );
    }

    #[test]
    fn applies_cr_only_differences_to_exact_bytes() {
        let stripped = edit_all("a\r\nb\r\n", "\r", "").expect("strip carriage returns");
        assert_eq!(
            stripped,
            EditOutcome {
                content: "a\nb\n".to_owned(),
                replacements: 2
            }
        );
        assert_eq!(edited("x\r\ny\r\n", "x\r\ny\r\n", "x\ny\n"), "x\ny\n");
        let added = edited("p\nq\n", "p\nq", "p\r\nq");
        assert_eq!(added, "p\r\nq\n");
        assert_eq!(edit(&added, "p\nq", "p\r\nq"), Err(EditError::NotFound));
        assert_eq!(edit("p\nq\n", "p\r\nq", "p\nq"), Err(EditError::NotFound));
    }

    #[test]
    fn fails_when_a_tolerant_match_leaves_the_file_unchanged() {
        assert_eq!(
            edit("it’s here\n", "it's here", "it’s here"),
            Err(EditError::NoChange)
        );
    }

    #[test]
    fn handles_multibyte_content_offsets() {
        let outcome =
            edit("你好世界\n第二行\r\n", "世界\n第二行", "地球\n第三行").expect("multibyte match");
        assert_eq!(outcome.content, "你好地球\n第三行\r\n");
        assert_eq!(outcome.replacements, 1);
    }

    #[test]
    fn matches_a_search_that_ends_with_a_line_ending() {
        assert_eq!(edited("a\nb\nc\n", "a\nb\n", "x\n"), "x\nc\n");
        assert_eq!(
            edit("a\nb\nc\n", "a\nb\n", "x\n"),
            Ok(EditOutcome {
                content: "x\nc\n".to_owned(),
                replacements: 1
            })
        );
    }
}
