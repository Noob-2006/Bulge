//! Standalone plain-text tool-call parsing and stripping.
//!
//! MARK: M8 — ported from openclaw `packages/tool-call-repair/src/payload.ts`.
//! Stream projection is intentionally omitted; only static parsing and stripping
//! are kept.

use std::ops::Range;

use serde_json::Value;

use super::grammar::{
    END_TOOL_REQUEST, HARMONY_CALL_MARKER, HARMONY_CHANNEL_MARKER, HARMONY_MESSAGE_MARKER,
    JsonObjectScan, Span, XmlishScan, consume_line_break,
    consume_structural_line_break_after_horizontal_whitespace, is_plain_text_tool_name_char,
    scan_json_object, scan_xmlish_tool_call, skip_horizontal_whitespace, skip_line_indentation,
    skip_whitespace, utf8_byte_length_within_limit,
};

/// Reference default for one serialized payload.
pub(crate) const DEFAULT_MAX_PLAIN_TEXT_TOOL_PAYLOAD_BYTES: usize = 256_000;
const MAX_PLAIN_TEXT_TOOL_NAME_CHARS: usize = 120;
const HARMONY_CHANNELS: [&str; 3] = ["commentary", "analysis", "final"];

/// A tool call recovered from one standalone plain-text block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Block {
    pub name: String,
    /// Compact JSON object text.
    pub arguments: String,
    /// Inclusive start of the block in the source text.
    pub start: usize,
    /// Exclusive end of the block in the source text.
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonSyntax {
    Harmony,
    NamedBracket,
    ToolBracket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JsonCandidate {
    syntax: JsonSyntax,
    name: Span,
    payload: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonToolCallScan {
    Invalid {
        at: usize,
    },
    Prefix {
        candidate: Option<JsonCandidate>,
    },
    Complete {
        candidate: JsonCandidate,
        end: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BlockScan {
    Complete(Block),
    NoMatch { next: usize },
}

fn is_literal_prefix_at(text: &str, start: usize, literal: &str) -> bool {
    text.get(start..)
        .is_some_and(|available| available.len() < literal.len() && literal.starts_with(available))
}

fn scan_tool_name_end(text: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut end = start;
    while bytes
        .get(end)
        .copied()
        .is_some_and(is_plain_text_tool_name_char)
    {
        if end - start == MAX_PLAIN_TEXT_TOOL_NAME_CHARS {
            return None;
        }
        end += 1;
    }
    Some(end)
}

fn candidate(syntax: JsonSyntax, name: Span, payload: Option<Span>) -> JsonCandidate {
    JsonCandidate {
        syntax,
        name,
        payload,
    }
}

fn scan_bracket_opening(text: &str, start: usize) -> JsonToolCallScan {
    let bytes = text.as_bytes();
    let mut cursor = start + 1;
    let mut syntax = JsonSyntax::NamedBracket;
    if text
        .get(cursor..)
        .is_some_and(|rest| rest.starts_with("tool:"))
    {
        syntax = JsonSyntax::ToolBracket;
        cursor += "tool:".len();
    } else if is_literal_prefix_at(text, cursor, "tool:") {
        return JsonToolCallScan::Prefix { candidate: None };
    }
    let name_start = cursor;
    let Some(name_end) = scan_tool_name_end(text, name_start) else {
        return JsonToolCallScan::Invalid {
            at: name_start + MAX_PLAIN_TEXT_TOOL_NAME_CHARS,
        };
    };
    let name = Span {
        start: name_start,
        end: name_end,
    };
    cursor = name_end;
    if cursor == bytes.len() {
        return JsonToolCallScan::Prefix {
            candidate: (name_start != name_end).then(|| candidate(syntax, name, None)),
        };
    }
    if name_start == name_end || bytes[cursor] != b']' {
        return JsonToolCallScan::Invalid { at: cursor };
    }
    cursor += 1;
    let value = candidate(syntax, name, None);
    if syntax == JsonSyntax::NamedBracket {
        let horizontal_end = skip_horizontal_whitespace(text, cursor);
        if horizontal_end == bytes.len() {
            return JsonToolCallScan::Prefix {
                candidate: Some(value),
            };
        }
        let Some(after_line_break) =
            consume_structural_line_break_after_horizontal_whitespace(text, cursor)
        else {
            return JsonToolCallScan::Invalid { at: horizontal_end };
        };
        cursor = after_line_break;
    }
    JsonToolCallScan::Complete {
        candidate: value,
        end: cursor,
    }
}

fn scan_harmony_opening(text: &str, start: usize) -> JsonToolCallScan {
    let bytes = text.as_bytes();
    let mut cursor = start;
    if text
        .get(cursor..)
        .is_some_and(|rest| rest.starts_with(HARMONY_CHANNEL_MARKER))
    {
        cursor += HARMONY_CHANNEL_MARKER.len();
    } else if is_literal_prefix_at(text, cursor, HARMONY_CHANNEL_MARKER) {
        return JsonToolCallScan::Prefix { candidate: None };
    } else if bytes.get(cursor) == Some(&b'<') {
        return JsonToolCallScan::Invalid { at: cursor };
    }

    let Some(channel) = HARMONY_CHANNELS.iter().find(|channel| {
        text.get(cursor..)
            .is_some_and(|rest| rest.starts_with(**channel))
    }) else {
        return if HARMONY_CHANNELS
            .iter()
            .any(|channel| is_literal_prefix_at(text, cursor, channel))
        {
            JsonToolCallScan::Prefix { candidate: None }
        } else {
            JsonToolCallScan::Invalid { at: cursor }
        };
    };
    cursor += channel.len();
    if cursor == bytes.len() {
        return JsonToolCallScan::Prefix { candidate: None };
    }
    if bytes[cursor] != b' ' && bytes[cursor] != b'\t' {
        return JsonToolCallScan::Invalid { at: cursor };
    }
    cursor = skip_horizontal_whitespace(text, cursor);
    if text
        .get(cursor..)
        .is_none_or(|rest| !rest.starts_with("to="))
    {
        return if is_literal_prefix_at(text, cursor, "to=") {
            JsonToolCallScan::Prefix { candidate: None }
        } else {
            JsonToolCallScan::Invalid { at: cursor }
        };
    }
    cursor += "to=".len();

    let name_start = cursor;
    let Some(name_end) = scan_tool_name_end(text, name_start) else {
        return JsonToolCallScan::Invalid {
            at: name_start + MAX_PLAIN_TEXT_TOOL_NAME_CHARS,
        };
    };
    let name = Span {
        start: name_start,
        end: name_end,
    };
    cursor = name_end;
    if cursor == bytes.len() {
        return JsonToolCallScan::Prefix {
            candidate: (name_start != name_end).then(|| candidate(JsonSyntax::Harmony, name, None)),
        };
    }
    if name_start == name_end || (bytes[cursor] != b' ' && bytes[cursor] != b'\t') {
        return JsonToolCallScan::Invalid { at: cursor };
    }
    cursor = skip_horizontal_whitespace(text, cursor);
    let value = candidate(JsonSyntax::Harmony, name, None);
    if text
        .get(cursor..)
        .is_none_or(|rest| !rest.starts_with("code"))
    {
        return if is_literal_prefix_at(text, cursor, "code") {
            JsonToolCallScan::Prefix {
                candidate: Some(value),
            }
        } else {
            JsonToolCallScan::Invalid { at: cursor }
        };
    }
    cursor = skip_whitespace(text, cursor + "code".len());
    if text
        .get(cursor..)
        .is_some_and(|rest| rest.starts_with(HARMONY_MESSAGE_MARKER))
    {
        cursor = skip_whitespace(text, cursor + HARMONY_MESSAGE_MARKER.len());
    } else if is_literal_prefix_at(text, cursor, HARMONY_MESSAGE_MARKER) {
        return JsonToolCallScan::Prefix {
            candidate: Some(value),
        };
    } else if bytes.get(cursor) == Some(&b'<') {
        return JsonToolCallScan::Invalid { at: cursor };
    }
    JsonToolCallScan::Complete {
        candidate: value,
        end: cursor,
    }
}

/// Scans a bracket- or Harmony-prefixed JSON tool call.
fn scan_plain_text_json_tool_call(text: &str, start: usize) -> JsonToolCallScan {
    let bytes = text.as_bytes();
    let opening = if bytes.get(start) == Some(&b'[') {
        scan_bracket_opening(text, start)
    } else {
        scan_harmony_opening(text, start)
    };
    let (value, cursor) = match opening {
        JsonToolCallScan::Complete { candidate, end } => (candidate, end),
        other => return other,
    };

    let payload_start = skip_whitespace(text, cursor);
    if payload_start == bytes.len() {
        return JsonToolCallScan::Prefix {
            candidate: Some(value),
        };
    }
    if bytes[payload_start] != b'{' {
        return JsonToolCallScan::Invalid { at: payload_start };
    }

    let json = scan_json_object(text, payload_start);
    let payload = Span {
        start: payload_start,
        end: json_end(&json),
    };
    if matches!(json, JsonObjectScan::Prefix { .. }) {
        return JsonToolCallScan::Prefix {
            candidate: Some(candidate(value.syntax, value.name, Some(payload))),
        };
    }

    let closing_candidate = candidate(value.syntax, value.name, Some(payload));
    let named_bracket = value.syntax == JsonSyntax::NamedBracket;
    let closing_start = skip_whitespace(text, payload.end);
    if named_bracket && closing_start == bytes.len() {
        return JsonToolCallScan::Prefix {
            candidate: Some(closing_candidate),
        };
    }
    let name = &text[value.name.start..value.name.end];
    let closing_suffix = format!("[/{name}]");
    let closings: &[&str] = if named_bracket {
        &[END_TOOL_REQUEST, closing_suffix.as_str()]
    } else {
        &[
            HARMONY_CALL_MARKER,
            END_TOOL_REQUEST,
            closing_suffix.as_str(),
        ]
    };
    for closing in closings {
        if text
            .get(closing_start..)
            .is_some_and(|rest| rest.starts_with(closing))
        {
            let end = closing_start + closing.len();
            return JsonToolCallScan::Complete {
                candidate: closing_candidate,
                end,
            };
        }
        if closing_start < bytes.len() && is_literal_prefix_at(text, closing_start, closing) {
            return JsonToolCallScan::Prefix {
                candidate: Some(closing_candidate),
            };
        }
    }
    if named_bracket {
        JsonToolCallScan::Invalid { at: closing_start }
    } else {
        JsonToolCallScan::Complete {
            candidate: closing_candidate,
            end: payload.end,
        }
    }
}

fn json_end(scan: &JsonObjectScan) -> usize {
    match scan {
        JsonObjectScan::Complete { end } | JsonObjectScan::Prefix { end } => *end,
    }
}

fn parse_json_arguments(text: &str, payload: Span) -> Option<String> {
    let raw = text.get(payload.start..payload.end)?;
    let value: Value = serde_json::from_str(raw).ok()?;
    value.is_object().then(|| compact_json_object(raw))
}

/// Removes JSON whitespace outside strings while preserving key order and values.
fn compact_json_object(raw: &str) -> String {
    let mut output = String::with_capacity(raw.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in raw.chars() {
        if in_string {
            output.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            in_string = true;
            output.push(ch);
        } else if !matches!(ch, ' ' | '\t' | '\r' | '\n') {
            output.push(ch);
        }
    }
    output
}

fn extract_xmlish_parameter_value(text: &str, start: usize, end: usize) -> String {
    let value = &text[start..end];
    let Some(payload_start) = consume_line_break(value, 0) else {
        return value.to_owned();
    };
    let mut extracted = value[payload_start..].to_owned();
    if extracted.ends_with("\r\n") {
        extracted.truncate(extracted.len() - 2);
    } else if extracted.ends_with(['\r', '\n']) {
        extracted.truncate(extracted.len() - 1);
    }
    extracted
}

fn names_allow(allowed: Option<&[String]>, name: &str) -> bool {
    allowed.is_none_or(|names| names.iter().any(|allowed| allowed == name))
}

fn json_block(
    text: &str,
    start: usize,
    candidate: &JsonCandidate,
    end: usize,
    allowed: Option<&[String]>,
    max_payload_bytes: usize,
) -> Option<Block> {
    let payload = candidate.payload?;
    let name = text.get(candidate.name.start..candidate.name.end)?;
    if !names_allow(allowed, name)
        || utf8_byte_length_within_limit(text, payload.start, payload.end, max_payload_bytes)
            .is_none()
    {
        return None;
    }
    let arguments = parse_json_arguments(text, payload)?;
    Some(Block {
        name: name.to_owned(),
        arguments,
        start,
        end,
    })
}

fn xmlish_block(
    text: &str,
    start: usize,
    candidate: &super::grammar::XmlishCandidate,
    end: usize,
    allowed: Option<&[String]>,
    max_payload_bytes: usize,
) -> Option<Block> {
    let payload = candidate.payload?;
    let name = text.get(candidate.name.start..candidate.name.end)?;
    if !names_allow(allowed, name)
        || utf8_byte_length_within_limit(text, payload.start, payload.end, max_payload_bytes)
            .is_none()
    {
        return None;
    }
    let mut parameters: Vec<(String, String)> = Vec::new();
    for parameter in &candidate.parameters {
        let name = text
            .get(parameter.name.start..parameter.name.end)?
            .to_owned();
        let value =
            extract_xmlish_parameter_value(text, parameter.value.start, parameter.value.end);
        if let Some(existing) = parameters
            .iter_mut()
            .find(|(existing, _)| existing == &name)
        {
            existing.1 = value;
        } else {
            parameters.push((name, value));
        }
    }
    let mut arguments = String::from("{");
    for (index, (name, value)) in parameters.iter().enumerate() {
        if index > 0 {
            arguments.push(',');
        }
        arguments.push_str(&serde_json::to_string(name).ok()?);
        arguments.push(':');
        arguments.push_str(&serde_json::to_string(&Value::String(value.clone())).ok()?);
    }
    arguments.push('}');
    Some(Block {
        name: name.to_owned(),
        arguments,
        start,
        end,
    })
}

fn json_next(scan: &JsonToolCallScan, text_len: usize) -> usize {
    match scan {
        JsonToolCallScan::Complete { end, .. } => *end,
        JsonToolCallScan::Invalid { at } => *at,
        JsonToolCallScan::Prefix { .. } => text_len,
    }
}

fn xmlish_next(scan: &XmlishScan, text_len: usize) -> usize {
    match scan {
        XmlishScan::Complete { end, .. } => *end,
        XmlishScan::Invalid { at } => *at,
        XmlishScan::Prefix { .. } => text_len,
    }
}

/// Classifies one JSON/XML call candidate at `start` and reports scan progress.
pub(crate) fn scan_block_at(
    text: &str,
    start: usize,
    allowed: Option<&[String]>,
    max_payload_bytes: usize,
) -> BlockScan {
    let json = scan_plain_text_json_tool_call(text, start);
    let xmlish = scan_xmlish_tool_call(text, start);

    if let JsonToolCallScan::Complete { candidate, end } = &json
        && let Some(block) = json_block(text, start, candidate, *end, allowed, max_payload_bytes)
    {
        return BlockScan::Complete(block);
    }
    if let XmlishScan::Complete { candidate, end } = &xmlish
        && let Some(block) = xmlish_block(text, start, candidate, *end, allowed, max_payload_bytes)
    {
        return BlockScan::Complete(block);
    }

    let next = start
        .saturating_add(1)
        .max(json_next(&json, text.len()))
        .max(xmlish_next(&xmlish, text.len()))
        .min(text.len());
    BlockScan::NoMatch { next }
}

/// Parses every standalone block in `text`; any surrounding prose means no block.
pub(crate) fn parse_standalone_plain_text_tool_call_blocks(
    text: &str,
    allowed: Option<&[String]>,
    max_payload_bytes: usize,
) -> Option<Vec<Block>> {
    let mut blocks = Vec::new();
    let mut cursor = skip_whitespace(text, 0);
    while cursor < text.len() {
        let BlockScan::Complete(block) = scan_block_at(text, cursor, allowed, max_payload_bytes)
        else {
            return None;
        };
        cursor = skip_whitespace(text, block.end);
        blocks.push(block);
    }
    (!blocks.is_empty()).then_some(blocks)
}

fn fenced_ranges(text: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let backtick = text[cursor..].find("```").map(|offset| cursor + offset);
        let tilde = text[cursor..].find("~~~").map(|offset| cursor + offset);
        let start = match (backtick, tilde) {
            (Some(left), Some(right)) => left.min(right),
            (Some(index), None) | (None, Some(index)) => index,
            (None, None) => break,
        };
        let marker = if text[start..].starts_with("```") {
            "```"
        } else {
            "~~~"
        };
        let search_from = start + marker.len();
        let end = text[search_from..]
            .find(marker)
            .map_or(text.len(), |offset| search_from + offset + marker.len());
        ranges.push(start..end);
        cursor = end;
    }
    ranges
}

fn is_offset_protected(ranges: &[Range<usize>], offset: usize) -> bool {
    ranges
        .iter()
        .any(|range| offset >= range.start && offset < range.end)
}

fn is_line_start(text: &str, index: usize) -> bool {
    index == 0
        || index >= text.len()
        || text
            .as_bytes()
            .get(index - 1)
            .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
}

fn next_line_start(text: &str, from: usize) -> usize {
    let bytes = text.as_bytes();
    let mut index = from;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => return index + 1,
            b'\r' => {
                return if bytes.get(index + 1) == Some(&b'\n') {
                    index + 2
                } else {
                    index + 1
                };
            }
            _ => index += 1,
        }
    }
    text.len()
}

fn line_start_at_or_after(text: &str, from: usize) -> usize {
    if from >= text.len() {
        text.len()
    } else if is_line_start(text, from) {
        from
    } else {
        next_line_start(text, from)
    }
}

/// Removes every full-line standalone call from `text` and returns the removed
/// blocks in source order. Fenced code is protected and left untouched.
pub(crate) fn strip_plain_text_tool_call_blocks(
    text: &str,
    allowed: Option<&[String]>,
    max_payload_bytes: usize,
) -> (Vec<Block>, String) {
    let protected = fenced_ranges(text);
    let mut blocks = Vec::new();
    let mut removals: Vec<Range<usize>> = Vec::new();
    let mut index = 0;

    while index < text.len() {
        if is_offset_protected(&protected, index) {
            index = next_line_start(text, index + 1);
            continue;
        }
        let block_start = skip_line_indentation(text, index);
        if block_start >= text.len() {
            break;
        }
        if is_offset_protected(&protected, block_start) {
            index = next_line_start(text, index + 1);
            continue;
        }

        let first_block = match scan_block_at(text, block_start, allowed, max_payload_bytes) {
            BlockScan::Complete(block) => block,
            BlockScan::NoMatch { next } => {
                index = line_start_at_or_after(text, next.max(index + 1));
                continue;
            }
        };

        let mut last_end = first_block.end;
        let mut sequence = vec![first_block];
        loop {
            let adjacent = skip_line_indentation(text, last_end);
            if adjacent >= text.len()
                || is_offset_protected(&protected, adjacent)
                || consume_line_break(text, adjacent).is_some()
            {
                break;
            }
            match scan_block_at(text, adjacent, allowed, max_payload_bytes) {
                BlockScan::Complete(block) if block.end > last_end => {
                    last_end = block.end;
                    sequence.push(block);
                }
                _ => break,
            }
        }

        let line_break_start = skip_line_indentation(text, last_end);
        let removal_end = if line_break_start == text.len() {
            line_break_start
        } else {
            consume_line_break(text, line_break_start).unwrap_or(last_end)
        };
        removals.push(index..removal_end);
        blocks.extend(sequence);
        index = line_start_at_or_after(text, removal_end.max(index + 1));
    }

    let mut output = String::with_capacity(text.len());
    let mut cursor = 0;
    for removal in removals {
        if removal.start > cursor {
            output.push_str(&text[cursor..removal.start]);
        }
        cursor = cursor.max(removal.end);
    }
    output.push_str(&text[cursor..]);
    (blocks, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    fn strip(text: &str) -> String {
        strip_plain_text_tool_call_blocks(text, None, DEFAULT_MAX_PLAIN_TEXT_TOOL_PAYLOAD_BYTES).1
    }

    #[test]
    fn returns_a_complete_harmony_call_before_a_visible_suffix() {
        let raw =
            r#"<|channel|>commentary to=read code<|message|>{"path":"/tmp/file"}<|call|>visible"#;
        let JsonToolCallScan::Complete { candidate, end } = scan_plain_text_json_tool_call(raw, 0)
        else {
            panic!("expected a complete harmony call");
        };
        assert_eq!(end, raw.find("visible").expect("suffix"));
        assert_eq!(&raw[candidate.name.start..candidate.name.end], "read");
        let payload = candidate.payload.expect("payload");
        assert_eq!(payload.start, raw.find('{').expect("object"));
        assert_eq!(payload.end, raw.find('}').expect("object") + 1);
    }

    #[test]
    fn classifies_the_streaming_harmony_prefix() {
        let raw = "commentary to=read co";
        let JsonToolCallScan::Prefix {
            candidate: Some(candidate),
        } = scan_plain_text_json_tool_call(raw, 0)
        else {
            panic!("expected a harmony prefix");
        };
        assert_eq!(candidate.syntax, JsonSyntax::Harmony);
        assert_eq!(&raw[candidate.name.start..candidate.name.end], "read");
        assert_eq!(candidate.name.start, 14);
        assert_eq!(candidate.name.end, 18);
    }

    #[test]
    fn accepts_120_character_names_and_rejects_the_121st() {
        for build in [
            |name: &str| format!("[{name}]\n{{}}[/{name}]"),
            |name: &str| format!("analysis to={name} code {{}}"),
        ] {
            assert!(matches!(
                scan_plain_text_json_tool_call(&build(&"x".repeat(120)), 0),
                JsonToolCallScan::Complete { .. }
            ));
            let oversized = build(&"x".repeat(121));
            match scan_plain_text_json_tool_call(&oversized, 0) {
                JsonToolCallScan::Invalid { at } => assert!(at > 0),
                other => panic!("expected invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn parses_standalone_blocks_with_compact_arguments_and_spans() {
        let text = "[read]\n{\"path\":\"/tmp/a\"}\n[/read]";
        let blocks = parse_standalone_plain_text_tool_call_blocks(
            text,
            None,
            DEFAULT_MAX_PLAIN_TEXT_TOOL_PAYLOAD_BYTES,
        )
        .expect("blocks");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].name, "read");
        assert_eq!(blocks[0].arguments, r#"{"path":"/tmp/a"}"#);
        assert_eq!(&text[blocks[0].start..blocks[0].end], text);
    }

    #[test]
    fn parses_xmlish_parameters_into_an_arguments_object() {
        let text = "<function=read><parameter=path>\n/tmp/a\n</parameter></function>";
        let blocks = parse_standalone_plain_text_tool_call_blocks(
            text,
            None,
            DEFAULT_MAX_PLAIN_TEXT_TOOL_PAYLOAD_BYTES,
        )
        .expect("blocks");
        assert_eq!(blocks[0].name, "read");
        assert_eq!(blocks[0].arguments, r#"{"path":"/tmp/a"}"#);
    }

    #[test]
    fn applies_the_allowlist_and_payload_cap() {
        let text = "[read]\n{\"path\":\"/tmp/a\"}\n[/read]";
        assert!(
            parse_standalone_plain_text_tool_call_blocks(text, Some(&allowed(&["write"])), 256_000)
                .is_none()
        );
        assert!(
            parse_standalone_plain_text_tool_call_blocks(text, Some(&allowed(&["read"])), 4)
                .is_none()
        );
        assert!(
            parse_standalone_plain_text_tool_call_blocks(text, Some(&allowed(&["read"])), 256_000)
                .is_some()
        );
    }

    #[test]
    fn rejects_non_object_json_arguments() {
        let text = "[read]\n[]\n[/read]";
        assert!(parse_standalone_plain_text_tool_call_blocks(text, None, 256_000).is_none());
    }

    #[test]
    fn does_not_scan_payloads_inside_protected_code_examples() {
        let raw = format!("```text\n{}```", "[tool:read] {\n".repeat(128));
        assert_eq!(strip(&raw), raw);
    }

    #[test]
    fn preserves_markdown_text_without_a_bracket_payload() {
        for raw in [
            "[guide](https://example.test)\nUse `code` here.",
            "[guide][reference]\n\n[reference]: https://example.test\n\n```js\nconst x = {};\n```",
            "[section]\nOrdinary prose with `code`.",
            "[tool:read]\n",
        ] {
            assert_eq!(strip(raw), raw);
        }
    }

    #[test]
    fn preserves_non_call_text() {
        for raw in [
            r#"Example [tool:read]{"path":"example.txt"}"#,
            "[read]\n{\"path\":}\n[/read]",
        ] {
            assert_eq!(strip(raw), raw);
        }
    }

    #[test]
    fn strips_unicode_indented_bracket_calls_after_each_line_ending() {
        for line_break in ["\r", "\r\n"] {
            let prefix = format!("Before{line_break}");
            let suffix = format!("{line_break}After");
            let json = format!("[read]{line_break}{{\"path\":\"example.txt\"}}[/read]");
            let xml = "[tool:read]<parameter=path>example.txt</parameter>";
            let adjacent = r#"[tool:write]{"path":"output.txt"}"#;

            assert_eq!(
                strip(&format!("{prefix}\u{a0}\t{json}{suffix}")),
                format!("{prefix}After")
            );
            assert_eq!(
                strip(&format!("{prefix}\u{2003}{xml} {adjacent}{suffix}")),
                format!("{prefix}After")
            );
        }
    }

    #[test]
    fn preserves_fenced_calls_while_stripping_adjacent_unprotected_calls() {
        let protected_call = "[read]\n{\"path\":\"example.txt\"}\n[/read]";
        let unprotected_call = "[read]\n{\"path\":\"secret.txt\"}\n[/read]";
        let raw = format!("```\n{protected_call}\n```\n{unprotected_call}\n");
        assert_eq!(strip(&raw), format!("```\n{protected_call}\n```\n"));
    }

    #[test]
    fn preserves_a_long_repeated_incomplete_json_candidate_in_one_scan() {
        let raw = "[tool:read] {\n".repeat(20_000);
        match scan_plain_text_json_tool_call(&raw, 0) {
            JsonToolCallScan::Prefix {
                candidate: Some(candidate),
            } => {
                assert_eq!(candidate.payload.expect("payload").end, raw.len());
            }
            other => panic!("expected prefix, got {other:?}"),
        }
        assert_eq!(strip(&raw), raw);
    }

    #[test]
    fn advances_once_through_far_invalid_payloads() {
        let xml = "<function=read><parameter=x>x\n".repeat(256) + "</parameter>X";
        assert_eq!(strip(&xml), xml);
        let json = "[read]\n{\n".repeat(256) + &"}".repeat(256) + "[/wrong]";
        assert_eq!(strip(&json), json);
    }

    #[test]
    fn protects_tilde_fences_as_well_as_backtick_fences() {
        let call = "[read]\n{\"path\":\"a\"}\n[/read]";
        let raw = format!("~~~\n{call}\n~~~\n{call}\n");
        assert_eq!(strip(&raw), format!("~~~\n{call}\n~~~\n"));
    }

    #[test]
    fn strips_multiple_adjacent_calls_and_reports_them_in_order() {
        let raw = "[read]\n{\"path\":\"a\"}[/read]\n[tool:write]{\"path\":\"b\"}\n";
        let (blocks, output) = strip_plain_text_tool_call_blocks(raw, None, 256_000);
        assert_eq!(
            blocks
                .iter()
                .map(|block| block.name.as_str())
                .collect::<Vec<_>>(),
            ["read", "write"]
        );
        assert_eq!(output, "");
    }
}
