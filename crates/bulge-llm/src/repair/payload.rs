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
#[path = "payload_tests.rs"]
mod tests;
