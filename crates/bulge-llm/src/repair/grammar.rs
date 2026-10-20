//! Structural scanners shared by plain-text tool-call repair.
//!
//! MARK: M8 — ported from openclaw `packages/tool-call-repair/src/grammar.ts`.
//! The reference tracks UTF-16 offsets for stream buffering; this port works on
//! byte offsets and only keeps the static scanning pieces.

/// Legacy marker some models emit after a serialized JSON tool request.
pub(crate) const END_TOOL_REQUEST: &str = "[END_TOOL_REQUEST]";
/// Harmony stream marker that introduces the target channel before a tool call.
pub(crate) const HARMONY_CHANNEL_MARKER: &str = "<|channel|>";
/// Harmony stream marker that may separate the header from the JSON payload.
pub(crate) const HARMONY_MESSAGE_MARKER: &str = "<|message|>";
/// Harmony stream marker that may close a serialized tool-call payload.
pub(crate) const HARMONY_CALL_MARKER: &str = "<|call|>";

/// A half-open byte range in the source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Span {
    pub start: usize,
    pub end: usize,
}

/// Tool names in bracket/plain-text repairs match provider-safe ids only.
pub(crate) fn is_plain_text_tool_name_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// XML-ish function tags allow namespace punctuation used by some models.
pub(crate) fn is_xmlish_name_char(byte: u8) -> bool {
    is_plain_text_tool_name_char(byte) || byte == b'.' || byte == b':' || byte == b'-'
}

fn is_js_whitespace(ch: char) -> bool {
    ch.is_whitespace() || ch == '\u{feff}'
}

/// Skips spaces and tabs only, preserving line boundaries for grammar decisions.
pub(crate) fn skip_horizontal_whitespace(text: &str, start: usize) -> usize {
    let bytes = text.as_bytes();
    let mut index = start;
    while index < bytes.len() && (bytes[index] == b' ' || bytes[index] == b'\t') {
        index += 1;
    }
    index
}

/// Skips indentation whitespace without crossing the current line boundary.
pub(crate) fn skip_line_indentation(text: &str, start: usize) -> usize {
    let mut index = start;
    for (offset, ch) in text[start..].char_indices() {
        if !is_js_whitespace(ch) || ch == '\r' || ch == '\n' {
            return start + offset;
        }
        index = start + offset + ch.len_utf8();
    }
    index
}

/// Skips JavaScript-style whitespace when line structure is no longer meaningful.
pub(crate) fn skip_whitespace(text: &str, start: usize) -> usize {
    let mut index = start;
    for (offset, ch) in text[start..].char_indices() {
        if !is_js_whitespace(ch) {
            return start + offset;
        }
        index = start + offset + ch.len_utf8();
    }
    index
}

/// Consumes either Unix or Windows line endings and returns the first offset after them.
pub(crate) fn consume_line_break(text: &str, start: usize) -> Option<usize> {
    match text.as_bytes().get(start).copied() {
        Some(b'\r') => Some(if text.as_bytes().get(start + 1) == Some(&b'\n') {
            start + 2
        } else {
            start + 1
        }),
        Some(b'\n') => Some(start + 1),
        _ => None,
    }
}

/// Skips optional indentation and consumes the line break that follows it.
pub(crate) fn consume_structural_line_break_after_horizontal_whitespace(
    text: &str,
    start: usize,
) -> Option<usize> {
    consume_line_break(text, skip_horizontal_whitespace(text, start))
}

/// Returns the encoded byte length when a source span stays within its limit.
pub(crate) fn utf8_byte_length_within_limit(
    text: &str,
    start: usize,
    end: usize,
    max_bytes: usize,
) -> Option<usize> {
    if end < start || end - start > max_bytes {
        return None;
    }
    let byte_length = text.get(start..end)?.len();
    (byte_length <= max_bytes).then_some(byte_length)
}

fn starts_with_ascii_marker_ignore_case(text: &str, cursor: usize, marker: &str) -> bool {
    let bytes = text.as_bytes();
    let end = cursor.saturating_add(marker.len());
    match bytes.get(cursor..end) {
        Some(candidate) => marker.as_bytes().eq_ignore_ascii_case(candidate),
        None => false,
    }
}

fn is_ascii_marker_prefix_ignore_case(text: &str, cursor: usize, marker: &str) -> bool {
    let bytes = text.as_bytes();
    let available = bytes.len().saturating_sub(cursor).min(marker.len());
    match bytes.get(cursor..cursor.saturating_add(available)) {
        Some(rest) => {
            rest.len() < marker.len() && marker.as_bytes()[..rest.len()].eq_ignore_ascii_case(rest)
        }
        None => false,
    }
}

fn index_of_ascii_marker_ignore_case(text: &str, marker: &str, start: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut cursor = start;
    while cursor < bytes.len() {
        let offset = text[cursor..].find('<')?;
        let candidate = cursor + offset;
        if starts_with_ascii_marker_ignore_case(text, candidate, marker) {
            return Some(candidate);
        }
        cursor = candidate + 1;
    }
    None
}

fn scan_xmlish_name_end(text: &str, start: usize, is_name_char: fn(u8) -> bool) -> usize {
    let bytes = text.as_bytes();
    let mut end = start;
    while end < bytes.len() && end - start < 121 && is_name_char(bytes[end]) {
        end += 1;
    }
    end
}

/// One `<parameter=...>...</parameter>` value inside an XML-ish call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XmlishParameter {
    pub name: Span,
    pub value: Span,
}

/// A partially or fully parsed `<function=...>` / `[name]` / `[tool:name]` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XmlishCandidate {
    pub name: Span,
    pub parameters: Vec<XmlishParameter>,
    pub payload: Option<Span>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum XmlishScan {
    Invalid {
        at: usize,
    },
    Prefix {
        candidate: Option<XmlishCandidate>,
        complete_end: Option<usize>,
    },
    Complete {
        candidate: XmlishCandidate,
        end: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XmlishSyntax {
    Function,
    NamedBracket,
    ToolBracket,
}

const FUNCTION_OPEN: &str = "<function=";
const FUNCTION_CLOSE: &str = "</function>";
const PARAMETER_OPEN: &str = "<parameter=";
const PARAMETER_CLOSE: &str = "</parameter>";

/// Uncapped structural scan shared by parsing and stripping.
pub(crate) fn scan_xmlish_tool_call(text: &str, start: usize) -> XmlishScan {
    let bytes = text.as_bytes();
    let mut cursor = start;
    let mut syntax;
    let name;

    match bytes.get(cursor).copied() {
        Some(b'<') => {
            if !starts_with_ascii_marker_ignore_case(text, cursor, FUNCTION_OPEN)
                && !is_ascii_marker_prefix_ignore_case(text, cursor, FUNCTION_OPEN)
            {
                return XmlishScan::Invalid { at: start };
            }
            if bytes.len() - cursor < FUNCTION_OPEN.len() {
                return XmlishScan::Prefix {
                    candidate: None,
                    complete_end: None,
                };
            }
            cursor += FUNCTION_OPEN.len();
            let name_start = cursor;
            cursor = scan_xmlish_name_end(text, name_start, is_xmlish_name_char);
            name = Span {
                start: name_start,
                end: cursor,
            };
            syntax = XmlishSyntax::Function;
            if cursor - name_start > 120 {
                return XmlishScan::Invalid { at: cursor };
            }
            if cursor == bytes.len() {
                return XmlishScan::Prefix {
                    candidate: Some(XmlishCandidate {
                        name,
                        parameters: Vec::new(),
                        payload: None,
                    }),
                    complete_end: None,
                };
            }
            if cursor == name_start || bytes[cursor] != b'>' {
                return XmlishScan::Invalid { at: cursor };
            }
            cursor += 1;
        }
        Some(b'[') => {
            cursor += 1;
            let first_name_start = cursor;
            cursor = scan_xmlish_name_end(text, first_name_start, is_plain_text_tool_name_char);
            if cursor - first_name_start > 120 {
                return XmlishScan::Invalid { at: cursor };
            }
            let first_name = &text[first_name_start..cursor];
            if cursor == bytes.len() && "tool".starts_with(first_name) {
                return XmlishScan::Prefix {
                    candidate: None,
                    complete_end: None,
                };
            }
            syntax = XmlishSyntax::NamedBracket;
            name = Span {
                start: first_name_start,
                end: cursor,
            };
            let mut name = name;
            if bytes.get(cursor) == Some(&b':') && first_name == "tool" {
                syntax = XmlishSyntax::ToolBracket;
                cursor += 1;
                let name_start = cursor;
                cursor = scan_xmlish_name_end(text, name_start, is_plain_text_tool_name_char);
                name = Span {
                    start: name_start,
                    end: cursor,
                };
                if cursor - name_start > 120 {
                    return XmlishScan::Invalid { at: cursor };
                }
            }
            if cursor == bytes.len() {
                return XmlishScan::Prefix {
                    candidate: Some(XmlishCandidate {
                        name,
                        parameters: Vec::new(),
                        payload: None,
                    }),
                    complete_end: None,
                };
            }
            if name.start == name.end || bytes[cursor] != b']' {
                return XmlishScan::Invalid { at: cursor };
            }
            cursor += 1;
            if syntax == XmlishSyntax::NamedBracket {
                if cursor == bytes.len() {
                    return XmlishScan::Prefix {
                        candidate: Some(XmlishCandidate {
                            name,
                            parameters: Vec::new(),
                            payload: None,
                        }),
                        complete_end: None,
                    };
                }
                let Some(after_line_break) =
                    consume_structural_line_break_after_horizontal_whitespace(text, cursor)
                else {
                    return XmlishScan::Invalid { at: cursor };
                };
                cursor = after_line_break;
            }
        }
        _ => return XmlishScan::Invalid { at: start },
    }

    let body_start = cursor;
    let mut parameters = Vec::new();
    let candidate = |payload_end: usize, parameters: &[XmlishParameter]| XmlishCandidate {
        name,
        parameters: parameters.to_vec(),
        payload: Some(Span {
            start: body_start,
            end: payload_end,
        }),
    };
    let prefix =
        |payload_end: usize, parameters: &[XmlishParameter], complete_end| XmlishScan::Prefix {
            candidate: Some(candidate(payload_end, parameters)),
            complete_end,
        };
    let complete =
        |payload_end: usize, parameters: &[XmlishParameter], end: usize| XmlishScan::Complete {
            candidate: candidate(payload_end, parameters),
            end,
        };
    let mut last_parameter_end: Option<usize> = None;

    loop {
        let marker_start = skip_whitespace(text, cursor);
        if marker_start == bytes.len() {
            return if syntax == XmlishSyntax::ToolBracket && last_parameter_end.is_some() {
                let end = last_parameter_end.unwrap_or(marker_start);
                complete(end, &parameters, end)
            } else {
                XmlishScan::Prefix {
                    candidate: Some(candidate(bytes.len(), &parameters)),
                    complete_end: None,
                }
            };
        }
        if starts_with_ascii_marker_ignore_case(text, marker_start, FUNCTION_CLOSE) {
            return if syntax != XmlishSyntax::Function && parameters.is_empty() {
                XmlishScan::Invalid { at: marker_start }
            } else {
                complete(
                    marker_start,
                    &parameters,
                    marker_start + FUNCTION_CLOSE.len(),
                )
            };
        }
        if is_ascii_marker_prefix_ignore_case(text, marker_start, FUNCTION_CLOSE) {
            return prefix(marker_start, &parameters, None);
        }
        if starts_with_ascii_marker_ignore_case(text, marker_start, PARAMETER_OPEN) {
            let name_start = marker_start + PARAMETER_OPEN.len();
            let name_end = scan_xmlish_name_end(text, name_start, is_xmlish_name_char);
            if name_end - name_start > 120 {
                return XmlishScan::Invalid { at: marker_start };
            }
            if name_end == bytes.len() {
                return prefix(marker_start, &parameters, None);
            }
            if name_end == name_start || bytes[name_end] != b'>' {
                return XmlishScan::Invalid { at: marker_start };
            }
            let value_start = name_end + 1;
            let Some(close_start) =
                index_of_ascii_marker_ignore_case(text, PARAMETER_CLOSE, value_start)
            else {
                return XmlishScan::Prefix {
                    candidate: Some(candidate(text.len(), &parameters)),
                    complete_end: None,
                };
            };
            let end = close_start + PARAMETER_CLOSE.len();
            parameters.push(XmlishParameter {
                name: Span {
                    start: name_start,
                    end: name_end,
                },
                value: Span {
                    start: value_start,
                    end: close_start,
                },
            });
            cursor = end;
            last_parameter_end = Some(end);
            continue;
        }
        if is_ascii_marker_prefix_ignore_case(text, marker_start, PARAMETER_OPEN) {
            return prefix(marker_start, &parameters, None);
        }
        if syntax == XmlishSyntax::ToolBracket && last_parameter_end.is_some() {
            let end = last_parameter_end.unwrap_or(marker_start);
            return complete(end, &parameters, end);
        }
        return XmlishScan::Invalid { at: marker_start };
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JsonObjectScan {
    Complete { end: usize },
    Prefix { end: usize },
}

/// Scans a balanced JSON object starting at `start` (which must be `{`).
pub(crate) fn scan_json_object(text: &str, start: usize) -> JsonObjectScan {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate().skip(start) {
        let byte = *byte;
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return JsonObjectScan::Complete { end: index + 1 };
                }
            }
            _ => {}
        }
    }
    JsonObjectScan::Prefix { end: bytes.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_xmlish_names() {
        let function = format!("<function={}", "x".repeat(121));
        assert!(matches!(
            scan_xmlish_tool_call(&function, 0),
            XmlishScan::Invalid { .. }
        ));

        let parameter = format!("<function=read><parameter={}", "x".repeat(121));
        assert!(matches!(
            scan_xmlish_tool_call(&parameter, 0),
            XmlishScan::Invalid { .. }
        ));
    }

    #[test]
    fn excludes_a_partial_function_close_from_the_payload_cap() {
        let body = " ".repeat(255_999);
        let prefix = format!("<function=read>{body}</func");
        let scan = scan_xmlish_tool_call(&prefix, 0);
        let XmlishScan::Prefix {
            candidate: Some(candidate),
            ..
        } = scan
        else {
            panic!("expected an XML-ish prefix");
        };
        let payload = candidate.payload.expect("prefix candidate has a payload");
        assert_eq!(
            utf8_byte_length_within_limit(&prefix, payload.start, payload.end, 256_000),
            Some(255_999)
        );

        let complete = format!("{prefix}tion>");
        assert!(matches!(
            scan_xmlish_tool_call(&complete, 0),
            XmlishScan::Complete { .. }
        ));
    }

    #[test]
    fn scans_complete_and_partial_json_objects() {
        assert_eq!(
            scan_json_object(r#"{"a":{"b":"}"},"c":"\\"}"#, 0),
            JsonObjectScan::Complete { end: 24 }
        );
        assert!(matches!(
            scan_json_object(r#"{"a":"unterminated"#, 0),
            JsonObjectScan::Prefix { .. }
        ));
    }

    #[test]
    fn treats_utf8_payload_lengths_as_bytes() {
        let text = "é";
        assert_eq!(
            utf8_byte_length_within_limit(text, 0, text.len(), 2),
            Some(2)
        );
        assert_eq!(utf8_byte_length_within_limit(text, 0, text.len(), 1), None);
    }
}
