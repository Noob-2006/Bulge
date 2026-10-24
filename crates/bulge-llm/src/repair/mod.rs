//! Repair tool calls that weak / local models emit as plain text.
//! MARK: M8 — transcribed by dsh; see marks/M8-repair.md.

mod grammar;
mod payload;

use serde_json::Value;

use grammar::{is_xmlish_name_char, skip_horizontal_whitespace, skip_whitespace};
use payload::{
    DEFAULT_MAX_PLAIN_TEXT_TOOL_PAYLOAD_BYTES, parse_standalone_plain_text_tool_call_blocks,
    strip_plain_text_tool_call_blocks,
};

/// One tool call recovered from assistant text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairedCall {
    pub name: String,
    /// Compact JSON object text.
    pub arguments: String,
    /// Byte range in the source text that the call occupied.
    pub span: std::ops::Range<usize>,
}

#[derive(Debug, Clone)]
pub struct RepairOptions {
    /// Only these names may be repaired; empty = reject all.
    pub allowed_tools: Vec<String>,
    pub max_payload_bytes: usize,
}

impl Default for RepairOptions {
    fn default() -> Self {
        Self {
            allowed_tools: Vec::new(),
            max_payload_bytes: DEFAULT_MAX_PLAIN_TEXT_TOOL_PAYLOAD_BYTES,
        }
    }
}

/// Cheap pre-check: does the text look like it contains a tool call attempt?
pub fn looks_like_tool_call(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 256_000 {
        return false;
    }
    is_plain_text_tool_call_attempt(trimmed)
}

/// Parse every standalone plain-text tool call block. Returns the calls and the
/// text with those spans removed. Text inside fenced code blocks is never repaired.
pub fn repair(text: &str, options: &RepairOptions) -> (Vec<RepairedCall>, String) {
    if options.allowed_tools.is_empty() {
        return (Vec::new(), text.to_owned());
    }
    let (blocks, output) = strip_plain_text_tool_call_blocks(
        text,
        Some(options.allowed_tools.as_slice()),
        options.max_payload_bytes,
    );
    if !blocks.is_empty() {
        let calls = blocks
            .into_iter()
            .map(|block| RepairedCall {
                name: block.name,
                arguments: block.arguments,
                span: block.start..block.end,
            })
            .collect();
        return (calls, output);
    }
    match repair_structured(text, options) {
        Some((calls, rest)) => (calls, rest),
        None => (Vec::new(), output),
    }
}

/// The whole-message call shapes that [`looks_like_tool_call`] recognizes but
/// the block scanner does not parse: `<tool_call>` / `<tool_calls>` /
/// `<function_call>` wrappers (one or several, around JSON or `<function=…>`),
/// JSON call objects and arrays, `<invoke name="…">` with `<parameter>`s, ReAct
/// `Action:` / `Action Input:`, and `[TOOL_CALL]`. The call is either the whole
/// text or follows one announcement line ("I'll call read:"); fenced code is
/// never repaired. Every call must be allowlisted and have object arguments,
/// or nothing is repaired.
fn repair_structured(text: &str, options: &RepairOptions) -> Option<(Vec<RepairedCall>, String)> {
    let trimmed_start = text.len() - text.trim_start().len();
    let trimmed = text.trim();
    let (prefix, body) = if is_structured_call(trimmed) {
        ("", trimmed)
    } else {
        let (prefix, body) = split_trailing(trimmed)?;
        if !accepted_prefix(prefix.trim()) {
            return None;
        }
        (prefix, body.trim())
    };
    if body.len() > options.max_payload_bytes {
        return None;
    }
    let calls = structured_calls(body)?;
    if calls.iter().any(|(name, _)| !options.allowed_tools.iter().any(|allowed| allowed == name)) {
        return None;
    }
    let body_start = trimmed_start + (body.as_ptr() as usize - trimmed.as_ptr() as usize);
    let span = body_start..body_start + body.len();
    let calls = calls.into_iter().map(|(name, arguments)| RepairedCall { name, arguments, span: span.clone() }).collect();
    Some((calls, prefix.trim().to_owned()))
}

/// Parse a whole call body into `(name, compact JSON object arguments)` pairs.
fn structured_calls(body: &str) -> Option<Vec<(String, String)>> {
    let body = body.trim();
    if let Some(parts) = split_wrapped(body) {
        let mut calls = Vec::new();
        for part in parts {
            calls.extend(structured_calls(part)?);
        }
        return (!calls.is_empty()).then_some(calls);
    }
    if let Ok(value) = serde_json::from_str::<Value>(body) {
        return json_calls(&value);
    }
    if let Some(blocks) = parse_standalone_plain_text_tool_call_blocks(body, None, usize::MAX) {
        return Some(blocks.into_iter().map(|block| (block.name, block.arguments)).collect());
    }
    if let Some((name, inner)) = parse_invoke_call(body) {
        return Some(vec![(name.to_owned(), invoke_arguments(inner)?)]);
    }
    if let Some((name, input)) = parse_action_call(body) {
        return Some(vec![(name.to_owned(), object_arguments(&serde_json::from_str(input.trim()).ok()?)?)]);
    }
    let (name, arguments) = parse_legacy_call(body)?;
    Some(vec![(name.to_owned(), object_arguments(&arguments)?)])
}

/// Split a run of `<tool_call>…</tool_call>` (or `tool_calls` /
/// `function_call`) elements into their bodies. `None` unless the text is
/// nothing but such elements.
fn split_wrapped(text: &str) -> Option<Vec<&str>> {
    const TAGS: [&str; 3] = ["tool_calls", "tool_call", "function_call"];
    let mut parts = Vec::new();
    let mut cursor = 0;
    while cursor < text.len() {
        let rest = &text[cursor..];
        let (tag, after_open) = TAGS.iter().find_map(|tag| strip_prefix_ci(rest, &format!("<{tag}>")).map(|after| (*tag, after)))?;
        let close = format!("</{tag}>");
        let inner_len = after_open.to_ascii_lowercase().find(&close)?;
        parts.push(after_open[..inner_len].trim());
        let consumed = rest.len() - after_open.len() + inner_len + close.len();
        cursor = skip_whitespace(text, cursor + consumed);
    }
    (!parts.is_empty()).then_some(parts)
}

/// Calls in a JSON value: an array of calls, `{"tool_calls": [...]}`, a call
/// object, or `{"function": {...}}`. Tool definitions (schemas) are not calls.
fn json_calls(value: &Value) -> Option<Vec<(String, String)>> {
    match value {
        Value::Array(items) => {
            let calls: Vec<_> = items.iter().map(json_calls).collect::<Option<Vec<_>>>()?.into_iter().flatten().collect();
            (!calls.is_empty()).then_some(calls)
        }
        Value::Object(record) => {
            if let Some(Value::Array(items)) = record.get("tool_calls").or_else(|| record.get("toolCalls")) {
                return json_calls(&Value::Array(items.clone()));
            }
            let name = classify_json_record(record)?;
            let function = record.get("function").or_else(|| record.get("function_call")).or_else(|| record.get("functionCall"));
            let source = match function {
                Some(Value::Object(function)) if read_tool_name(function).is_some() => function,
                _ => record,
            };
            let arguments = ["arguments", "args", "input", "parameters"]
                .iter()
                .find_map(|key| source.get(*key))
                .map_or(Some("{}".to_owned()), object_arguments)?;
            Some(vec![(name, arguments)])
        }
        _ => None,
    }
}

/// Compact JSON object text from an object, or from a string holding one.
fn object_arguments(value: &Value) -> Option<String> {
    match value {
        Value::Object(_) => serde_json::to_string(value).ok(),
        Value::String(text) => match serde_json::from_str::<Value>(text).ok()? {
            object @ Value::Object(_) => serde_json::to_string(&object).ok(),
            _ => None,
        },
        _ => None,
    }
}

/// Arguments from `<parameter name="p">value</parameter>` children; values are
/// strings (one leading/trailing line break trimmed). Anything else inside the
/// element means it is not a call.
fn invoke_arguments(inner: &str) -> Option<String> {
    let mut arguments = serde_json::Map::new();
    let mut rest = inner.trim();
    while !rest.is_empty() {
        let after = strip_prefix_ci(rest, "<parameter")?;
        let after = after.trim_start();
        let after = strip_prefix_ci(after, "name=")?;
        let quote = after.chars().next().filter(|q| matches!(q, '"' | '\''))?;
        let name_end = after[1..].find(quote)? + 1;
        let name = &after[1..name_end];
        let after = after[name_end + 1..].trim_start().strip_prefix('>')?;
        let close = after.to_ascii_lowercase().find("</parameter>")?;
        let value = after[..close].strip_prefix("\r\n").or_else(|| after[..close].strip_prefix('\n')).unwrap_or(&after[..close]);
        let value = value.strip_suffix("\r\n").or_else(|| value.strip_suffix('\n')).unwrap_or(value);
        if name.is_empty() {
            return None;
        }
        arguments.insert(name.to_owned(), Value::String(value.to_owned()));
        rest = after[close + "</parameter>".len()..].trim_start();
    }
    serde_json::to_string(&Value::Object(arguments)).ok()
}

fn is_plain_text_tool_call_attempt(text: &str) -> bool {
    if is_structured_call(text) {
        return true;
    }
    let Some((prefix, body)) = split_fence_or_trailing(text) else {
        return false;
    };
    let prefix = prefix.trim();
    if body.is_empty() || !accepted_prefix(prefix) {
        return false;
    }
    is_structured_call(body.trim())
}

/// Text allowed before a call: nothing, a bare tool label, or an announcement
/// such as "I'll call read:" / "Let me read the file.".
fn accepted_prefix(prefix: &str) -> bool {
    if prefix.is_empty() || is_plausible_tool_label(prefix) {
        return true;
    }
    let announcement = parse_announcement(prefix);
    announcement.and_then(parse_announced_tool).is_some() || announcement.is_some_and(is_file_announcement)
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

fn strip_suffix_ci<'a>(text: &'a str, suffix: &str) -> Option<&'a str> {
    let start = text.len().checked_sub(suffix.len())?;
    text.get(start..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
        .then(|| &text[..start])
}

fn split_fence_or_trailing(text: &str) -> Option<(&str, &str)> {
    split_fence(text).or_else(|| split_trailing(text))
}

fn split_fence(text: &str) -> Option<(&str, &str)> {
    let closing_line_start = text.rfind('\n').map_or(0, |index| index + 1);
    if closing_line_start == 0 {
        return None;
    }
    let closing_line = text[closing_line_start..].trim_start_matches([' ', '\t']);
    let marker = if closing_line == "```" {
        "```"
    } else if closing_line == "~~~" {
        "~~~"
    } else {
        return None;
    };

    let mut line_start = 0;
    while line_start < closing_line_start {
        let line_end = text[line_start..]
            .find('\n')
            .map(|offset| line_start + offset)?;
        let line = text[line_start..line_end]
            .strip_suffix('\r')
            .unwrap_or(&text[line_start..line_end]);
        let indentation = line.len() - line.trim_start_matches([' ', '\t']).len();
        let rest = &line[indentation..];
        if let Some(info) = rest.strip_prefix(marker) {
            let info = info.trim_matches([' ', '\t']);
            if info.is_empty()
                || info.eq_ignore_ascii_case("json")
                || info.eq_ignore_ascii_case("xml")
            {
                let mut body_end = closing_line_start;
                if text[..body_end].ends_with('\n') {
                    body_end -= 1;
                    if text[..body_end].ends_with('\r') {
                        body_end -= 1;
                    }
                }
                let body_start = line_end + 1;
                if body_start <= body_end {
                    return Some((&text[..line_start], &text[body_start..body_end]));
                }
                return Some((&text[..line_start], ""));
            }
        }
        line_start = line_end + 1;
    }
    None
}

fn split_trailing(text: &str) -> Option<(&str, &str)> {
    let newline = text.find('\n')?;
    if newline == 0 {
        return None;
    }
    let prefix = &text[..newline];
    let body_start = skip_whitespace(text, newline + 1);
    let body = &text[body_start..];
    let starts = body.starts_with(['<', '{', '[']) || starts_action(body);
    starts.then_some((prefix, body))
}

fn starts_action(text: &str) -> bool {
    let Some(rest) = strip_prefix_ci(text, "Action") else {
        return false;
    };
    let rest = &rest[skip_whitespace(rest, 0)..];
    rest.starts_with(':')
}

fn parse_announcement(prefix: &str) -> Option<&str> {
    const STARTERS: [&str; 4] = ["I'll ", "I will ", "I am going to ", "Let me "];
    let mut announcement = STARTERS
        .iter()
        .find_map(|starter| strip_prefix_ci(prefix, starter))?;
    if announcement.ends_with(['.', '!', ':']) {
        announcement = &announcement[..announcement.len() - 1];
    }
    if let Some(stripped) = strip_suffix_ci(announcement, " now") {
        announcement = stripped;
    }
    (!announcement.is_empty()).then_some(announcement)
}

fn parse_announced_tool(announcement: &str) -> Option<&str> {
    const VERBS: [&str; 5] = ["call ", "invoke ", "run ", "execute ", "use "];
    let mut name = VERBS
        .iter()
        .find_map(|verb| strip_prefix_ci(announcement, verb))?;
    if let Some(stripped) = strip_prefix_ci(name, "the ") {
        name = stripped;
    }
    if let Some(stripped) = strip_suffix_ci(name, " tool") {
        name = stripped;
    }
    is_tool_name(name).then_some(name)
}

fn is_file_announcement(announcement: &str) -> bool {
    const PHRASES: [&str; 5] = [
        "create the file",
        "read the file",
        "write the file",
        "update the file",
        "delete the file",
    ];
    PHRASES
        .iter()
        .any(|phrase| announcement.eq_ignore_ascii_case(phrase))
}

fn is_plausible_tool_label(text: &str) -> bool {
    if !is_tool_name(text) {
        return false;
    }
    text.as_bytes()
        .first()
        .is_some_and(|first| first.is_ascii_lowercase() || *first == b'_')
}

fn is_tool_name(text: &str) -> bool {
    let bytes = text.as_bytes();
    let Some(first) = bytes.first() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || *first == b'_') {
        return false;
    }
    bytes.iter().copied().all(is_xmlish_name_char)
}

fn is_structured_call(text: &str) -> bool {
    let body = text.trim();
    if let Some(parts) = split_wrapped(body) {
        return parts.into_iter().all(is_structured_call);
    }

    if classify_json_tool_name(body).is_some() {
        return true;
    }
    if parse_standalone_plain_text_tool_call_blocks(
        body,
        None,
        DEFAULT_MAX_PLAIN_TEXT_TOOL_PAYLOAD_BYTES,
    )
    .is_some()
    {
        return true;
    }
    if parse_invoke_call(body).is_some() {
        return true;
    }
    if let Some((name, input)) = parse_action_call(body) {
        let input = input.trim();
        let json_shaped = input.starts_with(['{', '[', '"']) || input.contains(['\r', '\n']);
        if is_tool_name(name)
            && !input.is_empty()
            && (!json_shaped || serde_json::from_str::<Value>(input).is_ok())
        {
            return true;
        }
    }
    parse_legacy_call(body).is_some()
}

fn classify_json_tool_name(text: &str) -> Option<String> {
    let value: Value = serde_json::from_str(text).ok()?;
    classify_json_value(&value)
}

fn classify_json_value(value: &Value) -> Option<String> {
    match value {
        Value::Array(items) => items.iter().find_map(classify_json_value),
        Value::Object(record) => classify_json_record(record),
        _ => None,
    }
}

fn classify_json_record(record: &serde_json::Map<String, Value>) -> Option<String> {
    if let Some(tool_calls) = record.get("tool_calls").or_else(|| record.get("toolCalls"))
        && let Value::Array(items) = tool_calls
    {
        return items.iter().find_map(classify_json_value);
    }

    let function = record
        .get("function")
        .or_else(|| record.get("function_call"))
        .or_else(|| record.get("functionCall"));
    if let Some(Value::Object(function_record)) = function {
        if record.get("type").and_then(Value::as_str) == Some("function")
            && function_record.contains_key("parameters")
        {
            return None;
        }
        if let Some(tool_name) = read_tool_name(function_record)
            && has_tool_args(function_record)
        {
            return Some(tool_name);
        }
    }

    let tool_name = read_tool_name(record)?;
    if has_tool_args(record) {
        return Some(tool_name);
    }
    let kind = record
        .get("type")
        .and_then(Value::as_str)?
        .to_ascii_lowercase();
    is_tool_call_type(&kind).then_some(tool_name)
}

fn read_tool_name(record: &serde_json::Map<String, Value>) -> Option<String> {
    const KEYS: [&str; 4] = ["name", "tool_name", "tool", "function_name"];
    KEYS.iter().find_map(|key| {
        let value = record.get(*key)?.as_str()?.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn has_tool_args(record: &serde_json::Map<String, Value>) -> bool {
    if ["arguments", "args", "input"]
        .iter()
        .any(|key| record.contains_key(*key))
    {
        return true;
    }
    let Some(parameters) = record.get("parameters") else {
        return false;
    };
    let description_is_string = record.get("description").is_some_and(Value::is_string);
    let type_is_function = record.get("type").and_then(Value::as_str) == Some("function");
    let parameters = parameters.as_object();
    let parameters_type_object = parameters
        .and_then(|parameters| parameters.get("type"))
        .and_then(Value::as_str)
        == Some("object");
    let has_properties = parameters
        .and_then(|parameters| parameters.get("properties"))
        .is_some_and(Value::is_object);
    !description_is_string && !type_is_function && !parameters_type_object && !has_properties
}

fn is_tool_call_type(kind: &str) -> bool {
    matches!(
        kind,
        "tool_call" | "toolcall" | "tooluse" | "tool_use" | "function_call" | "functioncall"
    )
}

fn parse_invoke_call(text: &str) -> Option<(&str, &str)> {
    const TAGS: [&str; 3] = ["invoke", "tool_call", "function_call"];
    for tag in TAGS {
        let open = format!("<{tag}");
        let Some(rest) = strip_prefix_ci(text, &open) else {
            continue;
        };
        let after_tag = skip_whitespace(rest, 0);
        if after_tag == 0 {
            continue;
        }
        let Some(rest) = strip_prefix_ci(&rest[after_tag..], "name=") else {
            continue;
        };
        let Some(quote @ ('"' | '\'')) = rest.chars().next() else {
            continue;
        };
        let value_start = quote.len_utf8();
        let Some(value_end) = rest[value_start..]
            .find(quote)
            .map(|offset| value_start + offset)
        else {
            continue;
        };
        let name = &rest[value_start..value_end];
        if name.is_empty() || name.contains(['"', '\'']) {
            continue;
        }
        let after_value = skip_whitespace(rest, value_end + quote.len_utf8());
        let Some(after_open) = rest
            .get(after_value..)
            .and_then(|rest| rest.strip_prefix('>'))
        else {
            continue;
        };
        let close = format!("</{tag}>");
        if let Some(inner) = strip_suffix_ci(after_open, &close)
            && is_tool_name(name)
        {
            return Some((name, inner));
        }
    }
    None
}

fn parse_action_call(text: &str) -> Option<(&str, &str)> {
    let rest = strip_prefix_ci(text, "Action")?;
    let rest = &rest[skip_horizontal_whitespace(rest, 0)..];
    let rest = rest.strip_prefix(':')?;
    let rest = &rest[skip_horizontal_whitespace(rest, 0)..];

    let bytes = rest.as_bytes();
    let mut name_end = 0;
    while name_end < bytes.len() && name_end < 120 && is_xmlish_name_char(bytes[name_end]) {
        name_end += 1;
    }
    if name_end == 0
        || bytes
            .get(name_end)
            .is_some_and(|byte| is_xmlish_name_char(*byte))
    {
        return None;
    }
    let name = &rest[..name_end];
    if !is_tool_name(name) {
        return None;
    }
    let rest = &rest[name_end..];
    let rest = &rest[skip_horizontal_whitespace(rest, 0)..];
    let rest = rest
        .strip_prefix("\r\n")
        .or_else(|| rest.strip_prefix('\n'))?;
    let rest = &rest[skip_horizontal_whitespace(rest, 0)..];
    let rest = strip_prefix_ci(rest, "Action Input")?;
    let rest = &rest[skip_horizontal_whitespace(rest, 0)..];
    let rest = rest.strip_prefix(':')?;
    let rest = &rest[skip_horizontal_whitespace(rest, 0)..];
    (!rest.is_empty()).then_some((name, rest))
}

fn take_ci(text: &str, cursor: usize, literal: &str) -> Option<usize> {
    let end = cursor.checked_add(literal.len())?;
    let candidate = text.get(cursor..end)?;
    candidate.eq_ignore_ascii_case(literal).then_some(end)
}

fn parse_legacy_call(text: &str) -> Option<(&str, Value)> {
    let mut cursor = 0;
    cursor = take_ci(text, cursor, "[")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "TOOL_CALL")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "]")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "{")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "tool")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "=>")?;
    cursor = skip_whitespace(text, cursor);
    let quote = *text.as_bytes().get(cursor)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    cursor += 1;
    let name_start = cursor;
    while text
        .as_bytes()
        .get(cursor)
        .is_some_and(|byte| *byte != quote)
    {
        cursor += 1;
    }
    let name = text.get(name_start..cursor)?;
    if !is_tool_name(name) || name.len() > 120 || name.contains(['"', '\'']) {
        return None;
    }
    cursor += 1;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, ",")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "args")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "=>")?;
    cursor = skip_whitespace(text, cursor);
    let args_start = take_ci(text, cursor, "{")?.checked_sub(1)?;
    let grammar::JsonObjectScan::Complete { end } = grammar::scan_json_object(text, args_start)
    else {
        return None;
    };
    let arguments: Value = serde_json::from_str(text.get(args_start..end)?).ok()?;
    if !arguments.is_object() {
        return None;
    }
    cursor = skip_whitespace(text, end);
    cursor = take_ci(text, cursor, "}")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "[")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "/")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "TOOL_CALL")?;
    cursor = skip_whitespace(text, cursor);
    cursor = take_ci(text, cursor, "]")?;
    text.get(cursor..)?.trim().is_empty().then_some((name, arguments))
}

#[cfg(test)]
mod tests;
