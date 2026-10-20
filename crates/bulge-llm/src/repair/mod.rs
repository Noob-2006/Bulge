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
    let calls = blocks
        .into_iter()
        .map(|block| RepairedCall {
            name: block.name,
            arguments: block.arguments,
            span: block.start..block.end,
        })
        .collect();
    (calls, output)
}

fn is_plain_text_tool_call_attempt(text: &str) -> bool {
    if is_structured_call(text) {
        return true;
    }
    let Some((prefix, body)) = split_fence_or_trailing(text) else {
        return false;
    };
    let prefix = prefix.trim();
    if body.is_empty() {
        return false;
    }
    let announcement = parse_announcement(prefix);
    let announced_tool = announcement.and_then(parse_announced_tool);
    let file_announcement = announcement.is_some_and(is_file_announcement);
    let tool_label = is_plausible_tool_label(prefix);
    if !prefix.is_empty() && !tool_label && announced_tool.is_none() && !file_announcement {
        return false;
    }
    is_structured_call(body.trim())
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
    let body = strip_xml_wrapper(body).unwrap_or(body);

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

fn strip_xml_wrapper(text: &str) -> Option<&str> {
    const TAGS: [&str; 3] = ["tool_call", "tool_calls", "function_call"];
    for tag in TAGS {
        let open = format!("<{tag}>");
        let Some(inner) = strip_prefix_ci(text, &open) else {
            continue;
        };
        let close = format!("</{tag}>");
        if let Some(inner) = strip_suffix_ci(inner, &close) {
            return Some(inner.trim());
        }
    }
    None
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

fn parse_invoke_call(text: &str) -> Option<&str> {
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
        if strip_suffix_ci(after_open, &close).is_some() && is_tool_name(name) {
            return Some(name);
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

fn parse_legacy_call(text: &str) -> Option<&str> {
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
    text.get(cursor..)?.trim().is_empty().then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(names: &[&str], max_payload_bytes: usize) -> RepairOptions {
        RepairOptions {
            allowed_tools: names.iter().map(|name| (*name).to_owned()).collect(),
            max_payload_bytes,
        }
    }

    fn repaired(text: &str) -> (Vec<RepairedCall>, String) {
        repair(text, &options(&["read", "write"], 256_000))
    }

    #[test]
    fn recognizes_structured_attempts() {
        let call = r#"{"name":"write","arguments":{"path":"proof.txt","content":"OK"}}"#;
        let fenced = format!("```json\n{call}\n```");
        let wrapped_xml = "<tool_call><function=read><parameter=path>proof.txt</parameter></function></tool_call>";
        let react = "Action: read\nAction Input: {\"path\":\"proof.txt\"}";
        let legacy = r#"[TOOL_CALL]{tool => "read", args => {"path":"proof.txt"}}[/TOOL_CALL]"#;

        for text in [
            call.to_owned(),
            format!(r#"{{"function_call":{call}}}"#),
            format!(r#"{{"functionCall":{call}}}"#),
            r#"{"name":"write","parameters":{"path":"proof.txt","content":"OK"}}"#.to_owned(),
            fenced.clone(),
            format!("I'll call write now.\n{fenced}"),
            format!("Let me invoke the write tool.\n{call}"),
            format!("I'll create the file now.\n{fenced}"),
            r#"[{"function":{"name":"read","arguments":"{}"}}]"#.to_owned(),
            r#"{"tool_calls":[{"function":{"name":"read","arguments":{}}}]}"#.to_owned(),
            format!(r#"[{{"name":"unregistered","arguments":{{}}}},{call}]"#),
            format!(r#"[{{"tool_calls":[]}},{call}]"#),
            r#"<invoke name="read"><parameter name="path">proof.txt</parameter></invoke>"#
                .to_owned(),
            format!("read\n{}", r#"<invoke name="read"><parameter name="path">proof.txt</parameter></invoke>"#),
            format!("<tool_call>{call}</tool_call>"),
            "```xml\n<function=read><parameter=path>proof.txt</parameter></function>\n```"
                .to_owned(),
            wrapped_xml.to_owned(),
            r#"<tool_calls><invoke name="read"><parameter name="path">proof.txt</parameter></invoke></tool_calls>"#.to_owned(),
            "<function_call><function=read><parameter=path>proof.txt</parameter></function></function_call>".to_owned(),
            react.to_owned(),
            "Action: read\nAction Input: {\n  \"path\": \"proof.txt\"\n}".to_owned(),
            "Action: read\r\nAction Input: proof.txt".to_owned(),
            format!("I'll call read now.\n{react}"),
            format!("```\n{react}\n```"),
            legacy.to_owned(),
            format!("Let me use read.\n{legacy}"),
            format!("```\n{legacy}\n```"),
        ] {
            assert!(looks_like_tool_call(&text), "expected a tool call: {text}");
        }
    }

    #[test]
    fn preserves_prose_examples_and_definitions() {
        let call = r#"{"name":"write","arguments":{"path":"proof.txt","content":"OK"}}"#;
        let fenced = format!("```json\n{call}\n```");
        let definition = r#"{"name":"write","description":"Write a file","parameters":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}}}}"#;
        let wrapped_xml = "<tool_call><function=read><parameter=path>proof.txt</parameter></function></tool_call>";
        let react = "Action: read\nAction Input: {\"path\":\"proof.txt\"}";
        let legacy = r#"[TOOL_CALL]{tool => "read", args => {"path":"proof.txt"}}[/TOOL_CALL]"#;

        for text in [
            "I will call write to create the file.",
            r#"{"name":"write","description":"an available tool"}"#,
            definition,
            r#"{"name":"write","description":"Write a file","parameters":{"type":"object"}}"#,
            r#"{"name":"write","parameters":{"type":"object"}}"#,
            r#"{"name":"write","parameters":{"properties":{"path":{"type":"string"}},"required":["path"]}}"#,
            r#"{"type":"function","function":{"name":"write","description":"Write a file","parameters":{}}}"#,
            r#"Here is an example of the API:"#,
            "Documentation",
            "Usage",
            "```text\ncall write proof.txt\n```",
            "```json\n{\"name\":\"write\",\"arguments\":{}}",
            "<tool_call><function=read><parameter=path>proof.txt</parameter></function>",
            "<tool_call><function=read><parameter=path>proof.txt</parameter></function></function_call>",
            "Action: read",
            "Action: read\nAction Input:",
            r#"Action: read
Action Input: {"path":"proof.txt""#,
            "Action: read\nAction Input: [\"proof.txt\"",
            r#"Action: read
Action Input: "proof.txt"#,
            "Action: read\nAction Input: {\"path\":\"proof.txt\"}\nObservation: example result",
            r#"[TOOL_CALL]{tool => "read", args => {}}]"#,
            r#"[TOOL_CALL]{tool => "read"}[/TOOL_CALL]"#,
        ] {
            assert!(!looks_like_tool_call(text), "expected prose: {text}");
        }

        for text in [
            format!("Here is an example of the API:\n{fenced}"),
            format!("I'll show an example.\n{fenced}"),
            format!("Documentation\n{fenced}"),
            format!("Usage\n{fenced}"),
            format!("{fenced}\nThis is an example; it has not run."),
        ] {
            assert!(!looks_like_tool_call(&text), "expected prose: {text}");
        }

        for text in [wrapped_xml, react, legacy] {
            for variant in [
                format!("Here is an example:\n{text}"),
                format!("Here is an example:\n```\n{text}\n```"),
                format!("{text}\nThis is an example; it has not run."),
            ] {
                assert!(!looks_like_tool_call(&variant), "expected prose: {variant}");
            }
        }
    }

    #[test]
    fn looks_like_tool_call_is_name_agnostic_while_repair_uses_the_allowlist() {
        let wrapped_xml = "<tool_call><function=unregistered><parameter=path>proof.txt</parameter></function></tool_call>";
        let react = "Action: unregistered\nAction Input: {\"path\":\"proof.txt\"}";
        let legacy =
            r#"[TOOL_CALL]{tool => "unregistered", args => {"path":"proof.txt"}}[/TOOL_CALL]"#;
        for text in [wrapped_xml, react, legacy] {
            assert!(
                looks_like_tool_call(text),
                "detection has no allowlist: {text}"
            );
            let (calls, output) = repair(text, &options(&["read"], 256_000));
            assert!(calls.is_empty());
            assert_eq!(output, text);
        }
    }

    #[test]
    fn keeps_explanatory_prefixes_literal() {
        let call = r#"{"name":"write","arguments":{"path":"proof.txt","content":"OK"}}"#;
        let fenced = format!("```json\n{call}\n```");
        assert!(!looks_like_tool_call(&format!(
            "Example of functions.write\n{fenced}"
        )));
    }

    #[test]
    fn repairs_a_standalone_json_block_and_removes_its_line() {
        let text = "Before\n[read]\n{\"path\":\"/tmp/a\"}\n[/read]\nAfter";
        let (calls, output) = repaired(text);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "read");
        assert_eq!(calls[0].arguments, r#"{"path":"/tmp/a"}"#);
        assert_eq!(
            &text[calls[0].span.clone()],
            "[read]\n{\"path\":\"/tmp/a\"}\n[/read]"
        );
        assert_eq!(output, "Before\nAfter");
    }

    #[test]
    fn repairs_xmlish_and_harmony_calls() {
        let xml = "<function=read><parameter=path>a</parameter></function>";
        let (calls, output) = repaired(xml);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "read");
        assert_eq!(calls[0].arguments, r#"{"path":"a"}"#);
        assert_eq!(output, "");

        let harmony = r#"<|channel|>commentary to=read code<|message|>{"path":"a"}<|call|>"#;
        let (calls, output) = repaired(harmony);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "read");
        assert_eq!(output, "");
    }

    #[test]
    fn repairs_multiple_calls_in_order() {
        let text = "[read]\n{\"path\":\"a\"}[/read]\n[tool:write]{\"path\":\"b\"}\n";
        let (calls, output) = repaired(text);
        assert_eq!(
            calls
                .iter()
                .map(|call| call.name.as_str())
                .collect::<Vec<_>>(),
            ["read", "write"]
        );
        assert_eq!(calls[0].arguments, r#"{"path":"a"}"#);
        assert_eq!(calls[1].arguments, r#"{"path":"b"}"#);
        assert_eq!(output, "");
    }

    #[test]
    fn preserves_argument_key_order_and_utf8_byte_spans() {
        let json = "[read]\n{ \"path\" : \"a\", \"mode\" : \"r\" }[/read]";
        let (calls, _) = repaired(json);
        assert_eq!(calls[0].arguments, r#"{"path":"a","mode":"r"}"#);

        let xml =
            "<function=read><parameter=path>a</parameter><parameter=mode>r</parameter></function>";
        let (calls, _) = repaired(xml);
        assert_eq!(calls[0].arguments, r#"{"path":"a","mode":"r"}"#);

        let text = "é\n[read]\n{\"path\":\"檔案\"}[/read]\né";
        let (calls, output) = repaired(text);
        assert_eq!(calls.len(), 1);
        assert_eq!(
            &text[calls[0].span.clone()],
            "[read]\n{\"path\":\"檔案\"}[/read]"
        );
        assert_eq!(output, "é\né");
    }

    #[test]
    fn never_repairs_without_an_allowlist() {
        let text = "[read]\n{\"path\":\"a\"}\n[/read]";
        let (calls, output) = repair(text, &RepairOptions::default());
        assert!(calls.is_empty());
        assert_eq!(output, text);
    }

    #[test]
    fn keeps_calls_with_unknown_names_and_oversized_payloads() {
        let unknown = "[write]\n{\"path\":\"a\"}\n[/write]";
        let (calls, output) = repair(unknown, &options(&["read"], 256_000));
        assert!(calls.is_empty());
        assert_eq!(output, unknown);

        let payload = "[read]\n{\"path\":\"aaaaaaaaaa\"}\n[/read]";
        let (calls, output) = repair(payload, &options(&["read"], 8));
        assert!(calls.is_empty());
        assert_eq!(output, payload);
    }

    #[test]
    fn keeps_non_object_arguments_literal() {
        for text in ["[read]\n[]\n[/read]", "[read]\n\"path\"\n[/read]"] {
            let (calls, output) = repair(text, &options(&["read"], 256_000));
            assert!(calls.is_empty());
            assert_eq!(output, text);
        }
    }

    #[test]
    fn never_repairs_calls_inside_fenced_code() {
        let call = "[read]\n{\"path\":\"a\"}\n[/read]";
        let text = format!("Example:\n```json\n{call}\n```\n");
        let (calls, output) = repaired(&text);
        assert!(calls.is_empty());
        assert_eq!(output, text);
    }
}
