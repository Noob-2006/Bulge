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

fn names_and_args(text: &str) -> Vec<(String, String)> {
    repaired(text).0.into_iter().map(|call| (call.name, call.arguments)).collect()
}

#[test]
fn repairs_every_whole_message_shape_the_detector_recognizes() {
    let read = vec![("read".to_owned(), r#"{"path":"a.txt"}"#.to_owned())];
    for text in [
        "<tool_call><function=read><parameter=path>a.txt</parameter></function></tool_call>",
        "<tool_call>\n{\"name\": \"read\", \"arguments\": {\"path\": \"a.txt\"}}\n</tool_call>",
        "<function_call>{\"name\":\"read\",\"arguments\":\"{\\\"path\\\":\\\"a.txt\\\"}\"}</function_call>",
        r#"{"tool_calls":[{"type":"function","function":{"name":"read","arguments":"{\"path\":\"a.txt\"}"}}]}"#,
        r#"<invoke name="read"><parameter name="path">a.txt</parameter></invoke>"#,
        "<invoke name=\"read\">\n<parameter name=\"path\">\na.txt\n</parameter>\n</invoke>",
        "Action: read\nAction Input: {\"path\": \"a.txt\"}",
        r#"[TOOL_CALL]{tool => "read", args => {"path":"a.txt"}}[/TOOL_CALL]"#,
    ] {
        assert_eq!(names_and_args(text), read, "{text}");
        assert!(looks_like_tool_call(text), "detector must agree: {text}");
    }
}

#[test]
fn repairs_several_wrapped_calls_and_keeps_an_announcement() {
    let text = "I'll call read:\n<tool_call>{\"name\":\"read\",\"arguments\":{\"path\":\"a\"}}</tool_call>\n<tool_call>{\"name\":\"write\",\"arguments\":{\"path\":\"b\",\"content\":\"x\"}}</tool_call>";
    let (calls, rest) = repaired(text);
    assert_eq!(calls.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["read", "write"]);
    assert_eq!(rest, "I'll call read:");
    assert_eq!(&text[calls[0].span.clone()], &text[text.find("<tool_call>").unwrap()..]);
}

#[test]
fn whole_message_shapes_keep_the_safety_rules() {
    // Not allowlisted, non-object arguments, a schema, fenced code, prose: untouched.
    for text in [
        "<tool_call>{\"name\":\"delete_everything\",\"arguments\":{}}</tool_call>",
        "<tool_call>{\"name\":\"read\",\"arguments\":[1,2]}</tool_call>",
        r#"{"name":"read","description":"Read a file","parameters":{"type":"object","properties":{"path":{"type":"string"}}}}"#,
        "```json\n{\"name\":\"read\",\"arguments\":{\"path\":\"a\"}}\n```",
        "Here is how you would call it:\n<tool_call>{\"name\":\"read\",\"arguments\":{\"path\":\"a\"}}</tool_call>",
        "Action: read\nAction Input: just a sentence",
        "<tool_call>{\"name\":\"read\",\"arguments\":{\"path\":\"a\"}}</tool_call> and then some prose",
    ] {
        let (calls, rest) = repaired(text);
        assert!(calls.is_empty(), "must not repair: {text}");
        assert_eq!(rest, text);
    }
    // One disallowed call in a batch blocks the whole batch.
    let mixed = "<tool_call>{\"name\":\"read\",\"arguments\":{}}</tool_call><tool_call>{\"name\":\"rm\",\"arguments\":{}}</tool_call>";
    assert!(repaired(mixed).0.is_empty());
    // The payload cap applies.
    let big = format!("<tool_call>{{\"name\":\"write\",\"arguments\":{{\"content\":\"{}\"}}}}</tool_call>", "x".repeat(400));
    assert!(repair(&big, &options(&["write"], 100)).0.is_empty());
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
