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
