//! End-to-end assembly through the public interfaces, offline:
//! raw SSE bytes -> SseParser -> WireProtocol decoder -> Assembler.

use bulge_llm::assemble::Assembler;
use bulge_llm::protocol::anthropic::AnthropicMessages;
use bulge_llm::protocol::openai_chat::OpenAiChat;
use bulge_llm::protocol::{EncodeContext, WireProtocol};
use bulge_llm::sse::SseParser;
use bulge_llm::*;

fn run(protocol: &dyn WireProtocol, model: &str, wire: &str, chunk_size: usize) -> assemble::Assembled {
    let mut parser = SseParser::new();
    let mut decoder = protocol.decoder(model);
    let mut assembler = Assembler::new();
    for piece in wire.as_bytes().chunks(chunk_size) {
        for event in parser.push(piece).events {
            for chunk in decoder.on_event(event).expect("decode") {
                assembler.push(&chunk);
            }
        }
    }
    for chunk in decoder.on_close().expect("close") {
        assembler.push(&chunk);
    }
    assert!(assembler.is_finished());
    assembler.finish(model)
}

fn sse(events: &[(&str, &str)]) -> String {
    events.iter().map(|(name, data)| format!("event: {name}\ndata: {data}\n\n")).collect()
}

#[test]
fn anthropic_stream_assembles_into_a_replayable_tool_turn() {
    let wire = sse(&[
        ("message_start", r#"{"type":"message_start","message":{"usage":{"input_tokens":10,"cache_read_input_tokens":90,"output_tokens":0}}}"#),
        ("content_block_start", r#"{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}"#),
        ("content_block_delta", r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"需要讀檔"}}"#),
        ("content_block_delta", r#"{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig-1"}}"#),
        ("content_block_stop", r#"{"type":"content_block_stop","index":0}"#),
        ("content_block_start", r#"{"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"call-1","name":"read","input":{}}}"#),
        ("content_block_delta", r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"path\":"}}"#),
        ("content_block_delta", r#"{"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"\"a.txt\"}"}}"#),
        ("content_block_stop", r#"{"type":"content_block_stop","index":1}"#),
        ("message_delta", r#"{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":20}}"#),
        ("message_stop", r#"{"type":"message_stop"}"#),
    ]);
    // Byte-at-a-time and whole-stream feeding must assemble identically.
    let whole = run(&AnthropicMessages, "m1", &wire, wire.len());
    let bytewise = run(&AnthropicMessages, "m1", &wire, 1);
    assert_eq!(whole, bytewise);

    assert_eq!(whole.finish, FinishReason::ToolCalls);
    assert_eq!(whole.usage.cache_read_tokens, 90);
    assert_eq!(whole.usage.output_tokens, 20);
    assert_eq!(
        whole.message.content,
        vec![
            ContentBlock::Reasoning { text: "需要讀檔".into(), signature: Some("sig-1".into()) },
            ContentBlock::ToolCall { id: "call-1".into(), name: "read".into(), arguments: r#"{"path":"a.txt"}"#.into() },
        ]
    );

    // The assembled turn plus its tool result must encode back for the same model
    // (signature kept) and for another model (signature dropped).
    let request = |model: &str| GenerateRequest {
        model: model.into(),
        messages: vec![
            Message::text(Role::System, "sys"),
            Message::text(Role::User, "讀 a.txt"),
            whole.message.clone(),
            Message::tool_result("call-1", "hello", false),
        ],
        tools: vec![],
        tool_choice: ToolChoice::Auto,
        max_tokens: None,
        temperature: None,
        stop: vec![],
        reasoning_effort: None,
        purpose: Purpose::Conversation,
    };
    let info = |id: &str| ModelInfo {
        id: id.into(),
        context_window: 128_000,
        max_tokens: 8_000,
        system_prompt_update: SystemPromptUpdate::InHistory,
        deferred_tools: true,
        images: false,
        reasoning: true,
    };
    let same = AnthropicMessages.encode(&request("m1"), &EncodeContext { model: &info("m1"), default_max_tokens: 4096 }).expect("encode");
    assert!(same.to_string().contains("sig-1"));
    let other = AnthropicMessages.encode(&request("m2"), &EncodeContext { model: &info("m2"), default_max_tokens: 4096 }).expect("encode");
    assert!(!other.to_string().contains("sig-1"));
}

#[test]
fn openai_stream_assembles_parallel_tool_calls() {
    let data = [
        r#"{"choices":[{"index":0,"delta":{"reasoning_content":"想一下"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"content":"好的"}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","function":{"name":"read","arguments":"{\"pa"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"th\":\"x\"}"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"b","function":{"name":"grep","arguments":"{}"}}]}}]}"#,
        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        r#"{"choices":[],"usage":{"prompt_tokens":100,"prompt_cache_hit_tokens":80,"completion_tokens":7}}"#,
        "[DONE]",
    ];
    let wire: String = data.iter().map(|d| format!("data: {d}\n\n")).collect();
    let out = run(&OpenAiChat, "m1", &wire, 7);
    assert_eq!(out.finish, FinishReason::ToolCalls);
    assert_eq!(out.usage.input_tokens, 20);
    assert_eq!(out.usage.cache_read_tokens, 80);
    let calls: Vec<_> = out
        .message
        .content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::ToolCall { id, arguments, .. } => Some((id.as_str(), arguments.as_str())),
            _ => None,
        })
        .collect();
    assert_eq!(calls, vec![("a", r#"{"path":"x"}"#), ("b", "{}")]);
}
