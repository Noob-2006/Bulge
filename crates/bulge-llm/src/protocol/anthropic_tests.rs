use super::*;
use crate::types::{ModelInfo, ToolSchema};

fn model(
    system_prompt_update: SystemPromptUpdate,
    reasoning: bool,
    deferred_tools: bool,
) -> ModelInfo {
    ModelInfo {
        id: "test-model".to_owned(),
        context_window: 128_000,
        max_tokens: 4_096,
        system_prompt_update,
        deferred_tools,
        images: true,
        reasoning,
        default_effort: None,
    }
}

fn request(messages: Vec<Message>) -> GenerateRequest {
    GenerateRequest {
        model: "test-model".to_owned(),
        messages,
        tools: Vec::new(),
        max_tokens: None,
        temperature: None,
        stop: Vec::new(),
        reasoning_effort: None,
        purpose: crate::types::Purpose::Conversation,
    }
}

fn encode(request: &GenerateRequest, model: &ModelInfo) -> Value {
    AnthropicMessages
        .encode(
            request,
            &EncodeContext {
                model,
                default_max_tokens: 1_024,
            },
        )
        .expect("encode")
}

fn encode_error(request: &GenerateRequest, model: &ModelInfo) -> LlmError {
    AnthropicMessages
        .encode(
            request,
            &EncodeContext {
                model,
                default_max_tokens: 1_024,
            },
        )
        .expect_err("encode should fail")
}

fn assistant_text(text: &str) -> Message {
    Message::text(Role::Assistant, text)
}

fn tool_call(id: &str, name: &str, arguments: &str) -> ContentBlock {
    ContentBlock::ToolCall {
        id: id.to_owned(),
        name: name.to_owned(),
        arguments: arguments.to_owned(),
    }
}

fn tool_message(id: &str, text: &str) -> Message {
    Message::tool_result(id, text, false)
}

#[test]
fn in_history_system_updates_follow_the_preceding_user_turn() {
    let messages = vec![
        Message::text(Role::System, "base"),
        Message::text(Role::User, "hello"),
        Message::text(Role::System, "update"),
        assistant_text("first"),
        Message::text(Role::User, "again"),
        assistant_text("second"),
    ];
    let body = encode(
        &request(messages),
        &model(SystemPromptUpdate::InHistory, true, false),
    );
    assert_eq!(body["system"], "base");
    let turns = body["messages"].as_array().expect("messages");
    assert_eq!(turns.len(), 5);
    assert_eq!(turns[0]["role"], "user");
    assert_eq!(turns[0]["content"][0]["text"], "hello");
    assert_eq!(turns[1]["role"], "system");
    assert_eq!(turns[1]["content"][0]["text"], "update");
    assert_eq!(turns[2]["role"], "assistant");
    assert_eq!(turns[3]["role"], "user");
    assert_eq!(turns[4]["role"], "assistant");
}

#[test]
fn in_history_update_without_a_user_turn_is_unsupported() {
    let messages = vec![
        Message::text(Role::System, "base"),
        Message::text(Role::System, "update"),
    ];
    let error = encode_error(
        &request(messages),
        &model(SystemPromptUpdate::InHistory, true, false),
    );
    assert_eq!(error.code, ErrorCode::UnsupportedContent);
}

#[test]
fn leading_only_system_updates_merge_into_the_top_level_prompt() {
    let messages = vec![
        Message::text(Role::System, "base"),
        Message::text(Role::User, "hello"),
        Message::text(Role::System, "extra"),
        assistant_text("ok"),
    ];
    let body = encode(
        &request(messages),
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    assert_eq!(body["system"], "base\n\nextra");
    let turns = body["messages"].as_array().expect("messages");
    assert_eq!(turns.len(), 2);
    assert_eq!(turns[0]["role"], "user");
    assert_eq!(turns[1]["role"], "assistant");
}

#[test]
fn signatures_are_replayed_only_for_the_same_source_model() {
    let reasoning = |source_model: Option<&str>| Message {
        role: Role::Assistant,
        content: vec![ContentBlock::Reasoning {
            text: "thinking".to_owned(),
            signature: Some("sig".to_owned()),
        }],
        tool_call_id: None,
        is_error: None,
        source_model: source_model.map(str::to_owned),
    };

    let same = encode(
        &request(vec![reasoning(Some("test-model"))]),
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    assert_eq!(same["messages"][0]["content"][0]["signature"], "sig");

    for source in [Some("other-model"), None] {
        let body = encode(
            &request(vec![reasoning(source)]),
            &model(SystemPromptUpdate::LeadingOnly, true, false),
        );
        let thinking = &body["messages"][0]["content"][0];
        assert_eq!(thinking["type"], "thinking");
        assert_eq!(thinking["thinking"], "thinking");
        assert!(thinking.get("signature").is_none());
    }
}

#[test]
fn invalid_tool_arguments_become_an_empty_object() {
    let message = Message {
        role: Role::Assistant,
        content: vec![
            tool_call("call-1", "lookup", "not json"),
            tool_call("call-2", "lookup", "[1,2]"),
        ],
        tool_call_id: None,
        is_error: None,
        source_model: None,
    };
    let body = encode(
        &request(vec![
            message,
            tool_message("call-1", "one"),
            tool_message("call-2", "two"),
        ]),
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    assert_eq!(body["messages"][0]["content"][0]["input"], json!({}));
    assert_eq!(body["messages"][0]["content"][1]["input"], json!({}));
}

#[test]
fn duplicate_tool_call_ids_are_invalid() {
    let message = Message {
        role: Role::Assistant,
        content: vec![
            tool_call("call-1", "lookup", "{}"),
            tool_call("call-1", "lookup", "{}"),
        ],
        tool_call_id: None,
        is_error: None,
        source_model: None,
    };
    let error = encode_error(
        &request(vec![message]),
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    assert_eq!(error.code, ErrorCode::InvalidRequest);
}

#[test]
fn tool_results_need_a_matching_call() {
    let error = encode_error(
        &request(vec![tool_message("missing", "result")]),
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    assert_eq!(error.code, ErrorCode::InvalidRequest);
}

#[test]
fn tool_calls_need_immediate_results() {
    let assistant = Message {
        role: Role::Assistant,
        content: vec![tool_call("call-1", "lookup", "{}")],
        tool_call_id: None,
        is_error: None,
        source_model: None,
    };
    let error = encode_error(
        &request(vec![assistant, Message::text(Role::User, "no result")]),
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    assert_eq!(error.code, ErrorCode::InvalidRequest);

    let assistant = Message {
        role: Role::Assistant,
        content: vec![tool_call("call-1", "lookup", "{}")],
        tool_call_id: None,
        is_error: None,
        source_model: None,
    };
    let error = encode_error(
        &request(vec![assistant]),
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    assert_eq!(error.code, ErrorCode::InvalidRequest);
}

#[test]
fn tool_results_move_to_the_front_of_the_answering_turn() {
    let assistant = Message {
        role: Role::Assistant,
        content: vec![tool_call("call-1", "lookup", "{\"q\":1}")],
        tool_call_id: None,
        is_error: None,
        source_model: None,
    };
    let body = encode(
        &request(vec![
            assistant,
            Message::text(Role::User, "note"),
            tool_message("call-1", "result"),
        ]),
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    let content = body["messages"][1]["content"].as_array().expect("content");
    assert_eq!(content.len(), 2);
    assert_eq!(content[0]["type"], "tool_result");
    assert_eq!(content[0]["tool_use_id"], "call-1");
    assert_eq!(content[1]["type"], "text");
    assert_eq!(content[1]["text"], "note");
}

#[test]
fn tool_changes_are_only_valid_in_system_messages() {
    let body = encode(
        &request(vec![
            Message {
                role: Role::System,
                content: vec![ContentBlock::ToolAddition {
                    name: "lookup".to_owned(),
                }],
                tool_call_id: None,
                is_error: None,
                source_model: None,
            },
            Message::text(Role::User, "hello"),
            Message::text(Role::System, "update"),
            assistant_text("ok"),
        ]),
        &model(SystemPromptUpdate::InHistory, true, false),
    );
    let turns = body["messages"].as_array().expect("messages");
    assert_eq!(turns[1]["role"], "system");
    assert_eq!(turns[1]["content"][0]["type"], "tool_addition");
    assert_eq!(turns[1]["content"][0]["tool"]["name"], "lookup");

    let error = encode_error(
        &request(vec![Message {
            role: Role::User,
            content: vec![ContentBlock::ToolRemoval {
                name: "lookup".to_owned(),
            }],
            tool_call_id: None,
            is_error: None,
            source_model: None,
        }]),
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    assert_eq!(error.code, ErrorCode::UnsupportedContent);
}

#[test]
fn images_and_stop_sequences_are_encoded() {
    let mut request = request(vec![Message {
        role: Role::User,
        content: vec![
            ContentBlock::Text {
                text: "look".to_owned(),
            },
            ContentBlock::Image {
                media_type: "image/png".to_owned(),
                data: "aGVsbG8=".to_owned(),
            },
        ],
        tool_call_id: None,
        is_error: None,
        source_model: None,
    }]);
    request.stop = vec!["STOP".to_owned()];
    let body = encode(
        &request,
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    assert_eq!(body["stop_sequences"], json!(["STOP"]));
    let content = &body["messages"][0]["content"];
    assert_eq!(content[1]["type"], "image");
    assert_eq!(content[1]["source"]["type"], "base64");
    assert_eq!(content[1]["source"]["media_type"], "image/png");
    assert_eq!(content[1]["source"]["data"], "aGVsbG8=");
}

#[test]
fn effort_defaults_and_overrides_switch_thinking() {
    let model_on = model(SystemPromptUpdate::LeadingOnly, true, false);
    let body = encode(&request(vec![Message::text(Role::User, "hi")]), &model_on);
    assert_eq!(body["thinking"]["type"], "enabled");
    assert_eq!(body["output_config"]["effort"], "high");

    let mut off = request(vec![Message::text(Role::User, "hi")]);
    off.reasoning_effort = Some(ReasoningEffort::Off);
    let body = encode(&off, &model_on);
    assert_eq!(body["thinking"]["type"], "disabled");
    assert!(body.get("output_config").is_none());

    let model_off = model(SystemPromptUpdate::LeadingOnly, false, false);
    let body = encode(&request(vec![Message::text(Role::User, "hi")]), &model_off);
    assert_eq!(body["thinking"]["type"], "disabled");
    assert!(body.get("output_config").is_none());

    let mut low = request(vec![Message::text(Role::User, "hi")]);
    low.reasoning_effort = Some(ReasoningEffort::Low);
    let body = encode(&low, &model_on);
    assert_eq!(body["output_config"]["effort"], "low");
}

#[test]
fn defer_loading_is_gated_by_the_model_capability_and_order_is_kept() {
    let mut request = request(vec![Message::text(Role::User, "hi")]);
    request.tools = vec![
        ToolSchema {
            name: "first".to_owned(),
            description: "one".to_owned(),
            parameters: json!({"type": "object"}),
            defer_loading: false,
        },
        ToolSchema {
            name: "second".to_owned(),
            description: "two".to_owned(),
            parameters: json!({"type": "object"}),
            defer_loading: true,
        },
    ];
    let body = encode(
        &request,
        &model(SystemPromptUpdate::LeadingOnly, true, true),
    );
    let tools = body["tools"].as_array().expect("tools");
    assert_eq!(tools[0]["name"], "first");
    assert!(tools[0].get("defer_loading").is_none());
    assert_eq!(tools[1]["name"], "second");
    assert_eq!(tools[1]["defer_loading"], true);

    let body = encode(
        &request,
        &model(SystemPromptUpdate::LeadingOnly, true, false),
    );
    assert!(body["tools"][1].get("defer_loading").is_none());
    assert_eq!(body["tools"][1]["description"], "two");
}

#[test]
fn max_tokens_falls_back_from_request_to_model_to_default() {
    let mut req = request(vec![Message::text(Role::User, "hi")]);
    let model = model(SystemPromptUpdate::LeadingOnly, true, false);
    assert_eq!(encode(&req, &model)["max_tokens"], 4_096);
    req.max_tokens = Some(12);
    assert_eq!(encode(&req, &model)["max_tokens"], 12);

    let mut no_model_limit = model.clone();
    no_model_limit.max_tokens = 0;
    let fallback = request(vec![Message::text(Role::User, "hi")]);
    assert_eq!(encode(&fallback, &no_model_limit)["max_tokens"], 1_024);
}

fn sse(value: Value) -> SseEvent {
    SseEvent {
        event: value.get("type").and_then(Value::as_str).map(str::to_owned),
        data: value.to_string(),
    }
}

fn feed(decoder: &mut AnthropicDecoder, value: Value) -> Vec<StreamChunk> {
    decoder.on_event(sse(value)).expect("event")
}

#[test]
fn decoder_translates_a_complete_mixed_stream() {
    let mut decoder = AnthropicDecoder::new();
    let mut chunks = Vec::new();
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "message_start",
            "message": { "usage": {
                "input_tokens": 10,
                "output_tokens": 1,
                "cache_read_input_tokens": 3,
                "cache_creation_input_tokens": 2
            }}
        }),
    ));
    chunks.extend(feed(&mut decoder, json!({"type": "ping"})));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "thinking", "thinking": "", "signature": "a"}
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "thinking_delta", "thinking": "think"}
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "signature_delta", "signature": "b"}
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "signature_delta", "signature": "c"}
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({"type": "content_block_stop", "index": 0}),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "content_block_start",
            "index": 1,
            "content_block": {"type": "text", "text": "Hello"}
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "content_block_delta",
            "index": 1,
            "delta": {"type": "text_delta", "text": " world"}
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({"type": "content_block_stop", "index": 1}),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "content_block_start",
            "index": 2,
            "content_block": {
                "type": "tool_use", "id": "tool-1", "name": "lookup", "input": {}
            }
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "content_block_delta",
            "index": 2,
            "delta": {"type": "input_json_delta", "partial_json": "{\"q\":"}
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "content_block_delta",
            "index": 2,
            "delta": {"type": "input_json_delta", "partial_json": "\"x\"}"}
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({"type": "content_block_stop", "index": 2}),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use"},
            "usage": {"output_tokens": 5}
        }),
    ));
    chunks.extend(feed(&mut decoder, json!({"type": "message_stop"})));

    assert_eq!(
        chunks,
        vec![
            StreamChunk::BlockStart {
                index: 0,
                kind: BlockKind::Reasoning
            },
            StreamChunk::ReasoningDelta {
                index: 0,
                text: "think".to_owned()
            },
            StreamChunk::BlockEnd {
                index: 0,
                block: ContentBlock::Reasoning {
                    text: "think".to_owned(),
                    signature: Some("abc".to_owned())
                }
            },
            StreamChunk::BlockStart {
                index: 1,
                kind: BlockKind::Text
            },
            StreamChunk::TextDelta {
                index: 1,
                text: "Hello".to_owned()
            },
            StreamChunk::TextDelta {
                index: 1,
                text: " world".to_owned()
            },
            StreamChunk::BlockEnd {
                index: 1,
                block: ContentBlock::Text {
                    text: "Hello world".to_owned()
                }
            },
            StreamChunk::BlockStart {
                index: 2,
                kind: BlockKind::ToolCall
            },
            StreamChunk::ToolCallDelta {
                index: 2,
                id: "tool-1".to_owned(),
                name: Some("lookup".to_owned()),
                arguments_delta: String::new()
            },
            StreamChunk::ToolCallDelta {
                index: 2,
                id: "tool-1".to_owned(),
                name: None,
                arguments_delta: "{\"q\":".to_owned()
            },
            StreamChunk::ToolCallDelta {
                index: 2,
                id: "tool-1".to_owned(),
                name: None,
                arguments_delta: "\"x\"}".to_owned()
            },
            StreamChunk::BlockEnd {
                index: 2,
                block: ContentBlock::ToolCall {
                    id: "tool-1".to_owned(),
                    name: "lookup".to_owned(),
                    arguments: "{\"q\":\"x\"}".to_owned()
                }
            },
            StreamChunk::Usage(TokenUsage {
                input_tokens: 10,
                output_tokens: 5,
                cache_read_tokens: 3,
                cache_write_tokens: 2,
                reasoning_tokens: 0
            }),
            StreamChunk::Finish(FinishReason::ToolCalls),
        ]
    );
    assert!(decoder.on_close().expect("closed").is_empty());
}

#[test]
fn truncated_tool_json_is_kept_on_max_tokens() {
    let mut decoder = AnthropicDecoder::new();
    feed(&mut decoder, json!({"type": "message_start"}));
    feed(
        &mut decoder,
        json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {
                "type": "tool_use", "id": "tool-1", "name": "lookup", "input": {}
            }
        }),
    );
    feed(
        &mut decoder,
        json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": "{\"q\":"}
        }),
    );
    let stopped = feed(
        &mut decoder,
        json!({"type": "content_block_stop", "index": 0}),
    );
    assert_eq!(
        stopped,
        vec![StreamChunk::BlockEnd {
            index: 0,
            block: ContentBlock::ToolCall {
                id: "tool-1".to_owned(),
                name: "lookup".to_owned(),
                arguments: "{\"q\":".to_owned()
            }
        }]
    );
    feed(
        &mut decoder,
        json!({
            "type": "message_delta",
            "delta": {"stop_reason": "max_tokens"}
        }),
    );
    let chunks = feed(&mut decoder, json!({"type": "message_stop"}));
    assert_eq!(
        chunks,
        vec![
            StreamChunk::Usage(TokenUsage::default()),
            StreamChunk::Finish(FinishReason::MaxTokens)
        ]
    );
}

#[test]
fn close_without_message_stop_is_stream_closed() {
    let mut decoder = AnthropicDecoder::new();
    feed(&mut decoder, json!({"type": "message_start"}));
    let error = decoder.on_close().expect_err("must be closed");
    assert_eq!(error.code, ErrorCode::StreamClosed);
}

#[test]
fn unknown_events_are_ignored() {
    let mut decoder = AnthropicDecoder::new();
    feed(&mut decoder, json!({"type": "message_start"}));
    assert!(feed(&mut decoder, json!({"type": "ping"})).is_empty());
    assert!(feed(&mut decoder, json!({"type": "provider_extension"})).is_empty());
    feed(
        &mut decoder,
        json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}),
    );
    let chunks = feed(&mut decoder, json!({"type": "message_stop"}));
    assert_eq!(
        chunks,
        vec![
            StreamChunk::Usage(TokenUsage::default()),
            StreamChunk::Finish(FinishReason::ToolCalls)
        ]
    );
}

#[test]
fn empty_stop_response_is_an_error() {
    let mut decoder = AnthropicDecoder::new();
    feed(&mut decoder, json!({"type": "message_start"}));
    feed(
        &mut decoder,
        json!({"type": "message_delta", "delta": {"stop_reason": "stop_sequence"}}),
    );
    let error = decoder
        .on_event(sse(json!({"type": "message_stop"})))
        .expect_err("empty response");
    assert_eq!(error.code, ErrorCode::EmptyResponse);
}

#[test]
fn error_events_are_classified() {
    let mut decoder = AnthropicDecoder::new();
    let error = decoder
        .on_event(sse(json!({
            "type": "error",
            "error": {"type": "invalid_request_error", "message": "bad input"}
        })))
        .expect_err("error event");
    assert_eq!(error.code, ErrorCode::InvalidRequest);
    assert_eq!(error.message, "bad input");
}

#[test]
fn malformed_tool_json_is_rejected_unless_truncated() {
    let mut decoder = AnthropicDecoder::new();
    feed(&mut decoder, json!({"type": "message_start"}));
    feed(
        &mut decoder,
        json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {
                "type": "tool_use", "id": "tool-1", "name": "lookup", "input": {}
            }
        }),
    );
    feed(
        &mut decoder,
        json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": "{\"q\":"}
        }),
    );
    feed(
        &mut decoder,
        json!({"type": "content_block_stop", "index": 0}),
    );
    feed(
        &mut decoder,
        json!({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}),
    );
    let error = decoder
        .on_event(sse(json!({"type": "message_stop"})))
        .expect_err("malformed tool json");
    assert_eq!(error.code, ErrorCode::MalformedResponse);
}
