use super::*;
use crate::types::{ModelInfo, Purpose, SystemPromptUpdate, ToolSchema};

fn model(reasoning: bool) -> ModelInfo {
    ModelInfo {
        id: "test-model".to_owned(),
        context_window: 128_000,
        max_tokens: 4_096,
        system_prompt_update: SystemPromptUpdate::LeadingOnly,
        deferred_tools: false,
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
        purpose: Purpose::Conversation,
    }
}

fn encode(request: &GenerateRequest, model: &ModelInfo) -> Value {
    OpenAiChat
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
    OpenAiChat
        .encode(
            request,
            &EncodeContext {
                model,
                default_max_tokens: 1_024,
            },
        )
        .expect_err("encode should fail")
}

fn assistant(blocks: Vec<ContentBlock>, source_model: Option<&str>) -> Message {
    Message {
        role: Role::Assistant,
        content: blocks,
        tool_call_id: None,
        is_error: None,
        source_model: source_model.map(str::to_owned),
    }
}

fn tool_call(id: &str, name: &str, arguments: &str) -> ContentBlock {
    ContentBlock::ToolCall {
        id: id.to_owned(),
        name: name.to_owned(),
        arguments: arguments.to_owned(),
    }
}

fn sse(value: Value) -> SseEvent {
    SseEvent {
        event: None,
        data: value.to_string(),
    }
}

fn feed(decoder: &mut OpenAiChatDecoder, value: Value) -> Vec<StreamChunk> {
    decoder.on_event(sse(value)).expect("event")
}

fn feed_done(decoder: &mut OpenAiChatDecoder) -> Vec<StreamChunk> {
    decoder
        .on_event(SseEvent {
            event: None,
            data: "[DONE]".to_owned(),
        })
        .expect("[DONE]")
}

#[test]
fn mid_history_system_updates_are_each_emitted_in_order() {
    let body = encode(
        &request(vec![
            Message::text(Role::System, "base"),
            Message::text(Role::User, "hello"),
            Message::text(Role::System, "update"),
            Message::text(Role::Assistant, "first"),
        ]),
        &model(true),
    );
    assert_eq!(body["model"], "test-model");
    assert_eq!(body["stream"], true);
    assert_eq!(body["stream_options"]["include_usage"], true);
    assert_eq!(body["max_tokens"], 4_096);
    let messages = body["messages"].as_array().expect("messages");
    assert_eq!(messages.len(), 4);
    assert_eq!(messages[0]["role"], "system");
    assert_eq!(messages[0]["content"], "base");
    assert_eq!(messages[1]["role"], "user");
    assert_eq!(messages[1]["content"], "hello");
    assert_eq!(messages[2]["role"], "system");
    assert_eq!(messages[2]["content"], "update");
    assert_eq!(messages[3]["role"], "assistant");
    assert_eq!(messages[3]["content"], "first");
}

#[test]
fn reasoning_is_replayed_only_for_the_same_source_model() {
    let reasoning = || {
        assistant(
            vec![
                ContentBlock::Reasoning {
                    text: "think".to_owned(),
                    signature: Some("sig".to_owned()),
                },
                ContentBlock::Text {
                    text: "answer".to_owned(),
                },
            ],
            Some("test-model"),
        )
    };
    let same = encode(&request(vec![reasoning()]), &model(true));
    assert_eq!(same["messages"][0]["content"], "answer");
    assert_eq!(same["messages"][0]["reasoning_content"], "think");

    for source in [Some("other-model"), None] {
        let mut message = reasoning();
        message.source_model = source.map(str::to_owned);
        let body = encode(&request(vec![message]), &model(true));
        assert_eq!(body["messages"][0]["content"], "answer");
        assert!(body["messages"][0].get("reasoning_content").is_none());
    }
}

#[test]
fn tool_pairing_errors_are_invalid_requests() {
    let orphan = encode_error(
        &request(vec![Message::tool_result("missing", "result", false)]),
        &model(true),
    );
    assert_eq!(orphan.code, ErrorCode::InvalidRequest);

    let unresolved = encode_error(
        &request(vec![assistant(
            vec![tool_call("call-1", "lookup", "{}")],
            None,
        )]),
        &model(true),
    );
    assert_eq!(unresolved.code, ErrorCode::InvalidRequest);

    let duplicate = encode_error(
        &request(vec![assistant(
            vec![
                tool_call("call-1", "lookup", "{}"),
                tool_call("call-1", "lookup", "{}"),
            ],
            None,
        )]),
        &model(true),
    );
    assert_eq!(duplicate.code, ErrorCode::InvalidRequest);

    let broken_sequence = encode_error(
        &request(vec![
            assistant(vec![tool_call("call-1", "lookup", "{}")], None),
            Message::text(Role::User, "not a result"),
            Message::tool_result("call-1", "too late", false),
        ]),
        &model(true),
    );
    assert_eq!(broken_sequence.code, ErrorCode::InvalidRequest);
}

#[test]
fn images_are_encoded_as_data_uri_image_urls() {
    let body = encode(
        &request(vec![Message {
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
        }]),
        &model(true),
    );
    let content = body["messages"][0]["content"].as_array().expect("content");
    assert_eq!(content[0]["type"], "text");
    assert_eq!(content[0]["text"], "look");
    assert_eq!(content[1]["type"], "image_url");
    assert_eq!(
        content[1]["image_url"]["url"],
        "data:image/png;base64,aGVsbG8="
    );

    let text_only = encode(
        &request(vec![Message::text(Role::User, "plain")]),
        &model(true),
    );
    assert_eq!(text_only["messages"][0]["content"], "plain");
}

#[test]
fn reasoning_effort_is_gated_by_the_model_capability() {
    let on = model(true);
    let default = encode(&request(vec![Message::text(Role::User, "hi")]), &on);
    assert_eq!(default["reasoning_effort"], "high");

    for (effort, expected) in [
        (ReasoningEffort::Low, Some("low")),
        (ReasoningEffort::Medium, Some("medium")),
        (ReasoningEffort::High, Some("high")),
        (ReasoningEffort::Max, Some("high")),
        (ReasoningEffort::Off, Some("none")),
    ] {
        let mut req = request(vec![Message::text(Role::User, "hi")]);
        req.reasoning_effort = Some(effort);
        let body = encode(&req, &on);
        match expected {
            Some(expected) => assert_eq!(body["reasoning_effort"], expected),
            None => assert!(body.get("reasoning_effort").is_none()),
        }
    }

    // A model default applies to calls that set none, and only to them.
    let mut medium = model(true);
    medium.default_effort = Some(ReasoningEffort::Medium);
    assert_eq!(encode(&request(vec![Message::text(Role::User, "hi")]), &medium)["reasoning_effort"], "medium");
    let mut req = request(vec![Message::text(Role::User, "hi")]);
    req.reasoning_effort = Some(ReasoningEffort::Low);
    assert_eq!(encode(&req, &medium)["reasoning_effort"], "low");

    let off = model(false);
    let body = encode(&request(vec![Message::text(Role::User, "hi")]), &off);
    assert!(body.get("reasoning_effort").is_none());
    let mut req = request(vec![Message::text(Role::User, "hi")]);
    req.reasoning_effort = Some(ReasoningEffort::High);
    let body = encode(&req, &off);
    assert!(body.get("reasoning_effort").is_none());
}

#[test]
fn tools_are_declared_normally_even_when_deferred() {
    let mut req = request(vec![Message::text(Role::User, "hi")]);
    req.tools = vec![ToolSchema {
        name: "lookup".to_owned(),
        description: "find a thing".to_owned(),
        parameters: json!({"type": "object"}),
        defer_loading: true,
    }];
    let body = encode(&req, &model(true));
    let tool = &body["tools"][0];
    assert_eq!(tool["type"], "function");
    assert_eq!(tool["function"]["name"], "lookup");
    assert_eq!(tool["function"]["description"], "find a thing");
    assert_eq!(tool["function"]["parameters"], json!({"type": "object"}));
    assert!(tool.get("defer_loading").is_none());
    assert!(tool["function"].get("defer_loading").is_none());

    let none = encode(
        &request(vec![Message::text(Role::User, "hi")]),
        &model(true),
    );
    assert!(none.get("tools").is_none());
}

#[test]
fn tool_messages_join_text_blocks_and_tool_calls_keep_raw_arguments() {
    let body = encode(
        &request(vec![
            assistant(
                vec![
                    ContentBlock::Text {
                        text: "calling".to_owned(),
                    },
                    tool_call("call-1", "lookup", "{\"q\":1}"),
                ],
                None,
            ),
            Message {
                role: Role::Tool,
                content: vec![
                    ContentBlock::Text {
                        text: "one".to_owned(),
                    },
                    ContentBlock::Text {
                        text: "two".to_owned(),
                    },
                ],
                tool_call_id: Some("call-1".to_owned()),
                is_error: None,
                source_model: None,
            },
        ]),
        &model(true),
    );
    let messages = body["messages"].as_array().expect("messages");
    assert_eq!(messages[0]["content"], "calling");
    assert_eq!(messages[0]["tool_calls"][0]["id"], "call-1");
    assert_eq!(messages[0]["tool_calls"][0]["type"], "function");
    assert_eq!(messages[0]["tool_calls"][0]["function"]["name"], "lookup");
    assert_eq!(
        messages[0]["tool_calls"][0]["function"]["arguments"],
        "{\"q\":1}"
    );
    assert_eq!(messages[1]["role"], "tool");
    assert_eq!(messages[1]["tool_call_id"], "call-1");
    assert_eq!(messages[1]["content"], "one\ntwo");

    let tool_only = encode(
        &request(vec![
            assistant(vec![tool_call("call-1", "lookup", "{}")], None),
            Message::tool_result("call-1", "result", false),
        ]),
        &model(true),
    );
    assert!(tool_only["messages"][0]["content"].is_null());
}

#[test]
fn unsupported_blocks_are_reported() {
    let system_tool_change = encode_error(
        &request(vec![Message {
            role: Role::System,
            content: vec![ContentBlock::ToolAddition {
                name: "lookup".to_owned(),
            }],
            tool_call_id: None,
            is_error: None,
            source_model: None,
        }]),
        &model(true),
    );
    assert_eq!(system_tool_change.code, ErrorCode::UnsupportedContent);

    let assistant_image = encode_error(
        &request(vec![assistant(
            vec![ContentBlock::Image {
                media_type: "image/png".to_owned(),
                data: "aGVsbG8=".to_owned(),
            }],
            None,
        )]),
        &model(true),
    );
    assert_eq!(assistant_image.code, ErrorCode::UnsupportedContent);
}

#[test]
fn decoder_translates_reasoning_text_parallel_tools_usage_and_done() {
    let mut decoder = OpenAiChatDecoder::new();
    let mut chunks = Vec::new();
    chunks.extend(feed(
        &mut decoder,
        json!({
            "choices": [{ "delta": { "reasoning_content": "think" } }]
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({ "choices": [{ "delta": { "content": "Hello" } }] }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({ "choices": [{ "delta": { "content": " world" } }] }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "choices": [{
                "delta": {
                    "tool_calls": [
                        {
                            "index": 0,
                            "id": "call-1",
                            "type": "function",
                            "function": { "name": "lookup", "arguments": "{\"q\":" }
                        },
                        {
                            "index": 1,
                            "id": "call-2",
                            "type": "function",
                            "function": { "name": "other", "arguments": "{\"x\":" }
                        }
                    ]
                }
            }]
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "choices": [{
                "delta": {
                    "tool_calls": [
                        { "index": 0, "function": { "arguments": "1}" } }
                    ]
                }
            }]
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "choices": [{
                "delta": {
                    "tool_calls": [
                        { "index": 1, "function": { "arguments": "2}" } }
                    ]
                }
            }]
        }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({ "choices": [{ "delta": {}, "finish_reason": "tool_calls" }] }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "choices": [],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15,
                "prompt_tokens_details": { "cached_tokens": 3 },
                "completion_tokens_details": { "reasoning_tokens": 2 }
            }
        }),
    ));
    chunks.extend(feed_done(&mut decoder));

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
                    signature: None
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
                id: "call-1".to_owned(),
                name: Some("lookup".to_owned()),
                arguments_delta: "{\"q\":".to_owned()
            },
            StreamChunk::BlockStart {
                index: 3,
                kind: BlockKind::ToolCall
            },
            StreamChunk::ToolCallDelta {
                index: 3,
                id: "call-2".to_owned(),
                name: Some("other".to_owned()),
                arguments_delta: "{\"x\":".to_owned()
            },
            StreamChunk::ToolCallDelta {
                index: 2,
                id: "call-1".to_owned(),
                name: None,
                arguments_delta: "1}".to_owned()
            },
            StreamChunk::ToolCallDelta {
                index: 3,
                id: "call-2".to_owned(),
                name: None,
                arguments_delta: "2}".to_owned()
            },
            StreamChunk::BlockEnd {
                index: 2,
                block: ContentBlock::ToolCall {
                    id: "call-1".to_owned(),
                    name: "lookup".to_owned(),
                    arguments: "{\"q\":1}".to_owned()
                }
            },
            StreamChunk::BlockEnd {
                index: 3,
                block: ContentBlock::ToolCall {
                    id: "call-2".to_owned(),
                    name: "other".to_owned(),
                    arguments: "{\"x\":2}".to_owned()
                }
            },
            StreamChunk::Usage(TokenUsage {
                input_tokens: 7,
                output_tokens: 5,
                cache_read_tokens: 3,
                cache_write_tokens: 0,
                reasoning_tokens: 2
            }),
            StreamChunk::Finish(FinishReason::ToolCalls),
        ]
    );
    assert!(feed_done(&mut decoder).is_empty());
}

#[test]
fn deepseek_cache_hits_are_subtracted_from_prompt_tokens() {
    let mut decoder = OpenAiChatDecoder::new();
    let mut chunks = feed(
        &mut decoder,
        json!({ "choices": [{ "delta": { "content": "hi" } }] }),
    );
    chunks.extend(feed(
        &mut decoder,
        json!({ "choices": [{ "delta": {}, "finish_reason": "stop" }] }),
    ));
    chunks.extend(feed(
        &mut decoder,
        json!({
            "choices": [],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 10,
                "prompt_cache_hit_tokens": 40,
                "completion_tokens_details": { "reasoning_tokens": 1 }
            }
        }),
    ));
    chunks.extend(feed_done(&mut decoder));
    assert!(matches!(
        &chunks[chunks.len() - 2],
        StreamChunk::Usage(TokenUsage {
            input_tokens: 60,
            output_tokens: 10,
            cache_read_tokens: 40,
            cache_write_tokens: 0,
            reasoning_tokens: 1,
        })
    ));
    assert_eq!(
        chunks.last(),
        Some(&StreamChunk::Finish(FinishReason::Stop))
    );
}

#[test]
fn on_close_finishes_when_a_finish_reason_was_seen() {
    let mut decoder = OpenAiChatDecoder::new();
    let mut chunks = feed(
        &mut decoder,
        json!({ "choices": [{ "delta": { "content": "hi" } }] }),
    );
    chunks.extend(feed(
        &mut decoder,
        json!({ "choices": [{ "delta": {}, "finish_reason": "stop" }] }),
    ));
    assert!(matches!(
        chunks.last(),
        Some(StreamChunk::BlockEnd {
            index: 0,
            block: ContentBlock::Text { .. }
        })
    ));

    let closed = decoder.on_close().expect("close");
    assert!(matches!(
        closed.as_slice(),
        [
            StreamChunk::Usage(_),
            StreamChunk::Finish(FinishReason::Stop)
        ]
    ));
    assert!(decoder.on_close().expect("second close").is_empty());
}

#[test]
fn on_close_without_done_or_finish_reason_is_stream_closed() {
    let mut decoder = OpenAiChatDecoder::new();
    feed(
        &mut decoder,
        json!({ "choices": [{ "delta": { "content": "hi" } }] }),
    );
    let error = decoder.on_close().expect_err("should fail");
    assert_eq!(error.code, ErrorCode::StreamClosed);
}

#[test]
fn in_band_errors_are_classified() {
    let mut decoder = OpenAiChatDecoder::new();
    let error = decoder
        .on_event(sse(json!({
            "error": { "type": "rate_limit_error", "message": "slow down" }
        })))
        .expect_err("in-band error");
    assert_eq!(error.code, ErrorCode::RateLimit);
}

#[test]
fn unsupported_finish_reasons_are_malformed() {
    let mut decoder = OpenAiChatDecoder::new();
    let error = decoder
        .on_event(sse(json!({
            "choices": [{ "delta": {}, "finish_reason": "banana" }]
        })))
        .expect_err("unknown finish reason");
    assert_eq!(error.code, ErrorCode::MalformedResponse);
}
