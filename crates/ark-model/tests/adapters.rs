mod mock;

use ark_core::{Block, Cancel, Message, ModelRequest, ProviderErrorKind as K, Role, StopReason, StreamEvent, SystemSegment, ToolSchema};
use ark_model::{build_with_idle, ProviderConfig, WireFormat};
use mock::{serve, sse, End, Mock, Reply};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const FORMATS: [WireFormat; 4] = [WireFormat::OpenAiChat, WireFormat::OpenAiResponses, WireFormat::Anthropic, WireFormat::Gemini];

fn cfg(id: &str, format: WireFormat, base: &str) -> ProviderConfig {
    ProviderConfig {
        id: id.into(),
        format,
        base_url: base.into(),
        api_key_env: None,
        api_key: Some("sk-test".into()),
        headers: BTreeMap::new(),
        idle_timeout_secs: None,
    }
}

fn id_for(f: WireFormat) -> &'static str {
    match f {
        WireFormat::OpenAiChat => "deepseek",
        WireFormat::OpenAiResponses => "openai",
        WireFormat::Anthropic => "anthropic",
        WireFormat::Gemini => "gemini",
    }
}

fn simple_req() -> ModelRequest {
    ModelRequest {
        model: "m".into(),
        system: vec![SystemSegment { id: "id".into(), text: "be brief".into(), cache: true }],
        messages: vec![Message::user("hi")],
        tools: vec![ToolSchema { name: "read".into(), description: "Read a file".into(), input_schema: json!({"type":"object"}) }],
        max_tokens: 256,
        temperature: None,
        cache_after_message: None,
        reasoning: None,
    }
}

fn run(f: WireFormat, mock: &Mock, req: &ModelRequest, idle: Duration, cancel: &Cancel) -> (Result<ark_core::ModelResponse, ark_core::ProviderError>, Vec<StreamEvent>) {
    let p = build_with_idle(&cfg(id_for(f), f, &mock.base), idle).unwrap();
    let mut evs = Vec::new();
    let r = p.complete(req, &mut |e| evs.push(e), cancel);
    (r, evs)
}

fn go(f: WireFormat, reply: Reply) -> Result<ark_core::ModelResponse, ark_core::ProviderError> {
    let m = serve(reply);
    run(f, &m, &simple_req(), Duration::from_secs(5), &Cancel::new()).0
}

// ---------- per-format fixtures ----------

fn text_stream(f: WireFormat) -> Vec<&'static str> {
    match f {
        WireFormat::OpenAiChat => vec![
            r#"data: {"model":"m-1","choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}"#,
            r#"data: {"choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":null}]}"#,
            r#"data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
            r#"data: {"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":60}}}"#,
            "data: [DONE]",
        ],
        WireFormat::OpenAiResponses => vec![
            r#"data: {"type":"response.created","response":{}}"#,
            r#"data: {"type":"response.output_text.delta","delta":"Hel"}"#,
            r#"data: {"type":"response.output_text.delta","delta":"lo"}"#,
            r#"data: {"type":"response.output_item.done","item":{"type":"message"}}"#,
            r#"data: {"type":"response.completed","response":{"model":"m-1","usage":{"input_tokens":100,"output_tokens":5,"input_tokens_details":{"cached_tokens":60}}}}"#,
        ],
        WireFormat::Anthropic => vec![
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"m-1\",\"usage\":{\"input_tokens\":40,\"cache_read_input_tokens\":60,\"output_tokens\":1}}}",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}",
            "event: ping\ndata: {\"type\":\"ping\"}",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"lo\"}}",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}",
        ],
        WireFormat::Gemini => vec![
            r#"data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Hel"}]}}],"modelVersion":"m-1"}"#,
            r#"data: {"candidates":[{"content":{"parts":[{"text":"lo"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":5,"cachedContentTokenCount":60}}"#,
        ],
    }
}

fn mid_stream_error(f: WireFormat) -> (Vec<&'static str>, K) {
    match f {
        WireFormat::OpenAiChat => (
            vec![
                r#"data: {"choices":[{"index":0,"delta":{"content":"Hel"}}]}"#,
                r#"data: {"error":{"message":"Rate limit reached","type":"rate_limit_error"}}"#,
            ],
            K::RateLimited { retry_after: None },
        ),
        WireFormat::OpenAiResponses => (
            vec![
                r#"data: {"type":"response.output_text.delta","delta":"Hel"}"#,
                r#"data: {"type":"response.failed","response":{"error":{"code":"server_error","message":"boom"}}}"#,
            ],
            K::Server,
        ),
        WireFormat::Anthropic => (
            vec![
                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1}}}",
                "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}",
            ],
            K::Overloaded,
        ),
        WireFormat::Gemini => (
            vec![
                r#"data: {"candidates":[{"content":{"parts":[{"text":"Hel"}]}}]}"#,
                r#"data: {"error":{"code":503,"message":"The model is overloaded.","status":"UNAVAILABLE"}}"#,
            ],
            K::Overloaded,
        ),
    }
}

// ---------- happy paths (one per format) ----------

#[test]
fn text_streaming_and_usage_all_formats() {
    for f in FORMATS {
        let m = serve(sse(&text_stream(f)));
        let (r, evs) = run(f, &m, &simple_req(), Duration::from_secs(5), &Cancel::new());
        let r = r.unwrap_or_else(|e| panic!("{f:?}: {e}"));
        assert_eq!(r.message.text(), "Hello", "{f:?}");
        assert_eq!(r.stop, StopReason::EndTurn, "{f:?}");
        assert_eq!(r.model, "m-1", "{f:?}");
        assert_eq!((r.usage.input_tokens, r.usage.cache_read_tokens, r.usage.output_tokens), (40, 60, 5), "{f:?}");
        assert!(!r.usage.estimated, "{f:?}");
        let streamed: String = evs.iter().filter_map(|e| if let StreamEvent::TextDelta(t) = e { Some(t.as_str()) } else { None }).collect();
        assert_eq!(streamed, "Hello", "{f:?}");
    }
}

// ---------- failure matrix (every format) ----------

#[test]
fn http_status_errors_all_formats() {
    for f in FORMATS {
        let e = go(f, Reply::Status { code: 429, headers: vec![("retry-after", "3".into())], body: r#"{"error":{"message":"slow down"}}"#.into() }).unwrap_err();
        assert_eq!(e.kind, K::RateLimited { retry_after: Some(Duration::from_secs(3)) }, "{f:?}");
        assert_eq!(e.message, "slow down");
        assert!(e.is_retryable());

        let e = go(f, Reply::Status { code: 500, headers: vec![], body: "oops".into() }).unwrap_err();
        assert_eq!((e.kind.clone(), e.status), (K::Server, Some(500)), "{f:?}");

        let e = go(f, Reply::Status { code: 529, headers: vec![], body: "{}".into() }).unwrap_err();
        assert_eq!(e.kind, K::Overloaded, "{f:?}");

        let e = go(f, Reply::Status { code: 401, headers: vec![], body: r#"{"error":{"message":"invalid x-api-key"}}"#.into() }).unwrap_err();
        assert_eq!(e.kind, K::Auth, "{f:?}");
        assert!(!e.is_retryable() && e.allows_fallback());

        let e = go(f, Reply::Status { code: 400, headers: vec![], body: r#"{"error":{"message":"prompt is too long: 300000 tokens > 200000 maximum"}}"#.into() }).unwrap_err();
        assert_eq!(e.kind, K::ContextOverflow, "{f:?}");

        let e = go(f, Reply::Status { code: 400, headers: vec![], body: r#"{"error":{"message":"tools.0.name: invalid"}}"#.into() }).unwrap_err();
        assert_eq!(e.kind, K::BadRequest, "{f:?}");
        assert!(!e.allows_fallback());
    }
}

#[test]
fn error_event_mid_stream_all_formats() {
    for f in FORMATS {
        let (chunks, kind) = mid_stream_error(f);
        assert_eq!(go(f, sse(&chunks)).unwrap_err().kind, kind, "{f:?}");
    }
}

#[test]
fn truncated_stream_without_terminal_event_is_protocol_error() {
    for f in FORMATS {
        let full = text_stream(f);
        // Everything except the terminal event(s), with a clean HTTP close.
        let cut = match f {
            WireFormat::OpenAiChat => &full[..2],
            WireFormat::Gemini => &full[..1],
            _ => &full[..full.len() - 1],
        };
        let e = go(f, sse(cut)).unwrap_err();
        assert_eq!(e.kind, K::Protocol, "{f:?}: {e}");
        assert!(e.is_retryable());
    }
}

#[test]
fn connection_dropped_mid_body_is_retryable() {
    for f in FORMATS {
        let chunks = text_stream(f)[..1].iter().map(|c| format!("{c}\n\n")).collect();
        let e = go(f, Reply::Sse { chunks, end: End::Abort }).unwrap_err();
        assert!(matches!(e.kind, K::Network | K::Protocol), "{f:?}: {e}");
        assert!(e.is_retryable());
    }
}

#[test]
fn malformed_json_chunk_is_protocol_error() {
    for f in FORMATS {
        let e = go(f, sse(&["data: {\"choices\":[{\"delta\":"])).unwrap_err();
        assert_eq!(e.kind, K::Protocol, "{f:?}");
        assert!(e.message.contains("malformed"), "{}", e.message);
    }
}

#[test]
fn json_error_body_with_status_200_is_classified() {
    for f in FORMATS {
        let e = go(f, Reply::Status { code: 200, headers: vec![], body: r#"{"error":{"type":"authentication_error","message":"bad key"}}"#.into() }).unwrap_err();
        assert_eq!(e.kind, K::Auth, "{f:?}");
    }
}

#[test]
fn cancellation_mid_stream_returns_promptly() {
    for f in FORMATS {
        let chunks = text_stream(f)[..1].iter().map(|c| format!("{c}\n\n")).collect();
        let m = serve(Reply::Sse { chunks, end: End::Hang });
        let cancel = Cancel::new();
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            c2.cancel();
        });
        let t = Instant::now();
        let (r, _) = run(f, &m, &simple_req(), Duration::from_secs(20), &cancel);
        assert_eq!(r.unwrap_err().kind, K::Cancelled, "{f:?}");
        assert!(t.elapsed() < Duration::from_secs(2), "{f:?} took {:?}", t.elapsed());
    }
}

#[test]
fn idle_timeout_after_partial_stream() {
    for f in FORMATS {
        let chunks = text_stream(f)[..1].iter().map(|c| format!("{c}\n\n")).collect();
        let m = serve(Reply::Sse { chunks, end: End::Hang });
        let t = Instant::now();
        let (r, _) = run(f, &m, &simple_req(), Duration::from_millis(300), &Cancel::new());
        let e = r.unwrap_err();
        assert_eq!(e.kind, K::Timeout, "{f:?}");
        assert!(e.is_retryable());
        assert!(t.elapsed() < Duration::from_secs(3), "{f:?}");
    }
}

#[test]
fn server_that_never_responds_times_out() {
    for f in FORMATS {
        let m = serve(Reply::Hang);
        let t = Instant::now();
        let (r, _) = run(f, &m, &simple_req(), Duration::from_millis(300), &Cancel::new());
        assert_eq!(r.unwrap_err().kind, K::Timeout, "{f:?}");
        assert!(t.elapsed() < Duration::from_secs(3));
    }
}

#[test]
fn connection_refused_is_network_error() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    for f in FORMATS {
        let p = build_with_idle(&cfg(id_for(f), f, &format!("http://127.0.0.1:{port}")), Duration::from_secs(5)).unwrap();
        let e = p.complete(&simple_req(), &mut |_| {}, &Cancel::new()).unwrap_err();
        assert_eq!(e.kind, K::Network, "{f:?}: {e}");
    }
}

#[test]
fn missing_usage_is_estimated() {
    let m = serve(sse(&[r#"data: {"choices":[{"delta":{"content":"hello world"},"finish_reason":"stop"}]}"#, "data: [DONE]"]));
    let (r, _) = run(WireFormat::OpenAiChat, &m, &simple_req(), Duration::from_secs(5), &Cancel::new());
    let u = r.unwrap().usage;
    assert!(u.estimated && u.input_tokens > 0 && u.output_tokens > 0);
}

// ---------- tool round-trips & request bodies ----------

fn tool_history() -> ModelRequest {
    let mut r = simple_req();
    r.system.push(SystemSegment { id: "volatile".into(), text: "now: 12:00".into(), cache: false });
    r.messages = vec![
        Message::user("read a"),
        Message {
            role: Role::Assistant,
            content: vec![
                Block::Thinking { text: "r1".into(), signature: Some("SIG".into()) },
                Block::Text { text: "".into() },
                Block::ToolUse { id: "call_1".into(), name: "read".into(), input: json!({"path": "a"}) },
            ],
        },
        Message {
            role: Role::User,
            content: vec![
                Block::ToolResult { tool_use_id: "call_1".into(), content: "file body".into(), is_error: false },
                Block::text("next"),
            ],
        },
    ];
    r.cache_after_message = Some(1);
    r
}

#[test]
fn openai_chat_tool_calls_and_deepseek_reasoning_echo() {
    let m = serve(sse(&[
        r#"data: {"choices":[{"delta":{"reasoning_content":"think"}}]}"#,
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"read","arguments":"{\"pa"}}]}}]}"#,
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"th\":\"x\"}"}}]}}]}"#,
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"ls","arguments":""}}]}}]}"#,
        r#"data: {"choices":[{"delta":{"tool_calls":[{"index":2,"id":"call_c","function":{"name":"bad","arguments":"{oops"}}]}}]}"#,
        r#"data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
        "data: [DONE]",
    ]));
    let (r, evs) = run(WireFormat::OpenAiChat, &m, &tool_history(), Duration::from_secs(5), &Cancel::new());
    let r = r.unwrap();
    assert_eq!(r.stop, StopReason::ToolUse);
    let uses: Vec<_> = r.message.tool_uses().map(|(i, n, a)| (i.to_string(), n.to_string(), a.clone())).collect();
    assert_eq!(uses[0], ("call_a".into(), "read".into(), json!({"path":"x"})));
    assert_eq!(uses[1], ("call_b".into(), "ls".into(), json!({})));
    assert_eq!(uses[2].2, json!({"__invalid_json": "{oops"}));
    assert!(matches!(&r.message.content[0], Block::Thinking { text, .. } if text == "think"));
    assert!(evs.iter().any(|e| matches!(e, StreamEvent::ToolUseStart { name, .. } if name == "read")));

    let req = m.request();
    assert_eq!(req.path, "/chat/completions");
    assert_eq!(req.header("authorization"), Some("Bearer sk-test"));
    let b = &req.body;
    assert_eq!(b["max_tokens"], 256);
    assert!(b.get("max_completion_tokens").is_none());
    let msgs = b["messages"].as_array().unwrap();
    assert_eq!(msgs[0]["role"], "system");
    assert_eq!(msgs[0]["content"], "be brief\n\nnow: 12:00");
    assert_eq!(msgs[2]["reasoning_content"], "r1");
    assert_eq!(msgs[2]["content"], serde_json::Value::Null);
    assert_eq!(msgs[2]["tool_calls"][0]["function"]["arguments"], r#"{"path":"a"}"#);
    assert_eq!(msgs[3], json!({"role":"tool","tool_call_id":"call_1","content":"file body"}));
    assert_eq!(msgs[4], json!({"role":"user","content":"next"}));
    assert_eq!(b["tools"][0]["function"]["name"], "read");
    assert_eq!(b["stream_options"]["include_usage"], true);
}

#[test]
fn openai_proper_uses_max_completion_tokens() {
    let m = serve(sse(&text_stream(WireFormat::OpenAiChat)));
    let p = build_with_idle(&cfg("openai-chat", WireFormat::OpenAiChat, &m.base), Duration::from_secs(5)).unwrap();
    p.complete(&simple_req(), &mut |_| {}, &Cancel::new()).unwrap();
    let b = m.request().body;
    assert_eq!(b["max_completion_tokens"], 256);
    assert!(b.get("max_tokens").is_none());
}

#[test]
fn openai_chat_tool_call_without_name_is_protocol_error() {
    let e = go(
        WireFormat::OpenAiChat,
        sse(&[r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{}"}}]},"finish_reason":"tool_calls"}]}"#, "data: [DONE]"]),
    )
    .unwrap_err();
    assert_eq!(e.kind, K::Protocol);
}

#[test]
fn responses_tool_call_and_reasoning_roundtrip() {
    let m = serve(sse(&[
        r#"data: {"type":"response.output_item.added","item":{"type":"reasoning","id":"rs_1"}}"#,
        r#"data: {"type":"response.reasoning_summary_text.delta","delta":"plan"}"#,
        r#"data: {"type":"response.output_item.done","item":{"type":"reasoning","id":"rs_1","encrypted_content":"ENC"}}"#,
        r#"data: {"type":"response.output_text.delta","delta":"Hi "}"#,
        r#"data: {"type":"response.output_item.done","item":{"type":"message"}}"#,
        r#"data: {"type":"response.output_item.added","item":{"type":"function_call","call_id":"c1","name":"read"}}"#,
        r#"data: {"type":"response.function_call_arguments.delta","delta":"{\"path\""}"#,
        r#"data: {"type":"response.output_item.done","item":{"type":"function_call","id":"fc_1","call_id":"c1","name":"read","arguments":"{\"path\":\"a\"}"}}"#,
        r#"data: {"type":"response.completed","response":{"usage":{"input_tokens":50,"output_tokens":7}}}"#,
    ]));
    let (r, _) = run(WireFormat::OpenAiResponses, &m, &simple_req(), Duration::from_secs(5), &Cancel::new());
    let r = r.unwrap();
    assert_eq!(r.stop, StopReason::ToolUse);
    let Block::Thinking { text, signature: Some(sig) } = &r.message.content[0] else { panic!("{:?}", r.message.content) };
    assert_eq!(text, "plan");
    assert_eq!(r.message.content[1], Block::text("Hi "));
    assert_eq!(r.message.tool_uses().next().unwrap(), ("c1", "read", &json!({"path":"a"})));

    // Feed the assistant turn back: reasoning item, function_call and its output must appear.
    let m2 = serve(sse(&text_stream(WireFormat::OpenAiResponses)));
    let mut req = simple_req();
    req.messages.push(r.message.clone());
    req.messages.push(Message { role: Role::User, content: vec![Block::ToolResult { tool_use_id: "c1".into(), content: "A".into(), is_error: false }] });
    run(WireFormat::OpenAiResponses, &m2, &req, Duration::from_secs(5), &Cancel::new()).0.unwrap();
    let b = m2.request();
    assert_eq!(b.path, "/responses");
    let input = b.body["input"].as_array().unwrap();
    assert_eq!(b.body["instructions"], "be brief");
    assert_eq!(b.body["store"], false);
    assert!(input.iter().any(|i| i["type"] == "reasoning" && i["encrypted_content"] == "ENC" && i["id"] == "rs_1"), "{input:?}");
    assert!(input.iter().any(|i| i["type"] == "function_call" && i["call_id"] == "c1" && i["arguments"] == r#"{"path":"a"}"#));
    assert!(input.iter().any(|i| i == &json!({"type":"function_call_output","call_id":"c1","output":"A"})));
    assert!(sig.contains("ENC"));
}

#[test]
fn responses_incomplete_maps_to_max_tokens() {
    let r = go(
        WireFormat::OpenAiResponses,
        sse(&[r#"data: {"type":"response.output_text.delta","delta":"cut"}"#, r#"data: {"type":"response.incomplete","response":{}}"#]),
    )
    .unwrap();
    assert_eq!(r.stop, StopReason::MaxTokens);
    assert!(r.usage.estimated);
}

#[test]
fn anthropic_thinking_tools_cache_control_and_headers() {
    let m = serve(sse(&[
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":90,\"cache_creation_input_tokens\":5,\"output_tokens\":1}}}",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"thinking\",\"thinking\":\"\"}}",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"hmm\"}}",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig1\"}}",
        "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}",
        "data: {\"type\":\"content_block_start\",\"index\":2,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"read\",\"input\":{}}}",
        "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\"}}",
        "data: {\"type\":\"content_block_delta\",\"index\":2,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"a\\\"}\"}}",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":20}}",
        "data: {\"type\":\"message_stop\"}",
    ]));
    let (r, _) = run(WireFormat::Anthropic, &m, &tool_history(), Duration::from_secs(5), &Cancel::new());
    let r = r.unwrap();
    assert_eq!(r.stop, StopReason::ToolUse);
    assert_eq!(r.message.content[0], Block::Thinking { text: "hmm".into(), signature: Some("sig1".into()) });
    assert_eq!(r.message.content[1], Block::text("Hi"));
    assert_eq!(r.message.tool_uses().next().unwrap(), ("toolu_1", "read", &json!({"path":"a"})));
    let u = r.usage;
    assert_eq!((u.input_tokens, u.cache_read_tokens, u.cache_write_tokens, u.output_tokens), (10, 90, 5, 20));

    let req = m.request();
    assert_eq!(req.path, "/messages");
    assert_eq!(req.header("x-api-key"), Some("sk-test"));
    assert_eq!(req.header("anthropic-version"), Some("2023-06-01"));
    let b = &req.body;
    assert_eq!(b["system"][0]["cache_control"], json!({"type":"ephemeral"}));
    assert!(b["system"][1].get("cache_control").is_none());
    let msgs = b["messages"].as_array().unwrap();
    // assistant turn: thinking with signature kept, empty text dropped, cache breakpoint on last block
    let a = msgs[1]["content"].as_array().unwrap();
    assert_eq!(a[0], json!({"type":"thinking","thinking":"r1","signature":"SIG"}));
    assert_eq!(a.len(), 2);
    assert_eq!(a[1]["type"], "tool_use");
    assert_eq!(a[1]["cache_control"], json!({"type":"ephemeral"}));
    assert!(msgs[0]["content"][0].get("cache_control").is_none());
    assert_eq!(msgs[2]["content"][0], json!({"type":"tool_result","tool_use_id":"call_1","content":"file body","is_error":false}));
}

#[test]
fn anthropic_unsigned_thinking_is_not_sent_and_unknown_block_delta_fails() {
    let mut req = simple_req();
    req.messages.push(Message { role: Role::Assistant, content: vec![Block::Thinking { text: "x".into(), signature: None }] });
    req.messages.push(Message::user("again"));
    let m = serve(sse(&text_stream(WireFormat::Anthropic)));
    run(WireFormat::Anthropic, &m, &req, Duration::from_secs(5), &Cancel::new()).0.unwrap();
    let b = m.request().body;
    assert_eq!(b["messages"][1]["content"], json!([{"type":"text","text":"(empty)"}]));

    let e = go(
        WireFormat::Anthropic,
        sse(&["data: {\"type\":\"content_block_delta\",\"index\":5,\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}"]),
    )
    .unwrap_err();
    assert_eq!(e.kind, K::Protocol);
}

#[test]
fn gemini_function_calls_signatures_and_names() {
    let m = serve(sse(&[
        r#"data: {"candidates":[{"content":{"role":"model","parts":[{"text":"Let me","thought":true}]}}]}"#,
        r#"data: {"candidates":[{"content":{"parts":[{"text":"Sure"}]}}]}"#,
        r#"data: {"candidates":[{"content":{"parts":[{"functionCall":{"name":"read","args":{"path":"a"}},"thoughtSignature":"TS1"},{"functionCall":{"name":"ls"}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":30,"candidatesTokenCount":4,"thoughtsTokenCount":2,"cachedContentTokenCount":10},"modelVersion":"gemini-x"}"#,
    ]));
    let (r, _) = run(WireFormat::Gemini, &m, &simple_req(), Duration::from_secs(5), &Cancel::new());
    let r = r.unwrap();
    assert_eq!(r.stop, StopReason::ToolUse);
    assert_eq!(r.model, "gemini-x");
    assert_eq!((r.usage.input_tokens, r.usage.output_tokens, r.usage.cache_read_tokens), (20, 6, 10));
    assert!(matches!(&r.message.content[0], Block::Thinking { text, signature: None } if text == "Let me"));
    let uses: Vec<_> = r.message.tool_uses().map(|(i, n, a)| (i.to_string(), n.to_string(), a.clone())).collect();
    assert_eq!(uses.len(), 2);
    assert_ne!(uses[0].0, uses[1].0, "synthesised ids must be unique");
    assert_eq!(uses[1].2, json!({}));

    let req0 = m.request();
    assert_eq!(req0.path, "/models/m:streamGenerateContent?alt=sse");
    assert_eq!(req0.header("x-goog-api-key"), Some("sk-test"));
    assert_eq!(req0.body["systemInstruction"]["parts"][0]["text"], "be brief");
    assert_eq!(req0.body["tools"][0]["functionDeclarations"][0]["name"], "read");

    // Round-trip: signature attaches to its functionCall, responses carry the function name.
    let mut req = simple_req();
    req.messages.push(r.message.clone());
    req.messages.push(Message {
        role: Role::User,
        content: vec![
            Block::ToolResult { tool_use_id: uses[0].0.clone(), content: "A".into(), is_error: false },
            Block::ToolResult { tool_use_id: uses[1].0.clone(), content: "denied".into(), is_error: true },
        ],
    });
    let m2 = serve(sse(&text_stream(WireFormat::Gemini)));
    run(WireFormat::Gemini, &m2, &req, Duration::from_secs(5), &Cancel::new()).0.unwrap();
    let b = m2.request().body;
    let model_parts = b["contents"][1]["parts"].as_array().unwrap();
    assert_eq!(b["contents"][1]["role"], "model");
    let fc: Vec<_> = model_parts.iter().filter(|p| p.get("functionCall").is_some()).collect();
    assert_eq!(fc[0]["thoughtSignature"], "TS1");
    assert!(fc[1].get("thoughtSignature").is_none());
    assert_eq!(b["contents"][2]["parts"][0], json!({"functionResponse":{"name":"read","response":{"content":"A"}}}));
    assert_eq!(b["contents"][2]["parts"][1], json!({"functionResponse":{"name":"ls","response":{"error":"denied"}}}));
}

#[test]
fn gemini_safety_block_and_max_tokens() {
    let r = go(WireFormat::Gemini, sse(&[r#"data: {"promptFeedback":{"blockReason":"SAFETY"}}"#])).unwrap();
    assert_eq!(r.stop, StopReason::Refusal);
    let r = go(WireFormat::Gemini, sse(&[r#"data: {"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"MAX_TOKENS"}]}"#])).unwrap();
    assert_eq!(r.stop, StopReason::MaxTokens);
}

#[test]
fn custom_headers_are_sent_and_local_servers_need_no_key() {
    let m = serve(sse(&text_stream(WireFormat::OpenAiChat)));
    let mut c = cfg("ollama", WireFormat::OpenAiChat, &m.base);
    c.api_key = None;
    c.headers.insert("x-title".into(), "ark".into());
    let p = build_with_idle(&c, Duration::from_secs(5)).unwrap();
    p.complete(&simple_req(), &mut |_| {}, &Cancel::new()).unwrap();
    let req = m.request();
    assert_eq!(req.header("x-title"), Some("ark"));
    assert!(req.header("authorization").is_none());
}

#[test]
fn images_and_reasoning_effort_reach_every_format() {
    for f in FORMATS {
        let m = serve(sse(&text_stream(f)));
        let mut req = simple_req();
        req.messages = vec![Message { role: Role::User, content: vec![Block::text("what is this?"), Block::Image { media_type: "image/png".into(), data: "iVBORw0K".into() }] }];
        req.reasoning = Some("high".into());
        req.temperature = Some(0.2);
        run(f, &m, &req, Duration::from_secs(5), &Cancel::new()).0.unwrap();
        let b = m.request().body;
        let s = b.to_string();
        assert!(s.contains("iVBORw0K") && s.contains("what is this?"), "{f:?}: {s}");
        match f {
            WireFormat::Anthropic => {
                assert_eq!(b["messages"][0]["content"][1]["source"]["media_type"], "image/png");
                assert_eq!(b["thinking"]["budget_tokens"], 24576);
                assert!(b["max_tokens"].as_u64().unwrap() > 24576 && b.get("temperature").is_none(), "{s}");
            }
            WireFormat::OpenAiChat => {
                assert_eq!(b["messages"][1]["content"][1]["image_url"]["url"], "data:image/png;base64,iVBORw0K");
                assert_eq!(b["reasoning_effort"], "high");
            }
            WireFormat::OpenAiResponses => {
                assert!(s.contains("input_image") && s.contains("data:image/png;base64,iVBORw0K"));
                assert_eq!(b["reasoning"]["effort"], "high");
            }
            WireFormat::Gemini => {
                assert_eq!(b["contents"][0]["parts"][1]["inlineData"]["mimeType"], "image/png");
                assert_eq!(b["generationConfig"]["thinkingConfig"]["thinkingBudget"], 24576);
            }
        }
    }
}
