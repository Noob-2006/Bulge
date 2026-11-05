//! Request knobs per wire: service tiers / fast mode, verbosity, strict tools,
//! reasoning clamping, subscription (OAuth) auth, Codex and Vertex endpoint shapes.
#[allow(dead_code)]
mod mock;

use ark_core::{Cancel, Message, ModelRequest, RequestOptions, SystemSegment, ToolSchema};
use ark_model::{build, ProviderConfig, WireFormat};
use mock::{serve, sse};
use serde_json::json;

const CHAT_OK: &[&str] = &[
    r#"data: {"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}"#,
    "data: [DONE]",
];
const RESP_OK: &[&str] = &[
    r#"data: {"type":"response.output_text.delta","delta":"ok"}"#,
    r#"data: {"type":"response.completed","response":{"usage":{"input_tokens":1,"output_tokens":1}}}"#,
];
const ANTH_OK: &[&str] = &[
    "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}",
    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"ok\"}}",
    "data: {\"type\":\"message_stop\"}",
];
const GEM_OK: &[&str] =
    &[r#"data: {"candidates":[{"content":{"parts":[{"text":"ok"}]},"finishReason":"STOP"}]}"#];

fn req(model: &str) -> ModelRequest {
    ModelRequest {
        model: model.into(),
        system: vec![SystemSegment {
            id: "s".into(),
            text: "sys".into(),
            cache: false,
        }],
        messages: vec![Message::user("hi")],
        tools: vec![ToolSchema {
            name: "read".into(),
            description: "r".into(),
            input_schema: json!({"type": "object"}),
        }],
        max_tokens: 100,
        temperature: Some(0.5),
        ..Default::default()
    }
}

fn cfg(id: &str, f: WireFormat, base: &str) -> ProviderConfig {
    ProviderConfig {
        id: id.into(),
        format: f,
        base_url: base.into(),
        api_key: Some("sk-test".into()),
        ..Default::default()
    }
}

#[test]
fn openai_chat_service_tier_verbosity_strict_and_effort_clamp() {
    let m = serve(sse(CHAT_OK));
    let mut c = cfg("openai-chat", WireFormat::OpenAiChat, &m.base);
    c.quirks = vec!["first_party".into()];
    c.reasoning_efforts = Some(vec!["low".into(), "high".into()]);
    let mut r = req("gpt-5.5");
    r.reasoning = Some("medium".into());
    r.options = RequestOptions {
        service_tier: Some("priority".into()),
        verbosity: Some("low".into()),
        strict_tools: true,
        ..Default::default()
    };
    build(&c)
        .unwrap()
        .complete(&r, &mut |_| {}, &Cancel::new())
        .unwrap();
    let b = m.request().body;
    assert_eq!(b["service_tier"], "priority");
    assert_eq!(b["verbosity"], "low");
    assert_eq!(
        b["reasoning_effort"], "low",
        "medium clamps to the nearest weaker supported level"
    );
    assert_eq!(b["tools"][0]["function"]["strict"], true);
    assert_eq!(b["max_completion_tokens"], 100);
}

#[test]
fn proxies_never_get_billing_knobs() {
    let m = serve(sse(CHAT_OK));
    let mut r = req("x");
    r.options.service_tier = Some("priority".into());
    build(&cfg("openrouter", WireFormat::OpenAiChat, &m.base))
        .unwrap()
        .complete(&r, &mut |_| {}, &Cancel::new())
        .unwrap();
    assert!(m.request().body.get("service_tier").is_none());
}

#[test]
fn codex_backend_shape() {
    let m = serve(sse(RESP_OK));
    let mut c = cfg("openai-codex", WireFormat::OpenAiResponses, &m.base);
    c.quirks = vec!["codex".into()];
    let mut r = req("gpt-5.5-codex");
    r.system.clear();
    r.reasoning = Some("max".into());
    r.options.service_tier = Some("priority".into());
    build(&c)
        .unwrap()
        .complete(&r, &mut |_| {}, &Cancel::new())
        .unwrap();
    let rec = m.request();
    assert_eq!(rec.path, "/responses");
    let b = rec.body;
    assert!(b.get("max_output_tokens").is_none() && b.get("temperature").is_none());
    assert!(b["instructions"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(b["reasoning"]["effort"], "xhigh");
    assert_eq!(b["service_tier"], "priority");
}

#[test]
fn anthropic_subscription_token_and_fast_mode() {
    let m = serve(sse(ANTH_OK));
    let mut c = cfg("anthropic", WireFormat::Anthropic, &m.base);
    c.api_key = Some("sk-ant-oat01-subscription".into());
    c.quirks = vec!["first_party".into()];
    let mut r = req("claude-opus-5-5");
    r.options.service_tier = Some("priority".into());
    build(&c)
        .unwrap()
        .complete(&r, &mut |_| {}, &Cancel::new())
        .unwrap();
    let rec = m.request();
    assert_eq!(
        rec.header("authorization"),
        Some("Bearer sk-ant-oat01-subscription")
    );
    assert!(rec.header("x-api-key").is_none());
    let beta = rec.header("anthropic-beta").unwrap();
    assert!(
        beta.contains("oauth-2025-04-20")
            && beta.contains("claude-code-20250219")
            && beta.contains("fast-mode")
    );
    assert!(rec.header("user-agent").unwrap().starts_with("claude-cli/"));
    assert_eq!(
        rec.body["system"][0]["text"],
        "You are Claude Code, Anthropic's official CLI for Claude."
    );
    assert_eq!(rec.body["speed"], "fast");

    // A Console key stays x-api-key; a non-fast model gets no speed.
    let m = serve(sse(ANTH_OK));
    let mut c = cfg("anthropic", WireFormat::Anthropic, &m.base);
    c.api_key = Some("sk-ant-api03-key".into());
    c.quirks = vec!["first_party".into()];
    let mut r = req("claude-opus-4-7");
    r.options.service_tier = Some("priority".into());
    build(&c)
        .unwrap()
        .complete(&r, &mut |_| {}, &Cancel::new())
        .unwrap();
    let rec = m.request();
    assert_eq!(rec.header("x-api-key"), Some("sk-ant-api03-key"));
    assert!(rec.body.get("speed").is_none());
}

#[test]
fn vertex_publisher_paths() {
    let m = serve(sse(ANTH_OK));
    let mut c = cfg(
        "anthropic-vertex",
        WireFormat::Anthropic,
        &format!("{}/v1/projects/p/locations/us-east5", m.base),
    );
    c.auth = "bearer".into();
    c.quirks = vec!["vertex".into()];
    build(&c)
        .unwrap()
        .complete(
            &req("claude-sonnet-4-5@20250929"),
            &mut |_| {},
            &Cancel::new(),
        )
        .unwrap();
    let rec = m.request();
    assert_eq!(rec.path, "/v1/projects/p/locations/us-east5/publishers/anthropic/models/claude-sonnet-4-5@20250929:streamRawPredict");
    assert_eq!(rec.body["anthropic_version"], "vertex-2023-10-16");
    assert!(rec.body.get("model").is_none());
    assert_eq!(rec.header("authorization"), Some("Bearer sk-test"));

    let m = serve(sse(GEM_OK));
    let mut c = cfg(
        "google-vertex",
        WireFormat::Gemini,
        &format!(
            "{}/v1/projects/p/locations/global/publishers/google",
            m.base
        ),
    );
    c.auth = "bearer".into();
    c.quirks = vec!["vertex".into()];
    let mut r = req("gemini-3-pro");
    r.reasoning = Some("xhigh".into());
    build(&c)
        .unwrap()
        .complete(&r, &mut |_| {}, &Cancel::new())
        .unwrap();
    let rec = m.request();
    assert!(rec.path.starts_with("/v1/projects/p/locations/global/publishers/google/models/gemini-3-pro:streamGenerateContent"));
    assert_eq!(rec.header("authorization"), Some("Bearer sk-test"));
    assert_eq!(
        rec.body["generationConfig"]["thinkingConfig"]["thinkingBudget"],
        32768
    );
}

#[test]
fn azure_api_key_header_and_query() {
    let m = serve(sse(CHAT_OK));
    let mut c = cfg("azure-openai", WireFormat::OpenAiChat, &m.base);
    c.auth = "api-key".into();
    c.query
        .insert("api-version".into(), "2025-04-01-preview".into());
    build(&c)
        .unwrap()
        .complete(&req("gpt-5.5"), &mut |_| {}, &Cancel::new())
        .unwrap();
    let rec = m.request();
    assert_eq!(rec.header("api-key"), Some("sk-test"));
    assert!(rec.header("authorization").is_none());
    assert!(
        rec.path
            .ends_with("/chat/completions?api-version=2025-04-01-preview"),
        "{}",
        rec.path
    );
}
