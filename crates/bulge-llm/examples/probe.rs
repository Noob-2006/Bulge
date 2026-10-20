//! P1 live probe: one tool-calling round trip against a real endpoint.
//! Tools are NOT executed; the tool result is a fixed placeholder.
//!
//! usage: probe <anthropic|openai> <base_url> <model> "<task>"
//! key:   $BULGE_API_KEY, or the first line of ~/.bulge/keys/<backend-id>
//!        where backend-id is the host part of base_url.

use std::sync::Arc;
use std::time::Duration;

use bulge_llm::assemble::Assembler;
use bulge_llm::http::{HttpBackend, HttpBackendConfig};
use bulge_llm::protocol::WireProtocol;
use bulge_llm::protocol::anthropic::AnthropicMessages;
use bulge_llm::protocol::openai_chat::OpenAiChat;
use bulge_llm::retry::RetryPolicy;
use bulge_llm::*;
use futures::StreamExt;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [kind, base_url, model, task] = args.as_slice() else {
        return Err("usage: probe <anthropic|openai> <base_url> <model> \"<task>\"".into());
    };
    let protocol: Arc<dyn WireProtocol> = match kind.as_str() {
        "anthropic" => Arc::new(AnthropicMessages),
        "openai" => Arc::new(OpenAiChat),
        other => return Err(format!("unknown protocol {other}").into()),
    };
    let backend_id = base_url.split("://").nth(1).unwrap_or(base_url).split('/').next().unwrap_or("default").to_owned();
    let api_key = match std::env::var("BULGE_API_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            let home = std::env::var("HOME")?;
            let path = format!("{home}/.bulge/keys/{backend_id}");
            std::fs::read_to_string(&path)
                .map_err(|e| format!("no BULGE_API_KEY and cannot read {path}: {e}"))?
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned()
        }
    };

    let backend = HttpBackend::new(
        HttpBackendConfig {
            id: backend_id,
            base_url: base_url.clone(),
            api_key,
            models: vec![],
            default_max_tokens: 4096,
            stream_idle_timeout: Duration::from_secs(120),
            retry: RetryPolicy::default(),
        },
        protocol,
    )?;

    let tools = vec![ToolSchema {
        name: "read".into(),
        description: "Read a UTF-8 text file from the workspace.".into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": { "path": { "type": "string" } },
            "required": ["path"]
        }),
        defer_loading: false,
    }];
    let mut messages = vec![
        Message::text(Role::System, "You are bulge, a cautious general-purpose agent. Use tools when needed."),
        Message::text(Role::User, task.clone()),
    ];

    for step in 1..=3 {
        let request = GenerateRequest {
            model: model.clone(),
            messages: messages.clone(),
            tools: tools.clone(),
            max_tokens: None,
            temperature: None,
            stop: vec![],
            reasoning_effort: None,
            purpose: Purpose::Conversation,
        };
        let mut stream = backend.stream(request, CancellationToken::new());
        let mut assembler = Assembler::new();
        println!("── step {step}");
        while let Some(chunk) = stream.next().await {
            match &chunk {
                StreamChunk::ReasoningDelta { text, .. } => eprint!("{text}"),
                StreamChunk::TextDelta { text, .. } => print!("{text}"),
                StreamChunk::BlockEnd { block: ContentBlock::ToolCall { name, arguments, .. }, .. } => {
                    println!("\n[tool call] {name} {arguments}");
                }
                _ => {}
            }
            assembler.push(&chunk);
        }
        let turn = assembler.finish(model);
        println!("\n[finish] {:?}  [usage] {:?}", turn.finish, turn.usage);
        let calls: Vec<String> = turn
            .message
            .content
            .iter()
            .filter_map(|b| match b {
                ContentBlock::ToolCall { id, .. } => Some(id.clone()),
                _ => None,
            })
            .collect();
        messages.push(turn.message);
        if turn.finish != FinishReason::ToolCalls {
            break;
        }
        for id in calls {
            messages.push(Message::tool_result(id, "(P1: tool execution disabled; file contents unavailable)", true));
        }
    }
    Ok(())
}
