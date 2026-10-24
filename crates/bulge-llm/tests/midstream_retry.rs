//! A stream that breaks after content already reached the consumer is retried
//! (per the retry policy) behind a `Restart` chunk, so the assembled reply is
//! the retried response alone — never the failed attempt's partial text, and
//! never a job failure for one transient drop.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bulge_llm::assemble::Assembler;
use bulge_llm::http::{HttpBackend, HttpBackendConfig};
use bulge_llm::protocol::openai_chat::OpenAiChat;
use bulge_llm::retry::RetryPolicy;
use bulge_llm::*;
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

fn sse(data: &[&str]) -> String {
    data.iter().map(|d| format!("data: {d}\n\n")).collect()
}

/// Serve: the first connection streams a partial reply and drops; later ones
/// stream a complete reply.
async fn flaky_server() -> (String, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { return };
            let attempt = counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                let _ = socket.read(&mut buf).await;
                let body = if attempt == 0 {
                    sse(&[r#"{"choices":[{"index":0,"delta":{"content":"PARTIAL-"}}]}"#])
                } else {
                    sse(&[
                        r#"{"choices":[{"index":0,"delta":{"content":"complete answer"}}]}"#,
                        r#"{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}"#,
                        "[DONE]",
                    ])
                };
                let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n";
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(body.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (format!("http://{addr}"), hits)
}

#[tokio::test]
async fn a_stream_dropped_midway_is_retried_from_scratch() {
    let (base_url, hits) = flaky_server().await;
    let backend = HttpBackend::new(
        HttpBackendConfig {
            id: "t".into(),
            base_url,
            api_key: "k".into(),
            models: Vec::new(),
            default_max_tokens: 256,
            stream_idle_timeout: Duration::from_secs(5),
            retry: RetryPolicy { max_retries: 2, initial_delay: Duration::from_millis(10), max_delay: Duration::from_millis(20), jitter_ratio: 0.0 },
        },
        Arc::new(OpenAiChat),
    )
    .unwrap();
    let request = GenerateRequest {
        model: "m".into(),
        messages: vec![Message::text(Role::User, "hi")],
        tools: Vec::new(),
        max_tokens: None,
        temperature: None,
        stop: Vec::new(),
        reasoning_effort: None,
        purpose: Purpose::Conversation,
    };
    let mut stream = backend.stream(request, CancellationToken::new());
    let mut assembler = Assembler::new();
    let mut restarts = 0;
    while let Some(chunk) = stream.next().await {
        restarts += usize::from(chunk == StreamChunk::Restart);
        assembler.push(&chunk);
    }
    let assembled = assembler.finish("m");

    assert_eq!(assembled.finish, FinishReason::Stop);
    assert_eq!(restarts, 1);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    let text: String = assembled
        .message
        .content
        .iter()
        .filter_map(|b| match b {
            ContentBlock::Text { text } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(text, "complete answer");
}

#[test]
fn restart_discards_blocks_but_keeps_billed_usage() {
    let mut assembler = Assembler::new();
    assembler.push(&StreamChunk::BlockEnd { index: 0, block: ContentBlock::Text { text: "partial".into() } });
    assembler.push(&StreamChunk::Usage(TokenUsage { output_tokens: 3, ..Default::default() }));
    assembler.push(&StreamChunk::Restart);
    assembler.push(&StreamChunk::BlockEnd { index: 0, block: ContentBlock::Text { text: "full".into() } });
    assembler.push(&StreamChunk::Usage(TokenUsage { output_tokens: 4, ..Default::default() }));
    assembler.push(&StreamChunk::Finish(FinishReason::Stop));
    let assembled = assembler.finish("m");
    assert_eq!(assembled.message.content, vec![ContentBlock::Text { text: "full".into() }]);
    assert_eq!(assembled.usage.output_tokens, 7);
}
