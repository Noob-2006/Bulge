//! Server-side ("native") compaction through the real OpenAI Responses adapter, against a
//! scripted local HTTP server: the request body must carry `context_management` only when the
//! config reaches the provider through `RequestOptions`, and a structured rejection must strip
//! the field, retry once and be remembered.

use ark_core::{Cancel, Message, ModelRequest, RequestOptions};
use ark_model::{build_with_idle, ProviderConfig, WireFormat};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

enum Reply {
    /// 200 text/event-stream body (already framed as `data: …`).
    Sse(&'static str),
    /// A JSON error status.
    Error { code: u16, body: &'static str },
}

const DONE: &str = r#"data: {"type":"response.completed","response":{"model":"gpt-5.6","usage":{"input_tokens":5,"output_tokens":1}}}"#;

/// Serve `replies` in order (one per request) and record every request body.
fn serve(replies: Vec<Reply>) -> (String, Arc<Mutex<Vec<Value>>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    std::thread::spawn(move || {
        for reply in replies {
            let Ok((mut s, _)) = l.accept() else { return };
            let Some(body) = read_request(&mut s) else { return };
            log.lock().unwrap().push(body);
            respond(&mut s, reply);
        }
    });
    (base, seen)
}

fn read_request(s: &mut TcpStream) -> Option<Value> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let len: usize = head
        .split("\r\n")
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < len {
        let n = s.read(&mut tmp).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    serde_json::from_slice(&body).ok()
}

fn respond(s: &mut TcpStream, reply: Reply) {
    match reply {
        Reply::Sse(ev) => {
            let body = format!("{ev}\n\n");
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            );
        }
        Reply::Error { code, body } => {
            let _ = s.write_all(
                format!(
                    "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        }
    }
}

/// The operator trusts the local fake server (`quirks = ["native_compaction"]`).
fn cfg(base: &str) -> ProviderConfig {
    ProviderConfig {
        id: "openai".into(),
        format: WireFormat::OpenAiResponses,
        base_url: base.into(),
        api_key: Some("sk-test".into()),
        quirks: vec!["native_compaction".into()],
        ..Default::default()
    }
}

fn req(model: &str, native: Option<u64>) -> ModelRequest {
    ModelRequest {
        model: model.into(),
        system: vec![],
        messages: vec![Message::user("hi")],
        tools: vec![],
        max_tokens: 64,
        temperature: None,
        cache_after_message: None,
        reasoning: None,
        options: RequestOptions { native_compaction: native, ..Default::default() },
    }
}

fn complete(p: &Arc<dyn ark_core::Provider>, r: &ModelRequest) -> Result<(), String> {
    p.complete(r, &mut |_ev| {}, &Cancel::new()).map(|_| ()).map_err(|e| e.message)
}

#[test]
fn configured_threshold_reaches_the_request_body() {
    let (base, seen) = serve(vec![Reply::Sse(DONE)]);
    let p = build_with_idle(&cfg(&base), Duration::from_secs(5)).unwrap();
    complete(&p, &req("gpt-5.6-plain", Some(140_000))).unwrap();
    let bodies = seen.lock().unwrap();
    assert_eq!(
        bodies[0]["context_management"],
        json!([{"type": "compaction", "compact_threshold": 140_000}]),
        "{}",
        bodies[0]
    );
}

#[test]
fn unconfigured_or_ineligible_requests_carry_no_field() {
    // No threshold (config off) and a model outside the marker: the body stays clean.
    let (base, seen) = serve(vec![Reply::Sse(DONE), Reply::Sse(DONE)]);
    let p = build_with_idle(&cfg(&base), Duration::from_secs(5)).unwrap();
    complete(&p, &req("gpt-5.6-plain-off", None)).unwrap();
    complete(&p, &req("gpt-5.5", Some(140_000))).unwrap();
    let bodies = seen.lock().unwrap();
    assert!(bodies[0].get("context_management").is_none(), "{}", bodies[0]);
    assert!(bodies[1].get("context_management").is_none(), "{}", bodies[1]);
}

#[test]
fn rejected_field_is_stripped_retried_and_remembered() {
    let (base, seen) = serve(vec![
        Reply::Error {
            code: 400,
            body: r#"{"error":{"message":"Unknown parameter: 'context_management'","type":"invalid_request_error"}}"#,
        },
        Reply::Sse(DONE),
        Reply::Sse(DONE),
    ]);
    let p = build_with_idle(&cfg(&base), Duration::from_secs(5)).unwrap();
    complete(&p, &req("gpt-5.6-recover", Some(140_000))).unwrap();
    // The next request in the same process never sends the field again.
    complete(&p, &req("gpt-5.6-recover", Some(140_000))).unwrap();
    let bodies = seen.lock().unwrap();
    assert!(bodies[0].get("context_management").is_some(), "sent once, then retried without it");
    assert!(bodies[1].get("context_management").is_none(), "{}", bodies[1]);
    assert!(bodies[2].get("context_management").is_none(), "the rejection is remembered");
}
