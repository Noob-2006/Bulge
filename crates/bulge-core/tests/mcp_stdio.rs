//! End-to-end check of the MCP stdio client against a real server process (a tiny
//! JSON-RPC echo server in Python). Skipped if `python3` is not on PATH.

use std::collections::HashMap;

use bulge_core::mcp::{McpClient, McpServerConfig};
use bulge_core::schedule::CallOutcome;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

const SERVER: &str = r#"
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        out = {"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":"2024-11-05","capabilities":{},"serverInfo":{"name":"fake","version":"0"}}}
    elif method == "tools/list":
        out = {"jsonrpc":"2.0","id":mid,"result":{"tools":[{"name":"echo","description":"echo back","inputSchema":{"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}}]}}
    elif method == "tools/call":
        args = msg.get("params",{}).get("arguments",{})
        out = {"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":"echo:"+args.get("text","")}]}}
    elif mid is None:
        continue
    else:
        out = {"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"method not found"}}
    sys.stdout.write(json.dumps(out)+"\n")
    sys.stdout.flush()
"#;

fn python3_available() -> bool {
    std::process::Command::new("python3")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn connects_lists_and_calls_a_real_stdio_server() {
    if !python3_available() {
        eprintln!("python3 not available; skipping MCP stdio integration test");
        return;
    }
    let script = std::env::temp_dir().join(format!("bulge-mcp-fake-{}.py", std::process::id()));
    std::fs::write(&script, SERVER).unwrap();

    let config = McpServerConfig {
        command: "python3".into(),
        args: vec![script.to_string_lossy().into_owned()],
        env: HashMap::new(),
        disabled: false,
        max_result_bytes: None,
    };

    let client = McpClient::connect("fake", &config).await.expect("connect");
    assert_eq!(client.tools().len(), 1);
    assert_eq!(client.tools()[0].name, "echo");

    let outcome = client.call_tool("echo", json!({ "text": "hi" }), CancellationToken::new()).await;
    match outcome {
        CallOutcome::Ok(v) => assert_eq!(v.get("text").and_then(Value::as_str), Some("echo:hi")),
        other => panic!("expected Ok, got {other:?}"),
    }

    let _ = std::fs::remove_file(&script);
}
