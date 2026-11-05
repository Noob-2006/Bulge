//! ark-plugin against a real (python) MCP server. Mostly failure paths.

use ark_core::{Cancel, Effect, Tool, ToolCtx, ToolHost, ToolOutput, ToolSpec};
use ark_plugin::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::io::{BufRead, BufReader, Cursor};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn fixture() -> Option<String> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/mcp/server.py");
    if Command::new("python3").arg("-c").arg("1").output().is_err() {
        eprintln!("python3 missing: skipping MCP fixture tests");
        return None;
    }
    Some(p.canonicalize().unwrap().to_string_lossy().into_owned())
}

fn tmp(tag: &str) -> PathBuf {
    let d = ark_core::tmp::scratch_path(format!("ark-plugin-{tag}-{}-{}", std::process::id(), Instant::now().elapsed().as_nanos() ^ rand()));
    std::fs::create_dir_all(&d).unwrap();
    d
}
fn rand() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
}

fn stdio(extra: &[&str]) -> Option<McpServerConfig> {
    let f = fixture()?;
    let mut args = vec!["-I".to_string(), f];
    args.extend(extra.iter().map(|s| s.to_string()));
    Some(McpServerConfig { command: Some("python3".into()), args, enabled: true, timeout_secs: Some(5), ..Default::default() })
}

struct NoHost;
impl ToolHost for NoHost {
    fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
        Err("no".into())
    }
    fn ask_user(&self, _: &str) -> Result<String, String> {
        Err("no".into())
    }
}

fn ctx() -> ToolCtx {
    ToolCtx {
        // Built on the server thread of the end-to-end test (a detached thread that outlives the
        // test), so nothing here may be created: an existing directory these tools never write to.
        workspace: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        session_id: "t".into(),
        artifacts: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        home: std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")),
        cancel: Cancel::new(),
        host: Arc::new(NoHost),
        secrets: Arc::new(|s: &str| s.replace("{{secret:TOKEN}}", "s3cr\"et")),
    }
}

fn find<'a>(tools: &'a [Arc<dyn Tool>], name: &str) -> &'a Arc<dyn Tool> {
    tools.iter().find(|t| t.spec().name == name).unwrap_or_else(|| panic!("no tool {name}: {:?}", tools.iter().map(|t| t.spec().name).collect::<Vec<_>>()))
}

#[test]
fn stdio_client_full_surface() {
    let Some(cfg) = stdio(&["--stderr"]) else { return };
    let c = Client::new("fx", cfg, no_secrets()).unwrap();
    assert!(!c.is_running(), "lazy until first use");
    let tools = c.list_tools().unwrap();
    assert_eq!(tools.len(), 11, "both pages collected");
    assert!(tools.iter().find(|t| t.name == "echo").unwrap().read_only);
    let r = c.call_tool("add", json!({"a": 2, "b": 3}), &Cancel::new()).unwrap();
    assert_eq!((r.text.as_str(), r.is_error), ("5", false));
    assert_eq!(r.raw["content"][0]["text"], "5", "raw CallToolResult kept");
    assert!(c.call_tool("fail", json!({}), &Cancel::new()).unwrap().is_error);
    let e = c.call_tool("nope", json!({}), &Cancel::new()).unwrap_err();
    assert!(e.contains("-32602") && e.contains("unknown tool"), "{e}");
    assert_eq!(c.read_resource("mem://a", &Cancel::new()).unwrap(), "alpha body");
    assert!(c.read_resource("mem://b", &Cancel::new()).unwrap().contains("binary resource"));
    assert!(c.read_resource("mem://zz", &Cancel::new()).is_err());
    let mut a = BTreeMap::new();
    a.insert("file".to_string(), "main.rs".to_string());
    assert_eq!(c.get_prompt("review", &a).unwrap(), "Please review main.rs");
    // Server-initiated request answered by the client.
    let r = c.call_tool("roots", json!({}), &Cancel::new()).unwrap();
    assert!(r.text.contains("\"roots\": []"), "{}", r.text);
    assert!(c.stderr_tail().contains("debug noise"), "stderr kept for diagnostics");
    assert_eq!(c.starts(), 1);
}

#[test]
fn missing_binary_and_bad_protocol_are_clear_errors() {
    let cfg = McpServerConfig { command: Some("/nonexistent/mcp-server".into()), enabled: true, ..Default::default() };
    let c = Client::new("ghost", cfg, no_secrets()).unwrap();
    let e = c.list_tools().unwrap_err();
    assert!(e.contains("cannot start") && e.contains("ghost"), "{e}");
    // Fails fast during cooldown instead of respawning on every call.
    let t = Instant::now();
    assert!(c.list_tools().is_err());
    assert!(t.elapsed() < Duration::from_millis(100));
    assert_eq!(c.starts(), 1);

    let Some(cfg) = stdio(&["--proto", "1999-01-01"]) else { return };
    let e = Client::new("old", cfg, no_secrets()).unwrap().info().unwrap_err();
    assert!(e.contains("1999-01-01"), "{e}");
    let Some(cfg) = stdio(&["--proto", "2024-11-05"]) else { return };
    assert!(Client::new("older", cfg, no_secrets()).unwrap().list_tools().is_ok(), "older supported version accepted");

    // A server that exits immediately: error shows its stderr.
    let cfg = McpServerConfig { command: Some("sh".into()), args: vec!["-c".into(), "echo 'fatal: bad config' >&2; exit 2".into()], timeout_secs: Some(3), ..Default::default() };
    let e = Client::new("dies", cfg, no_secrets()).unwrap().info().unwrap_err();
    assert!(e.contains("fatal: bad config"), "{e}");
}

#[test]
fn crash_mid_call_then_recovers_on_next_call() {
    let Some(cfg) = stdio(&[]) else { return };
    let c = Client::new("fx", cfg, no_secrets()).unwrap();
    assert_eq!(c.call_tool("echo", json!({"text": "a"}), &Cancel::new()).unwrap().text, "a");
    let e = c.call_tool("crash", json!({}), &Cancel::new()).unwrap_err();
    assert!(e.contains("restarted on the next call") && e.contains("crashing on purpose"), "{e}");
    assert!(!c.is_running());
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(c.call_tool("echo", json!({"text": "b"}), &Cancel::new()).unwrap().text, "b");
    assert_eq!(c.starts(), 2);
}

#[test]
fn garbage_oversize_timeout_and_cancel() {
    let Some(mut cfg) = stdio(&[]) else { return };
    cfg.timeout_secs = Some(1);
    let c = Client::new("fx", cfg, no_secrets()).unwrap();
    assert_eq!(c.call_tool("garbage", json!({}), &Cancel::new()).unwrap().text, "after garbage");
    assert!(c.stderr_tail().contains("ignored non-JSON stdout"));
    // 5 MiB reply is dropped; the call times out rather than eating memory.
    let e = c.call_tool("big", json!({"n": 5_000_000}), &Cancel::new()).unwrap_err();
    assert!(e.contains("timed out"), "{e}");
    assert!(c.stderr_tail().contains("oversized"));
    let big = c.call_tool("big", json!({"n": 100_000}), &Cancel::new()).unwrap();
    assert_eq!(big.text.len(), 100_000);
    let t = Instant::now();
    let e = c.call_tool("slow", json!({"ms": 3000}), &Cancel::new()).unwrap_err();
    assert!(e.contains("timed out") && t.elapsed() < Duration::from_millis(1800), "{e}");
    // Late reply to the timed-out request is ignored, server still usable.
    std::thread::sleep(Duration::from_millis(2300));
    assert_eq!(c.call_tool("echo", json!({"text": "ok"}), &Cancel::new()).unwrap().text, "ok");
    let cancel = Cancel::new();
    let cc = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        cc.cancel();
    });
    let e = c.call_tool("slow", json!({"ms": 800}), &cancel).unwrap_err();
    assert!(e.contains("cancelled"), "{e}");
}

#[test]
fn registry_caches_catalog_and_starts_lazily() {
    let dir = tmp("reg");
    let marker = dir.join("started.txt");
    let Some(cfg) = stdio(&["--touch", marker.to_str().unwrap(), "--instructions", "Use echo for tests."]) else { return };
    let mut cfgs = BTreeMap::new();
    cfgs.insert("fx".to_string(), cfg);
    cfgs.insert("ghost".to_string(), McpServerConfig { command: Some("/nonexistent/x".into()), ..Default::default() });
    cfgs.insert("off".to_string(), McpServerConfig { command: Some("/nonexistent/y".into()), enabled: false, ..Default::default() });
    cfgs.insert("bad name".to_string(), McpServerConfig { command: Some("x".into()), ..Default::default() });

    let reg = Registry::load(&cfgs, &dir.join("cache"), no_secrets());
    let starts = || std::fs::read_to_string(&marker).unwrap_or_default().lines().count();
    assert_eq!(starts(), 1, "uncached: started once to list tools");
    assert_eq!(reg.warnings().len(), 2, "{:?}", reg.warnings());
    assert!(reg.warnings().iter().any(|w| w.contains("ghost")) && reg.warnings().iter().any(|w| w.contains("bad name")));
    let tools = reg.tools();
    assert_eq!(tools.len(), 12, "11 tools + resources");
    assert!(tools.iter().all(|t| !t.spec().pinned && t.spec().name.starts_with("mcp__fx__")));
    assert!(find(&tools, "mcp__fx__echo").spec().idempotent);
    assert_eq!(reg.instructions(), vec![("fx".to_string(), "Use echo for tests.".to_string())]);
    assert_eq!(reg.prompts().len(), 1);
    drop(reg);

    // Second load: catalog from cache, no process started.
    let reg = Registry::load(&cfgs, &dir.join("cache"), no_secrets());
    assert_eq!(reg.tools().len(), 12);
    assert_eq!(starts(), 1, "cache hit must not start the server");
    assert!(!reg.status().iter().any(|(_, _, running)| *running));
    // First call starts it.
    let out = find(&reg.tools(), "mcp__fx__echo").call(&ctx(), json!({"text": "hi"}));
    assert_eq!(out, ToolOutput::ok("hi"));
    assert_eq!(starts(), 2);
    // Resources tool.
    let rt = find(&reg.tools(), "mcp__fx__resources").clone();
    assert!(rt.call(&ctx(), json!({"action": "list"})).content.contains("mem://a  Alpha"));
    assert_eq!(rt.call(&ctx(), json!({"action": "read", "uri": "mem://a"})).content, "alpha body");
    assert!(rt.call(&ctx(), json!({"action": "read"})).is_error);
    assert!(rt.call(&ctx(), json!({"action": "nuke"})).is_error);
    // Prompt argument validation happens before the round trip.
    assert!(reg.get_prompt("fx", "review", &BTreeMap::new()).unwrap_err().contains("file"));

    // list_changed invalidates the cache; the next load re-fetches.
    let c = reg.client("fx").unwrap();
    find(&reg.tools(), "mcp__fx__change").call(&ctx(), json!({}));
    std::thread::sleep(Duration::from_millis(100));
    assert!(c.is_stale());
    drop(reg);
    let mut reg = Registry::load(&cfgs, &dir.join("cache"), no_secrets());
    assert_eq!(starts(), 3, "stale cache refetched");
    assert_eq!(reg.refresh("fx").unwrap(), 11);
    assert!(reg.refresh("ghost").is_err());

    // Allowlist.
    cfgs.get_mut("fx").unwrap().tools = Some(vec!["echo".into()]);
    let reg = Registry::load(&cfgs, &dir.join("cache"), no_secrets());
    assert_eq!(reg.tools().iter().map(|t| t.spec().name).collect::<Vec<_>>(), ["mcp__fx__echo", "mcp__fx__resources"]);
}

#[test]
fn tool_effects_and_secret_substitution() {
    let dir = tmp("eff");
    let Some(cfg) = stdio(&[]) else { return };
    let mut cfgs = BTreeMap::new();
    cfgs.insert("fx".to_string(), cfg);
    let reg = Registry::load(&cfgs, &dir.join("cache"), no_secrets());
    let t = find(&reg.tools(), "mcp__fx__secret_echo").clone();
    let input = json!({"value": "{{secret:TOKEN}}"});
    // The gate sees the placeholder, the server gets the value.
    assert_eq!(t.effects(&ctx(), &input), vec![Effect::Net { dest: "mcp:fx".into(), payload: input.to_string() }]);
    assert_eq!(t.call(&ctx(), input).content, "got:s3cr\"et");
    assert_eq!(find(&reg.tools(), "mcp__fx__image").call(&ctx(), json!({})).content, "[image: image/png, 8 bytes]");
    let f = find(&reg.tools(), "mcp__fx__fail").call(&ctx(), json!({}));
    assert!(f.is_error && f.content == "it failed");
}

/// Kills the server even when an assertion fails (an orphan would hold the test's pipes open).
struct Srv(std::process::Child);
impl Drop for Srv {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn http_server(extra: &[&str]) -> Option<(Srv, u16)> {
    let f = fixture()?;
    let port = 20000 + (rand() % 20000) as u16;
    let mut child = Command::new("python3").arg("-I").arg(f).arg("--http").arg(port.to_string()).args(extra).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "ready");
    Some((Srv(child), port))
}

#[test]
fn streamable_http_json_sse_auth_and_errors() {
    let Some((_srv, port)) = http_server(&["--token", "t0k", "--expire", "1.5"]) else { return };
    let url = format!("http://127.0.0.1:{port}/mcp");
    let mut headers = BTreeMap::new();
    headers.insert("Authorization".to_string(), "Bearer {{secret:MCP}}".to_string());
    let secrets: Secrets = Arc::new(|s: &str| s.replace("{{secret:MCP}}", "t0k"));
    let cfg = McpServerConfig { url: Some(url.clone()), headers, timeout_secs: Some(5), ..Default::default() };
    let c = Client::new("web", cfg.clone(), secrets.clone()).unwrap();
    assert_eq!(c.list_tools().unwrap().len(), 11);
    // tools/call comes back as SSE with a progress notification first.
    assert_eq!(c.call_tool("echo", json!({"text": "sse"}), &Cancel::new()).unwrap().text, "sse");
    assert!(c.call_tool("nope", json!({}), &Cancel::new()).unwrap_err().contains("-32602"));
    // Session expiry → 404 → reconnect with a new session.
    std::thread::sleep(Duration::from_millis(1700));
    let e = c.call_tool("echo", json!({"text": "x"}), &Cancel::new()).unwrap_err();
    assert!(e.contains("session expired"), "{e}");
    assert_eq!(c.call_tool("echo", json!({"text": "again"}), &Cancel::new()).unwrap().text, "again");
    assert_eq!(c.starts(), 2);

    // Wrong token → 401 message.
    let e = Client::new("web", cfg.clone(), no_secrets()).unwrap().list_tools().unwrap_err();
    assert!(e.contains("unauthorized (HTTP 401)"), "{e}");
    // 500 and connection refused.
    let bad = McpServerConfig { url: Some(format!("http://127.0.0.1:{port}/fail500")), ..cfg.clone() };
    assert!(Client::new("b", bad, secrets.clone()).unwrap().info().unwrap_err().contains("HTTP 500"));
    let refused = McpServerConfig { url: Some("http://127.0.0.1:1/mcp".into()), ..cfg.clone() };
    assert!(Client::new("r", refused, secrets.clone()).unwrap().info().unwrap_err().contains("HTTP request failed"));
    // HTTP tools are judged by their real destination.
    let dir = tmp("http");
    let mut cfgs = BTreeMap::new();
    cfgs.insert("web".to_string(), cfg);
    let reg = Registry::load(&cfgs, &dir.join("cache"), secrets);
    assert!(reg.warnings().is_empty(), "{:?}", reg.warnings());
    let t = find(&reg.tools(), "mcp__web__echo").clone();
    assert!(matches!(&t.effects(&ctx(), &json!({}))[0], Effect::Net { dest, .. } if dest == &format!("http://127.0.0.1:{port}")));
}

#[test]
fn plugin_hooks_channels_and_failures() {
    let Some(cfg) = stdio(&["--plugin"]) else { return };
    let p = PluginHost::start("fxp", &cfg, no_secrets()).unwrap().with_hook_timeout(Duration::from_millis(500));
    assert_eq!(p.hooks(), ["pre_tool"]);
    assert_eq!(p.channels(), ["loop"]);
    let mut taken = HashSet::new();
    assert_eq!(p.tools(&mut taken).unwrap().len(), 12);
    assert_eq!(p.hook("pre_tool", json!({"tool": "shell", "input": {"command": "ls"}})).unwrap(), HookDecision::Allow);
    assert_eq!(p.hook("pre_tool", json!({"input": "forbidden thing"})).unwrap(), HookDecision::Deny("fixture forbids it".into()));
    assert_eq!(p.hook("pre_tool", json!({"input": "rewrite me"})).unwrap(), HookDecision::Modify(json!({"text": "rewritten"})));
    assert_eq!(p.hook("post_tool", json!({"input": "forbidden"})).unwrap(), HookDecision::Allow, "unsubscribed events never hit the plugin");
    // Hanging hook: fails open with an explanation, quickly.
    let t = Instant::now();
    let e = p.hook("pre_tool", json!({"input": "hang"})).unwrap_err();
    assert!(e.contains("allowing") && e.contains("timed out") && t.elapsed() < Duration::from_secs(2), "{e}");

    // Channel round trip: send → plugin echoes back as inbound.
    let rx = p.take_inbound().unwrap();
    assert!(p.take_inbound().is_none(), "single consumer");
    // The plugin is still busy in the hung hook (single-threaded); retry until it answers.
    let mut sent = None;
    for _ in 0..20 {
        match p.channel_send("loop", json!({"chat": "c1", "text": "hello"})) {
            Ok(v) => {
                sent = Some(v);
                break;
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
    assert_eq!(sent.expect("channel send eventually works"), json!({"id": "m1"}));
    let (ch, msg) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(ch, "loop");
    assert_eq!(msg["text"], "echo: hello");
    assert!(p.channel_send("nochan", json!({})).unwrap_err().contains("no channel"));

    // Plain MCP server as plugin: no extras, hooks allow.
    let Some(plain) = stdio(&[]) else { return };
    let q = PluginHost::start("plain", &plain, no_secrets()).unwrap();
    assert!(q.hooks().is_empty() && q.channels().is_empty());
    assert_eq!(q.hook("pre_tool", json!({"input": "forbidden"})).unwrap(), HookDecision::Allow);
    // HTTP config is rejected for plugins; crashing plugin restarts.
    assert!(PluginHost::start("h", &McpServerConfig { url: Some("http://x".into()), ..Default::default() }, no_secrets()).is_err());
    let _ = q.client().call_tool("crash", json!({}), &Cancel::new());
    std::thread::sleep(Duration::from_millis(50));
    assert!(q.ensure_running().is_ok());
    assert_eq!(q.client().starts(), 2);
}

// ───────────── server side ─────────────

struct Echo;
impl Tool for Echo {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "echo".into(), description: "Echo".into(), input_schema: json!({"type": "object"}), parallel_safe: true, idempotent: true, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, i: &Value) -> Vec<Effect> {
        vec![Effect::Exec { command: i["text"].as_str().unwrap_or("").into() }]
    }
    fn call(&self, _: &ToolCtx, i: Value) -> ToolOutput {
        if i["text"] == "panic" {
            panic!("boom");
        }
        ToolOutput::ok(i["text"].as_str().unwrap_or("").to_string())
    }
}

fn run_server(input: &str) -> Vec<Value> {
    let tools: Vec<Arc<dyn Tool>> = vec![Arc::new(Echo)];
    let judge = |e: &[Effect]| match &e[0] {
        Effect::Exec { command } if command.starts_with("sudo") => Err("privilege gate: sudo".to_string()),
        _ => Ok(()),
    };
    let mut out = Vec::new();
    let info = ServerInfo { name: "ark".into(), version: "0".into(), instructions: Some("hi".into()) };
    serve(&info, &tools, &ctx, &judge, Cursor::new(input.as_bytes().to_vec()), &mut out).unwrap();
    String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

#[test]
fn mcp_server_protocol_and_gates() {
    let input = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}"#,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"text":"sudo rm"}}}"#,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}"#,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"arguments":{}}}"#,
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":[1]}}"#,
        r#"this is not json"#,
        r#"[1,2]"#,
        r#"{"jsonrpc":"2.0","id":8,"method":"resources/list"}"#,
        "",
        r#"{"jsonrpc":"2.0","id":9,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo","arguments":{"text":"panic"}}}"#,
        r#"{"jsonrpc":"2.0","id":11,"method":"ping"}"#,
    ]
    .join("\n");
    let r = run_server(&input);
    assert_eq!(r.len(), 13, "{r:#?}");
    assert_eq!(r[0]["result"]["protocolVersion"], "2024-11-05");
    assert_eq!(r[0]["result"]["instructions"], "hi");
    assert_eq!(r[1]["result"]["tools"][0]["name"], "echo");
    assert_eq!(r[2]["result"]["content"][0]["text"], "hi");
    assert_eq!(r[3]["result"]["isError"], true);
    assert!(r[3]["result"]["content"][0]["text"].as_str().unwrap().contains("blocked: privilege gate"));
    assert_eq!(r[4]["error"]["code"], -32602);
    assert_eq!(r[5]["error"]["code"], -32602);
    assert_eq!(r[6]["error"]["code"], -32602);
    assert_eq!(r[7]["error"]["code"], -32700);
    assert_eq!(r[8]["error"]["code"], -32600);
    assert_eq!(r[9]["error"]["code"], -32601);
    assert_eq!(r[10]["id"], 9);
    assert_eq!(r[11]["result"]["isError"], true, "panic contained");
    assert_eq!(r[12]["id"], 11, "server survives a panicking tool");
}

#[test]
fn ark_client_talks_to_ark_server_end_to_end() {
    // Same framing as a real stdio client, over an OS pipe pair.
    let tools: Vec<Arc<dyn Tool>> = vec![Arc::new(Echo)];
    let (r1, w1) = pipe();
    let (r2, w2) = pipe();
    std::thread::spawn(move || {
        let judge = |_: &[Effect]| Ok(());
        let info = ServerInfo { name: "ark".into(), version: "0".into(), instructions: None };
        let _ = serve(&info, &tools, &ctx, &judge, BufReader::new(r1), w2);
    });
    use std::io::Write;
    let mut w = w1;
    let mut rd = BufReader::new(r2);
    writeln!(w, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#).unwrap();
    writeln!(w, r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"echo","arguments":{{"text":"via pipe"}}}}}}"#).unwrap();
    let mut l = String::new();
    rd.read_line(&mut l).unwrap();
    assert!(l.contains(ark_plugin::mcp::PROTOCOL), "no version asked → latest: {l}");
    l.clear();
    rd.read_line(&mut l).unwrap();
    assert!(l.contains("via pipe"));
}

fn pipe() -> (std::fs::File, std::fs::File) {
    use std::os::fd::FromRawFd;
    let mut fds = [0; 2];
    // SAFETY: plain syscall; the fds are owned by the returned Files.
    unsafe {
        assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
        (std::fs::File::from_raw_fd(fds[0]), std::fs::File::from_raw_fd(fds[1]))
    }
}
