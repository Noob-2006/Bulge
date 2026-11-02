//! Every plugin registration kind against tests/fixtures/plugin/kinds.py.

use ark_core::{Cancel, Message, ModelRequest, StreamEvent};
use ark_plugin::*;
use serde_json::json;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn host(extra: &[&str]) -> Option<Arc<PluginHost>> {
    if Command::new("python3").arg("-c").arg("1").output().is_err() {
        eprintln!("python3 missing: skipping plugin kinds test");
        return None;
    }
    let f = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/plugin/kinds.py").canonicalize().unwrap();
    let mut args = vec!["-I".to_string(), f.to_string_lossy().into_owned()];
    args.extend(extra.iter().map(|s| s.to_string()));
    let cfg = McpServerConfig { command: Some("python3".into()), args, timeout_secs: Some(10), ..Default::default() };
    Some(Arc::new(PluginHost::start("kinds", &cfg, no_secrets()).unwrap()))
}

#[test]
fn commands_routes_providers_and_hooks_are_declared_and_served() {
    let Some(h) = host(&[]) else { return };
    assert_eq!(h.commands.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["ping", "ask"]);
    assert_eq!(h.hooks().len(), 26);
    // Commands: a reply for the user, or a prompt for the agent.
    let r = h.command("ping", "hi", json!({"surface": "chat"})).unwrap();
    assert_eq!(r.text.as_deref(), Some("pong hi from chat"));
    assert_eq!(h.command("ask", "why", json!({})).unwrap().prompt.as_deref(), Some("Please answer: why"));
    assert!(h.command("nope", "", json!({})).is_err());
    // Routes: prefix + method matching, headers and status come back, credentials never reach the plugin.
    assert!(h.route("GET", "/echo/x").is_some() && h.route("DELETE", "/echo").is_none() && h.route("GET", "/echoes").is_none());
    assert!(h.route("PUT", "/public/hook").unwrap().public);
    let r = h.http("POST", "/echo/a", "q=1", &[("Authorization".into(), "Bearer t".into()), ("X-Y".into(), "z".into())], b"payload").unwrap();
    assert_eq!(r.status, 201);
    assert!(r.headers.contains(&("x-plugin".into(), "kinds".into())));
    let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
    assert_eq!((v["path"].as_str(), v["query"].as_str(), v["body"].as_str(), v["has_auth"].as_bool()), (Some("/echo/a"), Some("q=1"), Some("payload"), Some(false)));
    let r = h.http("POST", "/echo", "", &[], &[0xff, 0xfe]).unwrap();
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&r.body).unwrap()["body"], "\u{ff}\u{fe}", "binary bodies travel as base64");
    // Provider: deltas stream, the final response parses.
    let ps = h.provider_impls();
    assert_eq!(ps[0].0, "plug");
    assert_eq!(ps[0].1.caps("parrot").context_window, 8000);
    let req = ModelRequest { model: "parrot".into(), system: vec![], messages: vec![Message::user("hello there")], tools: vec![], max_tokens: 100, temperature: None, cache_after_message: None, reasoning: None };
    let mut deltas = String::new();
    let resp = ps[0].1.complete(&req, &mut |e| if let StreamEvent::TextDelta(t) = e { deltas.push_str(&t) }, &Cancel::new()).unwrap();
    assert_eq!(resp.message.text(), "parrot says: hello there");
    assert_eq!(deltas, "parrot says: hello there");
    assert_eq!((resp.usage.output_tokens, resp.model.as_str()), (4, "plug/parrot"));
    // Hooks: new events reach the plugin; message_sending rewrites.
    assert_eq!(h.hook("message_sending", json!({"input": "hi"})).unwrap(), HookDecision::Modify(json!("hi [via plugin]")));
    assert!(matches!(h.hook("message_received", json!({"input": "blocked words"})).unwrap(), HookDecision::Deny(_)));
}

#[test]
fn cli_middleware_context_memory_node_and_ui_kinds() {
    let Some(h) = host(&[]) else { return };
    // CLI: streamed output arrives before the final answer; the exit code comes back.
    assert_eq!(h.cli.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), ["kinds-echo"]);
    let mut streamed = String::new();
    let r = h.cli("kinds-echo", &["a".into(), "--fail".into()], "/tmp", &mut |s, t| streamed.push_str(&format!("{s}:{t}"))).unwrap();
    assert_eq!((streamed.as_str(), r.stdout.as_str(), r.exit), ("stdout:streamed\n", "argv=[\"a\", \"--fail\"]\n", 3));
    assert!(h.cli("nope", &[], "/", &mut |_, _| {}).is_err());
    // Middleware: only declared kinds, each answering with its own key.
    assert_eq!(h.middleware_kinds().len(), 4);
    assert_eq!(h.middleware("tool_request", None, json!({"args": {"text": "rewrite me"}})).unwrap(), Some(json!({"text": "rewritten"})));
    assert_eq!(h.middleware("tool_request", None, json!({"args": {"text": "keep"}})).unwrap(), None);
    assert_eq!(h.middleware("tool_execution", Some("call"), json!({"args": {"text": "cached"}})).unwrap(), Some(json!({"content": "FROM CACHE", "is_error": false})));
    let req = json!({"messages": [{"role": "user", "content": [{"type": "text", "text": "short-circuit"}]}]});
    assert_eq!(h.middleware("llm_execution", Some("call"), json!({"request": req})).unwrap(), Some(json!({"text": "answered by middleware"})));
    assert!(h.middleware("bogus", None, json!({})).unwrap().is_none(), "undeclared kinds are skipped");
    // Context engine.
    assert_eq!(h.context_engine.as_ref().map(|e| e.owns_compaction), Some(true));
    let a = h.context("assemble", json!({"session": "s", "messages": [Message::user("one"), Message::assistant("two"), Message::user("ENGINE three")], "prompt": "ENGINE three"})).unwrap();
    assert_eq!((a["messages"].as_array().map(Vec::len), a["system_prompt_addition"].as_str()), (Some(1), Some("engine was here")));
    let c = h.context("compact", json!({"session": "s", "messages": []})).unwrap();
    assert_eq!((c["summary"].as_str(), c["keep_messages"].as_u64()), (Some("engine summary"), Some(2)));
    // Memory provider through the `memory` tool.
    assert!(h.memory);
    assert_eq!(h.memory_prompt().as_deref(), Some("Memory provider: kinds"));
    let tool = PluginMemory(h.clone());
    struct NoHost;
    impl ark_core::ToolHost for NoHost {
        fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
            Err("no".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("no".into())
        }
    }
    let t = std::env::temp_dir();
    let ctx = ark_core::ToolCtx { workspace: t.clone(), session_id: "t".into(), artifacts: t.clone(), home: t, cancel: Cancel::new(), host: Arc::new(NoHost), secrets: Arc::new(|s: &str| s.to_string()) };
    use ark_core::Tool;
    assert_eq!(tool.spec().name, "memory");
    assert!(!tool.call(&ctx, json!({"action": "add", "text": "likes tea"})).is_error);
    assert_eq!(tool.call(&ctx, json!({"action": "search", "query": "TEA"})).content, "likes tea");
    assert!(tool.call(&ctx, json!({"action": "remove", "old": "tea"})).is_error);
    // Node commands and UI panels.
    assert_eq!(h.node_commands.iter().map(|c| (c.command.as_str(), c.dangerous)).collect::<Vec<_>>(), [("kinds.hello", false), ("kinds.wipe", true)]);
    assert_eq!(h.node_invoke("kinds.hello", json!({"name": "Amy"}), Duration::from_secs(5)).unwrap()["greeting"], "hello Amy");
    assert!(h.node_invoke("kinds.wipe", json!({}), Duration::from_secs(5)).is_err());
    assert_eq!(h.ui.iter().map(|u| (u.id.as_str(), u.surface.as_str())).collect::<Vec<_>>(), [("dash", "tab"), ("prefs", "settings")]);
    assert!(h.ui_render("dash", "").unwrap()["html"].as_str().unwrap().contains("kinds panel"));
    assert!(h.ui_render("ghost", "").is_err());
    assert_eq!(h.ui_call("dash", "count", json!({})).unwrap()["count"], 42);
}

#[test]
fn services_start_get_health_checked_restart_and_stop() {
    let d = std::env::temp_dir().join(format!("ark-kinds-{}-{}", std::process::id(), Instant::now().elapsed().as_nanos()));
    std::fs::create_dir_all(&d).unwrap();
    let (log, sick) = (d.join("log"), d.join("sick"));
    let Some(h) = host(&["--log", log.to_str().unwrap(), "--sick", sick.to_str().unwrap()]) else { return };
    let actions = || std::fs::read_to_string(&log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|v| v["kind"] == "service").map(|v| v["action"].as_str().unwrap_or("").to_string()).collect::<Vec<_>>();
    let stop = Cancel::new();
    let t = plugin::supervise(vec![h.clone()], stop.clone()).unwrap();
    let wait = |what: &dyn Fn(&[String]) -> bool| {
        let until = Instant::now() + Duration::from_secs(15);
        while Instant::now() < until && !what(&actions()) {
            std::thread::sleep(Duration::from_millis(50));
        }
    };
    wait(&|a| a.iter().filter(|x| *x == "health").count() >= 1);
    std::fs::write(&sick, "").unwrap();
    wait(&|a| a.iter().filter(|x| *x == "start").count() >= 2);
    let a = actions();
    assert_eq!(a[0], "start");
    assert!(a.iter().filter(|x| *x == "start").count() >= 2 && a.contains(&"stop".to_string()), "two failed checks restart it: {a:?}");
    stop.cancel();
    t.join().unwrap();
    assert_eq!(actions().last().map(String::as_str), Some("stop"));
    assert!(plugin::supervise(vec![], Cancel::new()).is_none());
}
