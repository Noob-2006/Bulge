//! The multi-round and extension features: outputSchema validation, tasks with
//! input_required, URL elicitation (-32042), sampling with tools, MCP Apps, the
//! 2026-07-28 stateless revision (stdio + HTTP headers), the events extension
//! with Standard Webhooks, and the outbound mcp-relay. The python fixture
//! (`--ext`, `--modern`) and fake Rust servers stand in for real ones.

use seagent_core::{Cancel, Effect, Tool, ToolCtx, ToolHost, ToolOutput, ToolSpec};
use seagent_net::httpd::{Handler, Opts, Request, Response, Server};
use seagent_net::ws::{Message, WebSocket};
use seagent_plugin::mcp::Client;
use seagent_plugin::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

fn fixture(extra: &[&str]) -> Option<McpServerConfig> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/mcp/server.py");
    if Command::new("python3").arg("-c").arg("1").output().is_err() {
        eprintln!("python3 missing: skipping MCP fixture tests");
        return None;
    }
    let mut args = vec!["-I".to_string(), p.canonicalize().unwrap().to_string_lossy().into_owned()];
    args.extend(extra.iter().map(|s| s.to_string()));
    Some(McpServerConfig { command: Some("python3".into()), args, timeout_secs: Some(5), ..Default::default() })
}

fn tmp(tag: &str) -> PathBuf {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = seagent_core::tmp::scratch_path(format!("seagent-mcpx-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

struct NoHost;
impl ToolHost for NoHost {
    fn spawn_agent(&self, _: seagent_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
        Err("no".into())
    }
    fn ask_user(&self, _: &str) -> Result<String, String> {
        Err("no".into())
    }
}

fn ctx(dir: &Path) -> ToolCtx {
    ToolCtx { workspace: dir.into(), session_id: "sess-1".into(), artifacts: dir.join("artifacts"), home: dir.into(), cancel: Cancel::new(), host: Arc::new(NoHost), secrets: Arc::new(|s: &str| s.to_string()) }
}

fn rpc_ok(id: &Value, result: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string()
}

#[test]
fn output_schema_mismatch_is_a_tool_error() {
    let Some(cfg) = fixture(&["--ext"]) else { return };
    let c = Client::new("fx", cfg, no_secrets()).unwrap();
    c.list_tools().unwrap();
    let good = c.call_tool("typed", json!({"good": true}), &Cancel::new()).unwrap();
    assert!(!good.is_error && good.text.contains(r#"{"n":1}"#), "{}", good.text);
    let bad = c.call_tool("typed", json!({"good": false}), &Cancel::new()).unwrap();
    assert!(bad.is_error && bad.text.contains("outputSchema") && bad.text.contains("$.n: expected integer"), "{}", bad.text);
}

#[test]
fn task_polls_then_input_required_elicits_and_completes() {
    let Some(cfg) = fixture(&["--ext"]) else { return };
    let c = Client::new("fx", cfg, no_secrets()).unwrap();
    let tools = c.list_tools().unwrap();
    assert_eq!(tools.iter().find(|t| t.name == "job").unwrap().task_support.as_deref(), Some("required"), "task-only tools are listed now");
    let asked: Arc<Mutex<Vec<Value>>> = Arc::default();
    let a2 = asked.clone();
    c.set_elicitor(Arc::new(move |_: &str, p: &Value| {
        a2.lock().unwrap().push(p.clone());
        Ok(json!({"action": "accept", "content": {"env": "staging"}}))
    }));
    let r = c.call_tool("job", json!({}), &Cancel::new()).unwrap();
    assert_eq!(r.text, "job ran in staging");
    assert!(r.raw["_meta"].get("io.modelcontextprotocol/related-task").is_none(), "related-task meta stripped");
    let p = asked.lock().unwrap()[0].clone();
    assert!(p["_meta"]["io.modelcontextprotocol/related-task"]["taskId"].is_string(), "elicitation came through tasks/result");
    assert!(c.list_tasks().unwrap().iter().any(|t| t["status"] == "completed"));
    // Cancelling while polling sends tasks/cancel.
    let cancel = Cancel::new();
    let cc = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        cc.cancel();
    });
    let e = c.call_tool("job", json!({}), &cancel).unwrap_err();
    assert!(e.contains("cancelled"), "{e}");
    assert!(c.list_tasks().unwrap().iter().any(|t| t["status"] == "cancelled"), "server saw tasks/cancel");
}

#[test]
fn url_elicitation_required_waits_for_completion_then_retries() {
    let Some(cfg) = fixture(&["--ext"]) else { return };
    let c = Client::new("fx", cfg.clone(), no_secrets()).unwrap();
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let s2 = seen.clone();
    c.set_elicitor(Arc::new(move |_: &str, p: &Value| {
        s2.lock().unwrap().push(p.clone());
        Ok(json!({"action": "accept"}))
    }));
    let t = Instant::now();
    let r = c.call_tool("needs_url", json!({}), &Cancel::new()).unwrap();
    assert_eq!(r.text, "signed in");
    assert!(t.elapsed() >= Duration::from_millis(150), "waited for notifications/elicitation/complete");
    let p = seen.lock().unwrap()[0].clone();
    assert_eq!((p["mode"].as_str(), p["url"].as_str()), (Some("url"), Some("https://auth.example/sign-in?x=1")));
    // A user who does not open the page: the call fails with the reason.
    let c = Client::new("fx", cfg, no_secrets()).unwrap();
    c.set_elicitor(Arc::new(|_: &str, _: &Value| Ok(json!({"action": "decline"}))));
    let e = c.call_tool("needs_url", json!({}), &Cancel::new()).unwrap_err();
    assert!(e.contains("did not open https://auth.example/sign-in"), "{e}");
}

#[test]
fn sampling_with_tools_returns_tool_use_over_stdio() {
    let Some(mut cfg) = fixture(&["--ext"]) else { return };
    cfg.sampling.enabled = true;
    let c = Client::new("fx", cfg, no_secrets()).unwrap();
    let got: Arc<Mutex<Option<Value>>> = Arc::default();
    let g2 = got.clone();
    c.set_sampler(Arc::new(move |p: &Value| {
        *g2.lock().unwrap() = Some(p.clone());
        Ok(json!({"role": "assistant", "content": [{"type": "tool_use", "id": "tu1", "name": "lookup", "input": {"city": "Taipei"}}], "model": "m", "stopReason": "toolUse"}))
    }));
    let r = c.call_tool("sample_tools", json!({}), &Cancel::new()).unwrap();
    assert!(r.text.contains(r#""stopReason": "toolUse""#) && r.text.contains("Taipei"), "{}", r.text);
    assert_eq!(got.lock().unwrap().as_ref().unwrap()["tools"][0]["name"], "lookup");
}

#[test]
fn mcp_apps_view_rides_on_the_result_and_app_only_tools_stay_hidden() {
    let Some(cfg) = fixture(&["--ext"]) else { return };
    let dir = tmp("apps");
    let cfgs = BTreeMap::from([("fx".to_string(), cfg.clone())]);
    for round in 0..2 {
        // Round 1 is served from the catalog cache: ui metadata survives it.
        let reg = Registry::load(&cfgs, &dir.join("cache"), no_secrets());
        let names: Vec<String> = reg.tools().iter().map(|t| t.spec().name).collect();
        assert!(names.contains(&"mcp__fx__app".to_string()) && !names.contains(&"mcp__fx__app_only".to_string()), "round {round}: {names:?}");
        assert!(reg.app_tools().iter().any(|(s, d)| s == "fx" && d.name == "app_only"));
        let t = reg.tools().into_iter().find(|t| t.spec().name == "mcp__fx__app").unwrap();
        let out = t.call(&ctx(&dir), json!({"q": 1}));
        assert_eq!(out.content, "app result", "the model sees only the result");
        let ui = out.ui_resource.expect("ui resource");
        assert_eq!((ui["server"].as_str(), ui["tool"].as_str(), ui["uri"].as_str()), (Some("fx"), Some("app"), Some("ui://fx/app.html")));
        assert!(ui["html"].as_str().unwrap().contains("ui/initialize"));
        assert_eq!(ui["csp"]["connectDomains"][0], "https://api.example");
        assert_eq!(ui["prefersBorder"], false);
        assert_eq!(ui["toolInput"], json!({"q": 1}));
        assert_eq!(ui["toolResult"]["content"][0]["text"], "app result");
        assert!(Path::new(ui["path"].as_str().unwrap()).exists(), "HTML stored with the session's artifacts");
    }
    // apps = false: no view.
    let mut off = cfg;
    off.apps = false;
    let reg = Registry::load(&BTreeMap::from([("fx".to_string(), off)]), &tmp("apps-off").join("cache"), no_secrets());
    let t = reg.tools().into_iter().find(|t| t.spec().name == "mcp__fx__app").unwrap();
    assert!(t.call(&ctx(&dir), json!({})).ui_resource.is_none());
}

#[test]
fn stateless_stdio_server_discover_and_mrtr() {
    let Some(cfg) = fixture(&["--modern"]) else { return };
    let c = Client::new("new", cfg.clone(), no_secrets()).unwrap();
    // auto: the legacy handshake is refused with -32022, so the client moves to server/discover.
    let info = c.info().unwrap();
    assert!(c.is_modern());
    assert_eq!((info["protocolVersion"].as_str(), info["instructions"].as_str()), (Some("2026-07-28"), Some("modern fixture")));
    assert!(c.list_tools().unwrap().iter().any(|t| t.name == "ask"), "every request carries the _meta protocol fields");
    let rounds: Arc<Mutex<usize>> = Arc::default();
    let r2 = rounds.clone();
    c.set_elicitor(Arc::new(move |_: &str, p: &Value| {
        *r2.lock().unwrap() += 1;
        assert_eq!(p["message"], "Name?");
        Ok(json!({"action": "accept", "content": {"name": "seagent"}}))
    }));
    // The elicitor is captured at connect: reconnect so it is in place.
    c.shutdown();
    assert_eq!(c.call_tool("ask", json!({}), &Cancel::new()).unwrap().text, "hello seagent", "input_required answered and retried with requestState");
    assert_eq!(*rounds.lock().unwrap(), 1);
    // protocol = "legacy" refuses to leave the handshake era.
    let legacy = McpServerConfig { protocol: Some("legacy".into()), ..cfg.clone() };
    assert!(Client::new("new", legacy, no_secrets()).unwrap().info().unwrap_err().contains("-32022"));
    // protocol = "stateless" goes straight to discover.
    let st = McpServerConfig { protocol: Some("stateless".into()), ..cfg };
    let c = Client::new("new", st, no_secrets()).unwrap();
    c.info().unwrap();
    assert!(c.is_modern());
    // A legacy server under "stateless" falls back to the handshake.
    let Some(old) = fixture(&[]) else { return };
    let c = Client::new("old", McpServerConfig { protocol: Some("stateless".into()), ..old }, no_secrets()).unwrap();
    assert_eq!(c.info().unwrap()["protocolVersion"], "2025-06-18");
    assert!(!c.is_modern());
}

#[test]
fn stateless_http_mirrors_headers_and_rejects_bad_x_mcp_header_tools() {
    type Seen = Vec<(Vec<(String, String)>, Value)>;
    let seen: Arc<Mutex<Seen>> = Arc::default();
    let s2 = seen.clone();
    let h: Handler = Arc::new(move |r: Request| {
        let v: Value = serde_json::from_slice(&r.body).unwrap_or_default();
        s2.lock().unwrap().push((r.headers.iter().map(|(k, v)| (k.to_ascii_lowercase(), v.clone())).collect(), v.clone()));
        let id = &v["id"];
        let err = |code: i64, msg: &str| Response::json(400, &json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg, "data": {"supported": ["2026-07-28"]}}}).to_string());
        let method = v["method"].as_str().unwrap_or("");
        if method == "initialize" {
            return err(-32022, "Unsupported protocol version");
        }
        if r.header("mcp-protocol-version") != Some("2026-07-28") || r.header("mcp-method") != Some(method) || v["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] != "2026-07-28" {
            return err(-32020, "Header mismatch");
        }
        match method {
            "server/discover" => Response::json(200, &rpc_ok(id, json!({"resultType": "complete", "supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}}))),
            "tools/list" => Response::json(200, &rpc_ok(id, json!({"resultType": "complete", "tools": [
                {"name": "q", "inputSchema": {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}, "query": {"type": "string"}}}},
                {"name": "bad", "inputSchema": {"type": "object", "properties": {"x": {"type": "number", "x-mcp-header": "X"}}}},
                {"name": "deep", "inputSchema": {"type": "object", "properties": {"l": {"type": "array", "items": {"type": "string", "x-mcp-header": "L"}}}}}
            ]}))),
            "tools/call" => {
                let region = v["params"]["arguments"]["region"].as_str().unwrap_or("");
                let want = if region.is_ascii() { region.to_string() } else { format!("=?base64?{}?=", seagent_net::crypto::b64(region.as_bytes())) };
                if r.header("mcp-name") != Some("q") || r.header("mcp-param-region") != Some(want.as_str()) {
                    return err(-32020, "Header mismatch: Mcp-Param-Region");
                }
                Response::json(200, &rpc_ok(id, json!({"resultType": "complete", "content": [{"type": "text", "text": format!("ran in {region}")}]})))
            }
            _ => err(-32601, "no"),
        }
    });
    let srv = Server::bind("127.0.0.1:0", Opts::default(), h).unwrap();
    let c = Client::new("m", McpServerConfig { url: Some(format!("http://{}/mcp", srv.local_addr())), timeout_secs: Some(5), ..Default::default() }, no_secrets()).unwrap();
    let tools = c.list_tools().unwrap();
    assert_eq!(tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), ["q"], "invalid x-mcp-header tools are excluded");
    assert_eq!(c.call_tool("q", json!({"region": "us-west1", "query": "x"}), &Cancel::new()).unwrap().text, "ran in us-west1");
    assert_eq!(c.call_tool("q", json!({"region": "台北"}), &Cancel::new()).unwrap().text, "ran in 台北", "non-ASCII uses the base64 sentinel");
    let s = seen.lock().unwrap();
    assert!(s.iter().all(|(h, _)| !h.iter().any(|(k, _)| k == "mcp-session-id")), "no sessions in the stateless era");
    assert!(!s.iter().any(|(_, v)| v["method"] == "notifications/initialized"));
    let call = &s.iter().find(|(_, v)| v["method"] == "tools/call").unwrap().1;
    let caps = &call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"];
    assert!(caps["extensions"]["io.modelcontextprotocol/ui"]["mimeTypes"][0] == "text/html;profile=mcp-app", "MCP Apps advertised: {caps}");
    assert!(call["params"]["_meta"]["progressToken"].is_string(), "caller _meta kept alongside the protocol fields");
}

#[test]
fn events_subscribe_verify_deliver_dedupe_gap_terminate_unsubscribe() {
    let dir = tmp("events");
    let hub = seagent_plugin::events::Hub::open(&dir.join("mcp-events.json"));
    let got: Arc<Mutex<Vec<seagent_plugin::events::Delivery>>> = Arc::default();
    let g2 = got.clone();
    hub.set_sink(Arc::new(move |d: &seagent_plugin::events::Delivery| g2.lock().unwrap().push(d.clone())));
    let hub_srv = Server::bind("127.0.0.1:0", Opts::default(), hub.handler()).unwrap();
    let hub_base = format!("http://{}/mcp-events", hub_srv.local_addr());
    // The MCP server: verifies the callback during events/subscribe, as the sketch requires.
    let grants: Arc<Mutex<Vec<Value>>> = Arc::default();
    let gr = grants.clone();
    let h: Handler = Arc::new(move |r: Request| {
        let v: Value = serde_json::from_slice(&r.body).unwrap_or_default();
        let id = &v["id"];
        match v["method"].as_str() {
            Some("initialize") => Response::json(200, &rpc_ok(id, json!({"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "ev", "version": "1"}}))),
            Some("events/list") => Response::json(200, &rpc_ok(id, json!({"events": [{"name": "push", "description": "a push", "inputSchema": {"type": "object"}}]}))),
            Some("events/subscribe") => {
                let d = &v["params"]["delivery"];
                let body = json!({"type": "verification", "challenge": "ch-123"}).to_string();
                let sig = seagent_plugin::events::sign_standard_webhook(body.as_bytes(), d["secret"].as_str().unwrap(), "msg_v", now());
                let resp = seagent_net::http::agent().post(d["url"].as_str().unwrap()).header("webhook-id", "msg_v").header("webhook-timestamp", &now().to_string()).header("webhook-signature", &sig).send(body.as_bytes());
                let echoed: Value = resp.ok().and_then(|mut r| r.body_mut().read_to_string().ok()).and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
                if echoed["challenge"] != "ch-123" {
                    return Response::json(200, &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32602, "message": "callback verification failed"}}).to_string());
                }
                gr.lock().unwrap().push(v["params"].clone());
                Response::json(200, &rpc_ok(id, json!({"id": "sub-1", "refreshBefore": "2099-01-01T00:00:00Z"})))
            }
            Some("events/unsubscribe") => Response::json(200, &rpc_ok(id, json!({}))),
            Some("tools/list") => Response::json(200, &rpc_ok(id, json!({"tools": []}))),
            _ => Response::empty(202),
        }
    });
    let srv = Server::bind("127.0.0.1:0", Opts::default(), h).unwrap();
    let cfg = McpServerConfig { url: Some(format!("http://{}/mcp", srv.local_addr())), timeout_secs: Some(5), events: true, events_url: Some(hub_base.clone()), ..Default::default() };
    let c = Arc::new(Client::new("ev", cfg.clone(), no_secrets()).unwrap());
    assert_eq!(hub.list(&c).unwrap()["events"][0]["name"], "push");
    let r = hub.subscribe(&c, "push", json!({"repo": "a"}), Some("sess-9".into())).unwrap();
    let route = r["subscribed"]["route"].as_str().unwrap().to_string();
    let p = grants.lock().unwrap()[0].clone();
    assert!(p["delivery"]["secret"].as_str().unwrap().starts_with("whsec_") && p["delivery"]["url"].as_str().unwrap().ends_with(&route));
    let secret = p["delivery"]["secret"].as_str().unwrap().to_string();
    let sub = hub.subscriptions()[&route].clone();
    assert_eq!((sub.subscription_id.as_deref(), sub.expires_at), (Some("sub-1"), seagent_plugin::events::parse_rfc3339("2099-01-01T00:00:00Z").unwrap()));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(dir.join("mcp-events.json")).unwrap().permissions().mode() & 0o777, 0o600, "secrets on disk are private");
    let post = |body: Value, secret: &str, id: &str| -> u16 {
        let b = body.to_string();
        let sig = seagent_plugin::events::sign_standard_webhook(b.as_bytes(), secret, id, now());
        let a: ureq::Agent = seagent_net::http::builder().http_status_as_error(false).build().into();
        a.post(&format!("{hub_base}/{route}")).header("webhook-id", id).header("webhook-timestamp", &now().to_string()).header("webhook-signature", &sig).send(b.as_bytes()).unwrap().status().as_u16()
    };
    let ev = json!({"eventId": "e-1", "name": "push", "timestamp": "2026-11-02T00:00:00Z", "data": {"ref": "main"}, "cursor": "c-1"});
    assert_eq!(post(ev.clone(), &secret, "msg_1"), 200);
    assert_eq!(post(ev.clone(), &secret, "msg_2"), 200, "redelivery acknowledged");
    assert_eq!(got.lock().unwrap().len(), 1, "deduplicated by eventId");
    assert_eq!(post(json!({"eventId": "e-2"}), "whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "msg_3"), 401, "wrong secret");
    let d = got.lock().unwrap()[0].clone();
    assert_eq!((d.server.as_str(), d.name.as_str(), d.session.as_deref()), ("ev", "push", Some("sess-9")));
    let prompt = seagent_plugin::events::prompt_for(&d);
    assert!(prompt.contains("treat it as data") && prompt.contains("\"ref\": \"main\""), "{prompt}");
    assert_eq!(hub.subscriptions()[&route].cursor.as_deref(), Some("c-1"));
    assert_eq!(post(json!({"type": "gap", "cursor": "c-9"}), &secret, "msg_4"), 200);
    assert_eq!(hub.subscriptions()[&route].cursor.as_deref(), Some("c-9"));
    // The bridge tool: subscribing is a standing rule, so the egress gate asks.
    let mut taken = std::collections::HashSet::new();
    let t = seagent_plugin::bridge::events_tool(&c, &hub, &mut taken);
    assert_eq!(t.spec().name, "mcp__ev__events");
    assert!(t.effects(&ctx(&dir), &json!({"action": "subscribe", "name": "push"})).iter().any(|e| matches!(e, Effect::Remote { .. })));
    assert!(!t.effects(&ctx(&dir), &json!({"action": "list"})).iter().any(|e| matches!(e, Effect::Remote { .. })));
    assert!(t.call(&ctx(&dir), json!({"action": "list"})).content.contains(&route));
    assert!(hub.unsubscribe(&c, "push", json!({"repo": "a"})).unwrap()["unsubscribed"] == route.as_str());
    assert!(hub.subscriptions().is_empty());
    // terminated envelope removes the route.
    hub.subscribe(&c, "push", json!({}), None).unwrap();
    let route2 = seagent_plugin::events::route_name("ev", "push", &json!({}));
    let secret2 = hub.subscriptions()[&route2].secret.clone();
    let b = json!({"type": "terminated", "error": {"code": -32024, "message": "revoked"}}).to_string();
    let sig = seagent_plugin::events::sign_standard_webhook(b.as_bytes(), &secret2, "m9", now());
    let (status, _) = hub.handle(&route2, &[("webhook-id".into(), "m9".into()), ("webhook-timestamp".into(), now().to_string()), ("webhook-signature".into(), sig)], b.as_bytes(), now());
    assert_eq!(status, 200);
    assert!(hub.subscriptions().is_empty());
    // Registry wiring: events = true exposes the tool.
    let reg = Registry::load(&BTreeMap::from([("ev".to_string(), cfg)]), &dir.join("cache"), no_secrets());
    assert!(reg.events().is_some() && reg.tools().iter().any(|t| t.spec().name == "mcp__ev__events"));
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

struct Echo;
impl Tool for Echo {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "echo".into(), description: "Echo".into(), input_schema: json!({"type": "object"}), parallel_safe: true, idempotent: true, pinned: true }
    }
    fn effects(&self, _: &ToolCtx, _: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, _: &ToolCtx, i: Value) -> ToolOutput {
        ToolOutput::ok(i["text"].as_str().unwrap_or("").to_string())
    }
}

#[test]
fn dual_era_server_discover_and_version_errors() {
    let tools: Vec<Arc<dyn Tool>> = vec![Arc::new(Echo)];
    let info = ServerInfo { name: "seagent".into(), version: "0".into(), instructions: Some("hi".into()) };
    let d = tmp("srv");
    let c = || ctx(&d);
    let srv = seagent_plugin::Server { info: &info, tools: &tools, ctx: &c, judge: &|_| Ok(()) };
    let meta = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {}});
    let r = srv.handle(&json!({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta}})).unwrap();
    assert_eq!(r["result"]["supportedVersions"][0], "2026-07-28");
    assert_eq!((r["result"]["resultType"].as_str(), r["result"]["instructions"].as_str()), (Some("complete"), Some("hi")));
    let r = srv.handle(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "x"}, "_meta": meta}})).unwrap();
    assert_eq!((r["result"]["content"][0]["text"].as_str(), r["result"]["resultType"].as_str()), (Some("x"), Some("complete")));
    assert_eq!(r["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"], "seagent");
    let r = srv.handle(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "1900-01-01"}}})).unwrap();
    assert_eq!(r["error"]["code"], -32022);
    assert_eq!(r["error"]["data"]["requested"], "1900-01-01");
    // Legacy requests are untouched (no resultType).
    let r = srv.handle(&json!({"jsonrpc": "2.0", "id": 4, "method": "tools/list"})).unwrap();
    assert!(r["result"].get("resultType").is_none());
    assert!(srv.handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).is_none());
    // seagent's own client, in stateless mode, against seagent's server over a pipe-like stdio is covered by
    // the fixture; here the Client probes seagent's server's discover through the relay test below.
}

/// A fake relay: challenge → hello (signature checked) → ready → pair.offer → grant.create → mcp.
#[test]
fn relay_handshake_pairing_grants_and_mcp_passthrough() {
    let (tx, rx) = mpsc::channel::<Value>();
    let tx = Arc::new(Mutex::new(tx));
    let h: Handler = Arc::new(move |r: Request| {
        assert_eq!(r.path, "/v1/gateway/connect");
        let key = r.query("key").unwrap().to_string();
        let host = r.header("host").unwrap().to_string();
        let tx = tx.clone();
        Response::upgrade(Box::new(move |s, head, rest| {
            let mut ws = WebSocket::accept(s, &head, rest).unwrap();
            let report = |v: Value| tx.lock().unwrap().send(v).unwrap();
            let recv = |ws: &mut WebSocket<std::net::TcpStream>| -> Value {
                loop {
                    if let Ok(Message::Text(t)) = ws.recv_blocking() {
                        return serde_json::from_str(&t).unwrap();
                    }
                }
            };
            let nonce = seagent_net::crypto::b64url(&seagent_net::crypto::random_bytes(32));
            ws.send_text(&json!({"type": "challenge", "protocol": 1, "relay": host, "nonce": nonce}).to_string()).unwrap();
            let hello = recv(&mut ws);
            let pk = seagent_net::crypto::b64url_decode(&key).unwrap();
            let sig = seagent_net::crypto::b64url_decode(hello["signature"].as_str().unwrap()).unwrap();
            assert!(seagent_net::crypto::ed25519_verify(&pk, format!("openclaw-mcp-relay/v1\n{nonce}\n{host}").as_bytes(), &sig), "signed challenge");
            let gw = format!("gw_{}", &seagent_net::crypto::b64url(&seagent_net::crypto::sha256(&pk))[..22]);
            ws.send_text(&json!({"type": "ready", "gatewayId": gw}).to_string()).unwrap();
            let offer = recv(&mut ws);
            assert_eq!(offer["op"], "pair.offer");
            ws.send_text(&json!({"type": "res", "id": offer["id"], "ok": true, "result": {}}).to_string()).unwrap();
            let hash = offer["params"]["codeHash"].clone();
            ws.send_text(&json!({"type": "req", "id": "r1", "op": "grant.create", "params": {"grantId": "gr_1", "codeHash": hash, "client": {"id": "c", "name": "ChatGPT"}}}).to_string()).unwrap();
            report(recv(&mut ws));
            ws.send_text(&json!({"type": "req", "id": "r1b", "op": "grant.create", "params": {"grantId": "gr_2", "codeHash": hash, "client": {"id": "c", "name": "again"}}}).to_string()).unwrap();
            report(recv(&mut ws));
            ws.send_text(&json!({"type": "req", "id": "r2", "op": "mcp", "grantId": "gr_1", "params": {"message": {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "echo", "arguments": {"text": "through the relay"}}}}}).to_string()).unwrap();
            report(recv(&mut ws));
            ws.send_text(&json!({"type": "req", "id": "r3", "op": "status", "grantId": "nope", "params": {}}).to_string()).unwrap();
            report(recv(&mut ws));
            let _ = ws.send(&Message::Close(Some((1000, "bye".into()))));
        }))
    });
    let srv = Server::bind("127.0.0.1:0", Opts::default(), h).unwrap();
    let dir = tmp("relay");
    let opts = seagent_plugin::relay::Opts { relay: format!("http://{}", srv.local_addr()), state: dir.join("mcp-relay.json"), name: "seagent".into(), version: "0".into(), pair: true };
    let stop = Cancel::new();
    let (s2, d2) = (stop.clone(), dir.clone());
    let logs: Arc<Mutex<Vec<String>>> = Arc::default();
    let l2 = logs.clone();
    let th = std::thread::spawn(move || {
        let tools: Vec<Arc<dyn Tool>> = vec![Arc::new(Echo)];
        let info = ServerInfo { name: "seagent".into(), version: "0".into(), instructions: None };
        let c = || ctx(&d2);
        let server = seagent_plugin::Server { info: &info, tools: &tools, ctx: &c, judge: &|_| Ok(()) };
        let handle = |m: &Value| server.handle(m);
        seagent_plugin::relay::run(&opts, &handle, &s2, &|l: &str| l2.lock().unwrap().push(l.to_string())).unwrap();
    });
    let next = || rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let created = next();
    assert_eq!((created["id"].as_str(), created["ok"].as_bool()), (Some("r1"), Some(true)), "{created}");
    let reused = next();
    assert_eq!(reused["error"]["code"], "not_found", "pairing codes are single-use");
    let mcp = next();
    assert_eq!(mcp["result"]["message"]["result"]["content"][0]["text"], "through the relay");
    let revoked = next();
    assert_eq!(revoked["error"]["code"], "grant_revoked");
    stop.cancel();
    th.join().unwrap();
    assert!(logs.lock().unwrap().iter().any(|l| l.contains("pairing code")), "{:?}", logs.lock().unwrap());
    let st: Value = serde_json::from_slice(&std::fs::read(dir.join("mcp-relay.json")).unwrap()).unwrap();
    assert_eq!(st["grants"][0]["id"], "gr_1");
    assert!(st["codes"].as_array().unwrap().is_empty(), "redeemed code removed");
}
