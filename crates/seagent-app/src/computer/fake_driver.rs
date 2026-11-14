//! A fake cua-driver for computer-use tests: it answers `manifest` and speaks MCP over stdio,
//! logging every `tools/call`, so [`super::cua::Driver`] / [`super::cua::CuaBackend`] /
//! [`super::cua::CuaDesk`] run their real code paths without a desktop or a real driver.
#![cfg_attr(not(unix), allow(dead_code, unused_imports))]

use serde_json::Value;
use std::path::{Path, PathBuf};

const DRIVER: &str = r#"#!/usr/bin/env python3
import base64, json, os, sys

LOG = os.environ.get("FAKE_CUA_LOG", "")

def log(entry):
    if LOG:
        with open(LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")

MANIFEST = {
    "binary_version": "0.21.0",
    "mcp_invocation": {"command": os.path.realpath(sys.argv[0]), "args": ["mcp"]},
    "subcommands": [
        {"name": "mcp", "args": [{"name": "--grant"}, {"name": "--socket"}]},
        {"name": "serve", "args": [{"name": "--approve-capability-manifest"}, {"name": "--capability-manifest"},
                                    {"name": "--embedded"}, {"name": "--permission-mode"}, {"name": "--socket"}]},
        {"name": "stop", "args": [{"name": "--socket"}]},
    ],
}

PNG = (b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR" + (800).to_bytes(4, "big") + (600).to_bytes(4, "big")
       + bytes([8, 2, 0, 0, 0, 0, 0, 0, 0]))
PNG_B64 = base64.b64encode(PNG).decode()

PROPS = {k: {"type": "object"} for k in [
    "session", "pid", "window_id", "x", "y", "button", "click_count", "element_token", "element_index",
    "element_id", "text", "key", "keys", "modifier", "direction", "amount", "value", "path", "app",
    "from_x", "from_y", "to_x", "to_y", "windowRef", "observation_id", "delivery_mode", "max_elements",
    "max_depth", "query", "x1", "y1", "x2", "y2", "durationMs", "reason", "recordVideo", "delayMs",
    "stopOnError", "on_screen_only", "format", "quality",
]}
CLICK_CAPS = ["accessibility.element_tokens"]

TOOLS = {n: PROPS for n in [
    "start_session", "end_session", "set_config", "get_config", "set_agent_cursor_enabled",
    "get_desktop_state", "screenshot", "list_windows", "list_apps", "get_window_state",
    "get_accessibility_tree", "get_cursor_position", "click", "double_click", "move_mouse",
    "mouse_down", "mouse_up", "drag", "scroll", "type_text", "press_key", "hotkey", "hold_key",
    "set_value", "launch_app", "kill_app", "bring_to_front", "zoom", "invoke_menu",
    "escalate_scope", "get_recording_state", "start_recording", "stop_recording", "replay_trajectory",
]}

WINDOWS = {"windows": [{"pid": 4242, "window_id": 77, "app_name": "FakeApp",
                        "title": "Fake Window", "z_index": 1.0, "is_on_screen": True}]}
ELEMENTS = [
    {"element_index": 1, "role": "button", "label": "Sign in", "element_token": "tok-1",
     "frame": {"x": 10, "y": 10, "w": 100, "h": 30}},
    {"element_index": 2, "role": "textbox", "label": "Email", "element_token": "tok-2",
     "frame": {"x": 10, "y": 60, "w": 200, "h": 30}},
]

def text(obj):
    return {"type": "text", "text": obj if isinstance(obj, str) else json.dumps(obj)}

def reply(content, structured):
    return {"content": content, "structuredContent": structured}

def call(name, args):
    if name == "get_config":
        return reply([text({"capture_scope": "desktop"})], {"capture_scope": "desktop"})
    if name == "get_desktop_state" or name == "screenshot" or name == "zoom":
        return reply([text("screen"), {"type": "image", "data": PNG_B64, "mimeType": "image/png"}],
                     {"screenshot_width": 800, "screenshot_height": 600})
    if name == "list_windows":
        return reply([text(WINDOWS)], WINDOWS)
    if name == "list_apps":
        return reply([text({"apps": [{"name": "FakeApp", "pid": 4242, "running": True, "bundle_id": "fake.app"}]})],
                     {"apps": [{"name": "FakeApp", "pid": 4242, "running": True, "bundle_id": "fake.app"}]})
    if name == "get_window_state" or name == "get_accessibility_tree":
        return reply([text("AXWindow \"Fake Window\"\n[1] button \"Sign in\"\n[2] textbox \"Email\""),
                      {"type": "image", "data": PNG_B64, "mimeType": "image/png"}],
                     {"elements": ELEMENTS, "window_title": "Fake Window"})
    if name == "get_cursor_position":
        return reply([text({"x": 120, "y": 240})], {"x": 120, "y": 240})
    if name in ("start_session", "end_session", "set_config", "set_agent_cursor_enabled",
                "get_recording_state", "stop_recording", "escalate_scope"):
        return reply([text({"ok": True})], {"ok": True})
    return reply([text({"ok": True, "effect": "confirmed"})], {"ok": True, "effect": "confirmed"})

def serve():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        mid, method = msg.get("id"), msg.get("method")
        if mid is None:
            continue
        if method == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fake-cua-driver", "version": "0.21.0"}}
        elif method == "tools/list":
            result = {"tools": [{"name": n, "description": n, "inputSchema": {"type": "object", "properties": p},
                                 "capabilities": CLICK_CAPS if n in ("click", "double_click") else []}
                                for n, p in TOOLS.items()], "capability_version": "2025-11-25"}
        elif method == "tools/call":
            name = msg["params"]["name"]
            args = msg["params"].get("arguments") or {}
            log({"name": name, "args": args})
            result = call(name, args)
        else:
            result = {}
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}), flush=True)

if sys.argv[1:2] == ["manifest"]:
    print(json.dumps(MANIFEST))
elif sys.argv[1:2] == ["mcp"]:
    serve()
else:
    print("usage: cua-driver {manifest,mcp}\n  --no-overlay")
"#;

/// A fake driver binary plus the calls it recorded.
pub struct FakeDriver {
    pub path: PathBuf,
    pub log: PathBuf,
}

impl FakeDriver {
    #[cfg(unix)]
    /// Install at `<home>/bin/<name>` (None when this host has no python3).
    pub fn install(home: &Path, name: &str) -> Option<FakeDriver> {
        if !seagent_core::platform::proc::command("python3").arg("-c").arg("1").output().is_ok_and(|o| o.status.success()) {
            return None;
        }
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        let dir = home.join("bin");
        std::fs::create_dir_all(&dir).ok()?;
        let path = dir.join(name);
        std::fs::write(&path, DRIVER).ok()?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).ok()?;
        Some(FakeDriver { path, log: home.join(format!("{name}-calls.jsonl")) })
    }

    /// Env the tool passes to the driver child (the recording path).
    pub fn env(&self) -> Vec<(String, String)> {
        vec![("FAKE_CUA_LOG".into(), self.log.display().to_string())]
    }

    pub fn calls(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).collect()
    }

    /// Args of every call to `tool`, in order.
    pub fn args_of(&self, tool: &str) -> Vec<Value> {
        self.calls().into_iter().filter(|c| c["name"] == tool).map(|c| c["args"].clone()).collect()
    }
}

/// A `[computer_use]` config driving the fake over the given backend.
pub fn cfg(driver: &FakeDriver, backend: &str) -> super::ComputerUseConfig {
    super::ComputerUseConfig {
        backend: backend.into(),
        driver_cmd: driver.path.display().to_string(),
        vision: false,
        timeout: 15,
        target: "host".into(),
        ..Default::default()
    }
}

/// A throwaway session context (own home + workspace, headless host).
pub fn ctx(home: &Path, sid: &str) -> seagent_core::ToolCtx {
    struct Host;
    impl seagent_core::ToolHost for Host {
        fn spawn_agent(&self, _r: seagent_core::tool::SpawnRequest, _c: &seagent_core::Cancel) -> Result<String, String> {
            Err("no".into())
        }
        fn ask_user(&self, _q: &str) -> Result<String, String> {
            Err("headless".into())
        }
        fn analyze_image(&self, q: &str, _mime: &str, _data: &str) -> Result<String, String> {
            Ok(format!("fake vision: {q}"))
        }
    }
    let ws = home.join("ws");
    let _ = std::fs::create_dir_all(&ws);
    seagent_core::ToolCtx {
        workspace: ws.clone(),
        session_id: sid.into(),
        artifacts: ws.join(".artifacts"),
        home: home.to_path_buf(),
        cancel: seagent_core::Cancel::new(),
        host: std::sync::Arc::new(Host),
        secrets: std::sync::Arc::new(|s: &str| s.to_string()),
    }
}

/// `(tool-output, parsed)` of a call through `seagent_core::Tool`.
pub fn run(t: &dyn seagent_core::Tool, c: &seagent_core::ToolCtx, input: Value) -> (seagent_core::ToolOutput, Value) {
    let o = t.call(c, input);
    let v = serde_json::from_str(&o.content).unwrap_or(Value::Null);
    (o, v)
}

/// The JSON object on some line of `content` that mentions `needle` (tool output is text+JSON).
pub fn find_json(content: &str, needle: &str) -> Value {
    content.lines().filter(|l| l.contains(needle)).find_map(|l| serde_json::from_str::<Value>(l).ok()).unwrap_or(Value::Null)
}

