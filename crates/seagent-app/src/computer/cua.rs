//! cua-driver over stdio MCP (Hermes `tools/computer_use/cua_backend*.py`; OpenClaw
//! `extensions/cua-computer/src/mcp-driver-client.ts`, both MIT).
//!
//! [`Driver`] is the transport: it resolves the binary like `seagent computer-use status`
//! (seagent-browser `control::cua`), gates on the 0.20 runtime contract (`cua-driver manifest`),
//! spawns the driver's own `mcp_invocation` (fallback `cua-driver mcp`), discovers per-tool
//! input schemas / capabilities from `tools/list`, declares a public session label and
//! flattens every `tools/call` result. [`CuaBackend`] is Hermes' `CuaDriverBackend`
//! (sticky window target, element tokens, delivery ladder) on top of it.

use super::backend::{image_size, mime_of, ActionResult, Backend, Capture, Delivery, Element, Point};
use super::config::ComputerUseConfig;
use seagent_core::Cancel;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const TELEMETRY_ENV: &str = "CUA_DRIVER_RS_TELEMETRY_ENABLED";
pub const NATIVE_WAYLAND_ENV: &str = "CUA_DRIVER_RS_ENABLE_WAYLAND";
/// Idempotent reads, safe to replay after a broken transport (mutations never are).
const REPLAY_SAFE: &[&str] = &["get_cursor_position", "get_displays", "get_screen_size", "get_window_state", "list_apps", "list_windows"];
const LIFECYCLE: &[&str] = &["start_session", "end_session"];

pub fn install_hint() -> String {
    "cua-driver is not installed. Install the pinned driver with:\n  seagent computer-use install\nor point [computer_use] driver_cmd (or $SEAGENT_CUA_DRIVER_CMD) at an existing binary.".into()
}

/// The driver `computer_use` would run: `$SEAGENT_CUA_DRIVER_CMD`, `driver_cmd`, `<home>/bin/cua-driver`, PATH.
pub fn resolve_driver(cfg: &ComputerUseConfig, home: &Path) -> Option<PathBuf> {
    use seagent_browser::control::{cua, screen};
    let explicit = std::env::var(cua::DRIVER_ENV).ok().filter(|s| !s.trim().is_empty()).or_else(|| Some(cfg.driver_cmd.clone()).filter(|s| !s.trim().is_empty()));
    let cu = cua::Cu { home: home.to_path_buf(), override_cmd: explicit, artifact: None, backend: cfg.backend.clone(), desktop: screen::Desktop::new(home), config_home: None };
    cu.resolve()
}

/// Env for the driver child: the Bot Desktop's DISPLAY/XAUTHORITY/bus (`desktop_env`), telemetry
/// off unless opted in, the native-Wayland bridge when asked for and a Wayland display exists.
/// (Provider secrets are scrubbed by the MCP stdio transport.)
pub fn child_env(cfg: &ComputerUseConfig, desktop_env: &[(String, String)]) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = desktop_env.to_vec();
    if !cfg.cua_telemetry {
        env.push((TELEMETRY_ENV.into(), "0".into()));
    }
    let wayland = desktop_env.iter().find(|(k, _)| k == "WAYLAND_DISPLAY").map(|(_, v)| v.clone()).or_else(|| std::env::var("WAYLAND_DISPLAY").ok()).is_some_and(|v| !v.is_empty());
    if cfg.native_wayland && wayland {
        env.push((NATIVE_WAYLAND_ENV.into(), "1".into()));
    }
    env.push(("CUA_DRIVER_RS_UPDATE_CHECK".into(), "false".into()));
    env
}

fn run_out(bin: &Path, args: &[&str], t: Duration, env: &[(String, String)]) -> Option<(i32, String, String)> {
    let b = bin.display().to_string();
    let mut argv = vec![b.as_str()];
    argv.extend_from_slice(args);
    let e: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    seagent_browser::util::run(&argv, t, None, &e).ok()
}

/// One flattened `tools/call` result (Hermes `_extract_tool_result`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Out {
    /// Joined text parts, parsed as JSON when they look like JSON.
    pub data: Value,
    /// (base64, mime) image parts; mime "" when the part carried none.
    pub images: Vec<(String, String)>,
    pub structured: Value,
    pub is_error: bool,
}

impl Out {
    pub fn text(&self) -> String {
        match &self.data {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            v => v.to_string(),
        }
    }
    /// Screenshot as (bytes, mime): an image part, else `screenshot_png_b64` / `png_b64`.
    pub fn image(&self) -> Option<(Vec<u8>, String)> {
        let (b64, mime) = match self.images.first().filter(|(d, _)| !d.is_empty()) {
            Some((d, m)) => (d.clone(), m.clone()),
            None => {
                let s = &self.structured;
                let b = s["screenshot_png_b64"].as_str().or(s["png_b64"].as_str()).or(s["image_base64"].as_str())?;
                (b.to_string(), s["screenshot_mime_type"].as_str().or(s["mime_type"].as_str()).unwrap_or("").to_string())
            }
        };
        let bytes = seagent_net::crypto::b64_decode(b64.trim())?;
        let mime = if mime.is_empty() { mime_of(&bytes).to_string() } else { mime };
        Some((bytes, mime))
    }
}

pub fn flatten(raw: &Value) -> Out {
    let mut texts = vec![];
    let mut images = vec![];
    for part in raw["content"].as_array().into_iter().flatten() {
        match part["type"].as_str() {
            Some("text") => texts.push(part["text"].as_str().unwrap_or("").to_string()),
            Some("image") if part["data"].as_str().is_some_and(|d| !d.is_empty()) => images.push((part["data"].as_str().unwrap_or("").to_string(), part["mimeType"].as_str().unwrap_or("").to_string())),
            _ => {}
        }
    }
    let joined = texts.into_iter().filter(|t| !t.is_empty()).collect::<Vec<_>>().join("\n");
    let data = if joined.is_empty() {
        Value::Null
    } else if joined.trim_start().starts_with(['{', '[']) {
        serde_json::from_str(&joined).unwrap_or(Value::String(joined))
    } else {
        Value::String(joined)
    };
    let structured = raw.get("structuredContent").filter(|s| s.is_object()).cloned().unwrap_or(Value::Null);
    Out { data, images, structured, is_error: raw["isError"] == true }
}

fn outcome_unknown(name: &str, e: &str, code: &str) -> Out {
    Out {
        data: json!(format!("cua-driver {name}: outcome unknown ({e}); the action may or may not have landed — re-capture before retrying")),
        images: vec![],
        structured: json!({"code": code, "message": format!("outcome unknown: {e}")}),
        is_error: true,
    }
}

/// cua-driver's recoverable ended-session rejection.
fn ended_session(o: &Out) -> bool {
    let m = format!("{} {}", o.text(), o.structured).to_lowercase();
    o.is_error && m.contains("session") && m.contains("start_session") && (m.contains("has ended") || m.contains("session ended"))
}

/// The live MCP connection to one cua-driver.
pub struct Driver {
    client: seagent_plugin::Client,
    schemas: HashMap<String, Value>,
    caps: HashMap<String, HashSet<String>>,
    pub capability_version: String,
    /// Public session label sent as `session` on every call.
    pub session: String,
    declared: bool,
    daemon: Option<(std::process::Child, PathBuf)>,
    pub bin: PathBuf,
    pub command: String,
    pub args: Vec<String>,
}

impl Driver {
    /// Spawn and handshake. `prefix` names the session label (`seagent-…` / `openclaw-…`).
    pub fn start(cfg: &ComputerUseConfig, home: &Path, desktop_env: &[(String, String)], prefix: &str) -> Result<Driver, String> {
        let bin = resolve_driver(cfg, home).ok_or_else(install_hint)?;
        let env = child_env(cfg, desktop_env);
        let manifest: Option<Value> = run_out(&bin, &["manifest"], Duration::from_secs(6), &env).filter(|(c, _, _)| *c == 0).and_then(|(_, o, _)| serde_json::from_str(o.trim()).ok());
        let reason = seagent_browser::control::cua::manifest_reason(manifest.as_ref());
        if !reason.is_empty() {
            return Err(format!("cua-driver is not ready: {reason}. Run `seagent computer-use install` to repair it, or update the binary [computer_use] driver_cmd selects."));
        }
        let m = manifest.unwrap_or_default();
        let mut args: Vec<String> = m["mcp_invocation"]["args"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_else(|| vec!["mcp".into()]);
        // Only a concrete (path-bearing) manifest command replaces the binary we verified.
        let command = m["mcp_invocation"]["command"].as_str().filter(|c| c.contains('/')).map(PathBuf::from).unwrap_or_else(|| bin.clone());
        let lookup = |k: &str| desktop_env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).or_else(|| std::env::var(k).ok());
        let no_overlay = cfg.no_overlay(&lookup);
        if no_overlay && run_out(&command, &["--help"], Duration::from_secs(3), &env).is_some_and(|(_, o, e)| format!("{o}{e}").contains("--no-overlay")) {
            args.push("--no-overlay".into());
        }
        let mut daemon = None;
        if cfg.permission_mode == "bounded" {
            // bounded: a private `serve` daemon validates the capability manifest; `mcp` proxies to it.
            let sock = crate::node::tmp_file("cua", "sock");
            let s = sock.display().to_string();
            let manifest_path = seagent_core::tool::expand_home(cfg.capability_manifest.trim()).display().to_string();
            let child = std::process::Command::new(&bin)
                .args(["serve", "--socket", &s, "--permission-mode", "bounded", "--capability-manifest", &manifest_path, "--embedded"])
                .envs(env.iter().map(|(k, v)| (k, v)))
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .map_err(|e| format!("cua-driver serve: {e}"))?;
            let deadline = Instant::now() + Duration::from_secs(10);
            while !sock.exists() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if !sock.exists() {
                let mut c = child;
                let _ = c.kill();
                let _ = c.wait();
                return Err("cua-driver serve (permission_mode = \"bounded\") did not open its socket within 10s; check capability_manifest".into());
            }
            args.extend(["--socket".to_string(), s]);
            daemon = Some((child, sock));
        }
        let mcfg = seagent_plugin::McpServerConfig { command: Some(command.display().to_string()), args: args.clone(), env: env.iter().cloned().collect(), timeout_secs: Some(cfg.timeout.clamp(5, 600)), ..Default::default() };
        let client = seagent_plugin::Client::new("cua-driver", mcfg, Arc::new(|s: &str| s.to_string()))?;
        let mut d = Driver { client, schemas: HashMap::new(), caps: HashMap::new(), capability_version: String::new(), session: format!("{prefix}-{}", seagent_net::crypto::random_token(6)), declared: false, daemon, bin, command: command.display().to_string(), args };
        d.discover()?;
        let sid = d.session.clone();
        let o = d.call("start_session", json!({"session": sid}));
        d.declared = !o.is_error;
        Ok(d)
    }

    /// Per-tool input schemas and capability tokens (`tools/list`); soft prerequisite.
    fn discover(&mut self) -> Result<(), String> {
        let r = self.client.request("tools/list", json!({}), &Cancel::new()).map_err(|e| format!("cua-driver MCP startup failed: {e}"))?;
        for t in r["tools"].as_array().into_iter().flatten() {
            let Some(name) = t["name"].as_str() else { continue };
            self.schemas.insert(name.to_string(), t.get("inputSchema").cloned().unwrap_or(json!({})));
            self.caps.insert(name.to_string(), t["capabilities"].as_array().into_iter().flatten().filter_map(|c| c.as_str().map(str::to_string)).collect());
        }
        self.capability_version = r["capability_version"].as_str().unwrap_or("").to_string();
        Ok(())
    }

    pub fn has_tool(&self, name: &str) -> bool {
        self.schemas.contains_key(name)
    }
    pub fn discovered(&self) -> bool {
        !self.schemas.is_empty()
    }
    /// The live schema of `tool` accepts `prop` (fails closed).
    pub fn supports_prop(&self, tool: &str, prop: &str) -> bool {
        self.schemas.get(tool).is_some_and(|s| s["properties"].get(prop).is_some())
    }
    pub fn supports_cap(&self, cap: &str, tool: Option<&str>) -> bool {
        match tool {
            Some(t) => self.caps.get(t).is_some_and(|c| c.contains(cap)),
            None => self.caps.values().any(|c| c.contains(cap)),
        }
    }
    pub fn tools(&self) -> Vec<String> {
        let mut v: Vec<String> = self.schemas.keys().cloned().collect();
        v.sort();
        v
    }

    fn raw_call(&self, name: &str, args: &Value) -> Result<Out, String> {
        self.client.call_tool(name, args.clone(), &Cancel::new()).map(|r| {
            let mut o = flatten(&r.raw);
            o.is_error |= r.is_error;
            o
        })
    }

    /// One tool call. Transport failures never replay a mutation: they come back as an
    /// `outcome_unknown` error; idempotent reads retry once on a fresh connection. An
    /// ended-session rejection re-declares the label and retries once.
    pub fn call(&mut self, name: &str, args: Value) -> Out {
        let mut out = match self.raw_call(name, &args) {
            Ok(o) => o,
            Err(e) if REPLAY_SAFE.contains(&name) => match self.raw_call(name, &args) {
                Ok(o) => o,
                Err(e2) => return outcome_unknown(name, &format!("{e}; retry: {e2}"), "transport_outcome_unknown"),
            },
            Err(e) => return outcome_unknown(name, &e, if e.contains("timed out") || e.contains("timeout") { "timeout_outcome_unknown" } else { "transport_outcome_unknown" }),
        };
        if ended_session(&out) && !LIFECYCLE.contains(&name) && self.declared {
            let sid = self.session.clone();
            if self.raw_call("start_session", &json!({"session": sid})).is_ok_and(|o| !o.is_error) {
                if let Ok(o) = self.raw_call(name, &args) {
                    out = o;
                }
            }
        }
        out
    }

    /// `call` with `session` injected (unless the caller supplied one).
    pub fn scall(&mut self, name: &str, mut args: Value) -> Out {
        if let Some(m) = args.as_object_mut() {
            m.entry("session").or_insert_with(|| json!(self.session));
        }
        self.call(name, args)
    }

    pub fn stop(&mut self) {
        if self.declared {
            let sid = self.session.clone();
            let _ = self.raw_call("end_session", &json!({"session": sid}));
            self.declared = false;
        }
        self.client.shutdown();
        if let Some((mut c, sock)) = self.daemon.take() {
            let _ = c.kill();
            let _ = c.wait();
            let _ = std::fs::remove_file(sock);
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Hermes `_action_result_from`: lift cua-driver's structured verdict (structuredContent wins, the
/// flattened text payload is the fallback).
pub fn action_result(name: &str, o: &Out, requested_delivery: Option<&str>) -> ActionResult {
    let mut meta = Map::new();
    for part in [&o.data, &o.structured] {
        if let Some(m) = part.as_object() {
            meta.extend(m.clone());
        }
    }
    let raw = |k: &str| o.structured.get(k).or_else(|| meta.get(k)).cloned().unwrap_or(Value::Null);
    let message = match &o.data {
        Value::Object(m) => m.get("message").and_then(Value::as_str).unwrap_or("").to_string(),
        Value::String(s) => s.clone(),
        _ => String::new(),
    };
    let message = if message.is_empty() { o.structured["message"].as_str().unwrap_or("").to_string() } else { message };
    let s = |v: Value| v.as_str().map(str::to_string);
    ActionResult {
        ok: !o.is_error,
        action: name.into(),
        message,
        verified: raw("verified").as_bool(),
        effect: s(raw("effect")),
        escalation: Some(raw("escalation")).filter(Value::is_object),
        path: s(raw("path")),
        degraded: raw("degraded").as_bool(),
        delivery_mode: requested_delivery.map(str::to_string),
        code: s(raw("code")).or_else(|| s(raw("reason_code"))),
        meta,
    }
}

// ───────────────────────── window discovery (Hermes cua_backend_parse / _capture) ─────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub struct Win {
    pub app: String,
    pub pid: i64,
    pub wid: i64,
    pub off_screen: bool,
    pub title: String,
    pub z: f64,
}

fn positive(v: &Value) -> Option<i64> {
    let n = match v {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }?;
    (n > 0).then_some(n)
}

/// Normalised `list_windows` rows, frontmost first; rows without integer pid/window_id are skipped.
pub fn windows(o: &Out) -> Vec<Win> {
    let mut raw: Vec<Value> = vec![];
    for (c, keys) in [(&o.structured, &["windows"][..]), (&o.data, &["windows", "_legacy_windows"][..])] {
        if let Some(v) = keys.iter().find_map(|k| c[*k].as_array().filter(|a| !a.is_empty())) {
            raw = v.clone();
            break;
        }
    }
    let mut w: Vec<Win> = raw
        .iter()
        .filter_map(|w| {
            Some(Win {
                pid: positive(&w["pid"])?,
                wid: positive(&w["window_id"])?,
                app: w["app_name"].as_str().unwrap_or("").to_string(),
                off_screen: w["is_on_screen"] == false,
                title: w["title"].as_str().unwrap_or("").to_string(),
                z: w["z_index"].as_f64().unwrap_or(0.0),
            })
        })
        .collect();
    w.sort_by(|a, b| b.z.partial_cmp(&a.z).unwrap_or(std::cmp::Ordering::Equal));
    w
}

const NON_APP_TITLES: &[&str] = &["@!", "Desktop", "gnome-shell", "GNOME Shell"];
const FULL_SCREEN: &[&str] = &["screen", "fullscreen", "full screen", "all"];
const DESKTOP_NAMES: &[&str] = &["progman", "workerw", "program manager", "shell_traywnd", "taskbar", "finder", "desktop", "dock"];
const DESKTOP_BACKDROP: &[&str] = &["progman", "workerw", "program manager", "finder", "desktop"];
pub const FULL_SCREEN_NOTE: &str = "full-screen capture has no interactable elements; to act on what you see, call capture(app='<AppName>') for that app's clickable element list, or capture(app='desktop') for the desktop shell (wallpaper icons / taskbar) with elements";

fn real_app_window(w: &Win) -> bool {
    !NON_APP_TITLES.iter().any(|p| w.title.starts_with(p) || w.title.to_lowercase().starts_with(&p.to_lowercase()))
}
fn self_window(w: &Win) -> bool {
    w.app.trim().to_lowercase().replace([' ', '_', '-'], "") == "cuadriver"
}
fn desktop_window(w: &Win, names: &[&str]) -> bool {
    let h = format!("{} {}", w.app, w.title).to_lowercase();
    names.iter().any(|n| h.contains(n))
}

/// Best window of a frontmost-first list (Hermes `_select_capture_target`).
pub fn select_target(windows: &[Win], app_requested: bool, exact: bool, active: Option<i64>) -> Option<Win> {
    let mut pool: Vec<&Win> = windows.iter().filter(|w| !w.off_screen).collect();
    if !exact {
        let ext: Vec<&Win> = pool.iter().copied().filter(|w| !self_window(w)).collect();
        if !ext.is_empty() {
            pool = ext;
        }
    }
    if !exact && !app_requested {
        let real: Vec<&Win> = pool.iter().copied().filter(|w| real_app_window(w)).collect();
        if !real.is_empty() {
            pool = real;
        }
        let uninformative = pool.iter().map(|w| w.z.to_bits()).collect::<HashSet<_>>().len() <= 1;
        if uninformative {
            if let Some(hit) = active.and_then(|a| pool.iter().find(|w| w.wid == a)) {
                return Some((*hit).clone());
            }
        }
    }
    pool.first().map(|w| (*w).clone()).or_else(|| windows.first().cloned())
}

/// `xprop -root _NET_ACTIVE_WINDOW` (best effort; X11 only).
fn x11_active_window() -> Option<i64> {
    let out = crate::node::run_cmd(&["xprop", "-root", "_NET_ACTIVE_WINDOW"], Duration::from_secs(2)).ok()?;
    let i = out.find("0x")?;
    let hex: String = out[i + 2..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    i64::from_str_radix(&hex, 16).ok()
}

/// get_window_state AX-tree markdown → elements (fallback for drivers without structuredContent.elements).
pub fn parse_tree(markdown: &str) -> Vec<Element> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r#"(?m)^\s*(?:-\s+)?\[(\d+)\]\s+(\w+)(?:\s*=\s*"([^"]*)"|\s+"([^"]*)"|\s+\(([^)]*)\))?(?:\s+(?:\(\d+\)\s+)?id=([^\s\[\]]+))?"#).unwrap());
    re.captures_iter(markdown)
        .filter_map(|c| {
            let paren = c.get(5).map(|m| m.as_str()).filter(|p| !p.chars().all(|ch| ch.is_ascii_digit()));
            let label = c.get(3).map(|m| m.as_str()).or(c.get(4).map(|m| m.as_str())).or(paren).or(c.get(6).map(|m| m.as_str())).unwrap_or("");
            Some(Element { index: c[1].parse().ok()?, role: c[2].to_string(), label: label.to_string(), ..Default::default() })
        })
        .collect()
}

/// The canonical `structuredContent.elements` array (real frames + element tokens).
pub fn parse_structured(raw: &[Value]) -> Vec<Element> {
    raw.iter()
        .filter_map(|e| {
            let index = e["element_index"].as_u64()? as u32;
            let f = &e["frame"];
            let n = |k: &str| f[k].as_f64().map(|v| v as i64).unwrap_or(0);
            Some(Element {
                index,
                role: e["role"].as_str().unwrap_or("").to_string(),
                label: e["label"].as_str().unwrap_or("").to_string(),
                bounds: if f.is_object() { [n("x"), n("y"), n("w"), n("h")] } else { [0; 4] },
                app: String::new(),
                handle: e["element_token"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect()
}

/// (key, modifiers) of `cmd+s` / `ctrl-alt-t`; the last non-modifier wins (Hermes `_parse_key_combo`).
pub fn parse_key_combo(keys: &str) -> (Option<String>, Vec<String>) {
    let mut mods = vec![];
    let mut key = None;
    for part in keys.split(['+', '-']).map(|p| p.trim().to_lowercase()).filter(|p| !p.is_empty()) {
        let n = match part.as_str() {
            "command" => "cmd",
            "alt" => "option",
            "control" => "ctrl",
            p => p,
        }
        .to_string();
        if matches!(n.as_str(), "cmd" | "shift" | "option" | "ctrl" | "fn") {
            mods.push(n);
        } else {
            key = Some(part);
        }
    }
    (key, mods)
}

// ───────────────────────── Hermes CuaDriverBackend ─────────────────────────

const NO_TARGET: &str = "No active window — call capture() first.";
const BTF_UNSUPPORTED: &str = "The connected cua-driver does not advertise the standalone bring_to_front tool.";
const FG_UNSUPPORTED: &str = "The connected cua-driver action schema does not accept delivery_mode, so foreground delivery is unavailable. Use another verified rung without assuming the reported package version describes the live schema.";

pub struct CuaBackend {
    pub d: Driver,
    pid: Option<i64>,
    wid: Option<i64>,
    last_app: Option<String>,
    target: Option<(i64, i64)>,
    tokens: HashMap<u32, String>,
    ax_max: u32,
}

impl CuaBackend {
    pub fn start(cfg: &ComputerUseConfig, home: &Path, env: &[(String, String)]) -> Result<CuaBackend, String> {
        let mut d = Driver::start(cfg, home, env, "seagent")?;
        if cfg.max_image_dimension > 0 {
            d.scall("set_config", json!({"max_image_dimension": cfg.max_image_dimension}));
        }
        let lookup = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).or_else(|| std::env::var(k).ok());
        if cfg.no_overlay(&lookup) {
            let sid = d.session.clone();
            d.scall("set_agent_cursor_enabled", json!({"enabled": false, "cursor_id": sid}));
        }
        Ok(CuaBackend { d, pid: None, wid: None, last_app: None, target: None, tokens: HashMap::new(), ax_max: cfg.ax_max_elements })
    }

    fn clear(&mut self) {
        self.pid = None;
        self.wid = None;
        self.last_app = None;
        self.target = None;
        self.tokens.clear();
    }
    fn set_target(&mut self, w: &Win) {
        self.pid = Some(w.pid);
        self.wid = Some(w.wid);
        self.tokens.clear();
        self.target = Some((w.pid, w.wid));
    }
    fn failed(&mut self, mode: &str, msg: &str) -> Capture {
        self.clear();
        Capture { mode: mode.into(), window_title: msg.into(), ..Default::default() }
    }

    fn list_windows_raw(&mut self) -> Vec<Win> {
        let o = self.d.scall("list_windows", json!({"on_screen_only": true}));
        windows(&o)
    }

    /// `app=` → exact window names, exact list_apps aliases, substrings, nameless titles.
    fn match_app(&mut self, ws: &[Win], app: &str) -> Vec<Win> {
        let want = app.trim().to_lowercase();
        let exact: Vec<Win> = ws.iter().filter(|w| !want.is_empty() && w.app.trim().to_lowercase() == want).cloned().collect();
        if want.is_empty() || !exact.is_empty() {
            return exact;
        }
        let apps = self.list_apps().unwrap_or_default();
        let (mut exact_pids, mut partial_pids) = (HashSet::new(), HashSet::new());
        for a in &apps {
            let Some(pid) = positive(&a["pid"]) else { continue };
            if a["running"] == false {
                continue;
            }
            let aliases: Vec<String> = ["bundle_id", "bundleId", "name", "app_name", "display_name"].iter().filter_map(|k| a[*k].as_str()).map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect();
            if aliases.contains(&want) {
                exact_pids.insert(pid);
            } else if aliases.iter().any(|s| s.contains(&want)) {
                partial_pids.insert(pid);
            }
        }
        let tiers: [Vec<Win>; 4] = [
            ws.iter().filter(|w| exact_pids.contains(&w.pid)).cloned().collect(),
            ws.iter().filter(|w| w.app.to_lowercase().contains(&want)).cloned().collect(),
            ws.iter().filter(|w| partial_pids.contains(&w.pid)).cloned().collect(),
            ws.iter().filter(|w| w.app.trim().is_empty() && w.title.to_lowercase().contains(&want)).cloned().collect(),
        ];
        tiers.into_iter().find(|t| !t.is_empty()).unwrap_or_default()
    }

    fn gws_args(&self) -> Value {
        let mut a = json!({"pid": self.pid, "window_id": self.wid});
        if self.ax_max > 0 {
            a["max_elements"] = json!(self.ax_max);
        }
        a
    }

    fn full_screen(&mut self, mode: &str) -> Capture {
        self.clear();
        let prev = self.d.scall("get_config", json!({})).structured["capture_scope"].as_str().map(str::to_string);
        if prev.as_deref() != Some("desktop") {
            self.d.scall("set_config", json!({"key": "capture_scope", "value": "desktop"}));
        }
        let o = self.d.scall("get_desktop_state", json!({}));
        if let Some(p) = prev.filter(|p| p != "desktop") {
            self.d.scall("set_config", json!({"key": "capture_scope", "value": p}));
        }
        let Some((img, mime)) = o.image().filter(|_| !o.is_error) else {
            return self.failed(mode, "<get_desktop_state returned no image; the driver may predate the desktop capture lane — try capture(app='<AppName>') for a specific window>");
        };
        let (w, h) = image_size(&img).unwrap_or((o.structured["screenshot_width"].as_u64().unwrap_or(0) as u32, o.structured["screenshot_height"].as_u64().unwrap_or(0) as u32));
        Capture { mode: "vision".into(), width: w, height: h, image: Some(img), mime, app: "screen".into(), window_title: "Full screen (composited)".into(), note: FULL_SCREEN_NOTE.into(), ..Default::default() }
    }

    fn target_args(&self, action: &str, need_window: bool) -> Result<Value, Box<ActionResult>> {
        match (self.pid, self.wid) {
            (Some(p), w) if !need_window || w.is_some() => Ok(if need_window { json!({"pid": p, "window_id": w}) } else { json!({"pid": p}) }),
            _ => Err(Box::new(ActionResult::refuse(action, NO_TARGET))),
        }
    }

    /// Fill element / coordinate addressing (+ window_id).
    ///
    /// The refusal is boxed: `ActionResult` is the crate's public action payload, and returning it
    /// by value from these small helpers tripped `result_large_err`.
    fn pointer(&self, tool: &str, args: &mut Value, at: Point, missing: Option<&str>) -> Result<(), Box<ActionResult>> {
        let extra = match at {
            Point::Element(i) => json!({"element_index": i}),
            Point::Xy(x, y) => json!({"x": x, "y": y}),
            Point::None => return missing.map_or(Ok(()), |m| Err(Box::new(ActionResult::refuse(tool, m)))),
        };
        let Some(w) = self.wid else { return Err(Box::new(ActionResult::refuse(tool, format!("No active window_id for {}.", if matches!(at, Point::Element(_)) { "element_index click" } else { "coordinate click" })))) };
        merge(args, extra);
        args["window_id"] = json!(w);
        Ok(())
    }

    fn act(&mut self, name: &str, mut args: Value, inject_session: bool) -> ActionResult {
        if let Some(idx) = args["element_index"].as_u64() {
            if let Some(tok) = self.tokens.get(&(idx as u32)).cloned() {
                if self.d.supports_prop(name, "element_token") || self.d.supports_cap("accessibility.element_tokens", Some(name)) {
                    args["element_token"] = json!(tok);
                }
            }
        }
        let delivery = args["delivery_mode"].as_str().map(str::to_string);
        let o = if inject_session { self.d.scall(name, args) } else { self.d.call(name, args) };
        action_result(name, &o, delivery.as_deref())
    }

    /// One delivery rung; `bring_to_front` runs the standalone focus tool first.
    fn run_input(&mut self, action: &str, mut args: Value, d: &Delivery) -> ActionResult {
        match d.mode.as_deref() {
            None | Some("background") => {}
            Some("foreground") => {
                if !self.d.supports_prop(action, "delivery_mode") {
                    let mut r = ActionResult::refuse(action, FG_UNSUPPORTED).code("foreground_unsupported");
                    r.delivery_mode = Some("foreground".into());
                    return r;
                }
                args["delivery_mode"] = json!("foreground");
            }
            Some(m) => return ActionResult::refuse(action, format!("unknown delivery_mode '{m}' — use background|foreground.")).code("bad_delivery_mode"),
        }
        if d.bring_to_front {
            if d.mode.as_deref() != Some("foreground") {
                return ActionResult::refuse(action, "bring_to_front requires delivery_mode='foreground'.").code("bring_to_front_requires_foreground");
            }
            if !self.d.has_tool("bring_to_front") {
                let mut r = ActionResult::refuse(action, BTF_UNSUPPORTED).code("bring_to_front_unsupported");
                r.delivery_mode = Some("foreground".into());
                return r;
            }
            let (Some(p), Some(w)) = (self.pid, self.wid) else {
                let mut r = ActionResult::refuse(action, "Capture an exact target before requesting persistent foreground focus.").code("bring_to_front_target_required");
                r.delivery_mode = Some("foreground".into());
                return r;
            };
            let f = self.act("bring_to_front", json!({"pid": p, "window_id": w}), false);
            if !f.ok {
                return f;
            }
        }
        let mut r = self.act(action, args, true);
        if d.bring_to_front {
            r.meta.insert("foreground_focus".into(), json!({"invoked": true, "tool": "bring_to_front"}));
        }
        r
    }
}

pub fn merge(a: &mut Value, b: Value) {
    if let (Some(m), Value::Object(n)) = (a.as_object_mut(), b) {
        m.extend(n);
    }
}

// ───────────────────────── OpenClaw `computer` desk over cua-driver ─────────────────────────

/// The `computer` (OpenClaw) surface on cua-driver: the same driver `computer_use` uses,
/// carrying frame-bound desktop coordinates plus `windowRef` / `elementRef` / `observationId`
/// targets. Refs are minted here (`w1`, `e3`) and only mean something to this desk.
pub struct CuaDesk {
    pub d: Driver,
    /// windowRef → window.
    wins: HashMap<String, Win>,
    /// windowRef → latest observationId.
    obs: HashMap<String, String>,
    /// elementRef → (windowRef, element token).
    tokens: HashMap<String, (String, String)>,
    seq: u64,
}

impl CuaDesk {
    pub fn start(cfg: &ComputerUseConfig, home: &Path, env: &[(String, String)]) -> Result<CuaDesk, String> {
        let mut d = Driver::start(cfg, home, env, "openclaw")?;
        if cfg.max_image_dimension > 0 {
            d.scall("set_config", json!({"max_image_dimension": cfg.max_image_dimension}));
        }
        // Desktop captures (`computer` screenshot) read the whole screen, like the native desk.
        d.scall("set_config", json!({"key": "capture_scope", "value": "desktop"}));
        let lookup = |k: &str| env.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).or_else(|| std::env::var(k).ok());
        if cfg.no_overlay(&lookup) {
            let sid = d.session.clone();
            d.scall("set_agent_cursor_enabled", json!({"enabled": false, "cursor_id": sid}));
        }
        Ok(CuaDesk { d, wins: HashMap::new(), obs: HashMap::new(), tokens: HashMap::new(), seq: 0 })
    }

    fn win(&self, p: &Value) -> Result<Option<Win>, String> {
        match p["windowRef"].as_str().map(str::trim).filter(|w| !w.is_empty()) {
            None => Ok(None),
            Some(r) => self.wins.get(r).cloned().map(Some).ok_or_else(|| format!("COMPUTER_STALE_WINDOW: unknown windowRef {r}; call list_windows again")),
        }
    }

    /// Window input carries the observation it was computed from; a newer one invalidates it.
    fn check_observation(&self, p: &Value) -> Result<(), String> {
        let (Some(w), Some(o)) = (p["windowRef"].as_str(), p["observationId"].as_str()) else { return Ok(()) };
        match self.obs.get(w) {
            Some(cur) if cur == o => Ok(()),
            _ => Err("COMPUTER_STALE_OBSERVATION: observationId is not the latest get_window_state for this windowRef; observe again".into()),
        }
    }

    fn target(&self, p: &Value, out: &mut Value, need_window: bool) -> Result<(), String> {
        if let Some(w) = self.win(p)? {
            out["pid"] = json!(w.pid);
            if need_window {
                out["window_id"] = json!(w.wid);
            }
        }
        if let Some(e) = p["elementRef"].as_str().filter(|e| !e.is_empty()) {
            let (w, tok) = self.tokens.get(e).ok_or_else(|| format!("COMPUTER_STALE_ELEMENT: unknown elementRef {e}; call get_window_state again"))?;
            out["element_token"] = json!(tok);
            if let Some(win) = self.wins.get(w) {
                out["pid"] = json!(win.pid);
                out["window_id"] = json!(win.wid);
            }
        }
        if let Some(n) = p["observationId"].as_str() {
            out["observation_id"] = json!(n);
        }
        Ok(())
    }

    /// A driver tool this desk needs but the connected driver does not advertise.
    fn need(&self, tool: &str, action: &str) -> Result<(), String> {
        if self.d.discovered() && !self.d.has_tool(tool) {
            return Err(format!("COMPUTER_UNSUPPORTED_ACTION: the connected cua-driver has no `{tool}` tool, which `{action}` needs; update the driver (`seagent computer-use install`)"));
        }
        Ok(())
    }

    /// A driver reply as the `computer` tool's result object.
    fn reply(&self, action: &str, o: &Out) -> Result<Value, String> {
        if o.is_error {
            let m = o.text();
            let m = if m.trim().is_empty() { o.structured.to_string() } else { m };
            return Err(format!("COMPUTER_DRIVER_ERROR: cua-driver {action} failed: {m}"));
        }
        let mut v = match o.data.clone() {
            v @ Value::Object(_) => v,
            v => json!({"details": v}),
        };
        {
            let m = v.as_object_mut().unwrap();
            m.insert("ok".into(), json!(true));
            if !m.contains_key("effect") && !m.contains_key("verified") {
                m.insert("effect".into(), json!("unverifiable"));
            }
            if let Some(s) = o.structured.as_object() {
                for (k, x) in s {
                    m.entry(k.clone()).or_insert_with(|| x.clone());
                }
            }
            m.insert("route".into(), json!("cua-driver"));
        }
        Ok(v)
    }

    fn act_driver(&mut self, tool: &str, action: &str, args: Value) -> Result<Value, String> {
        self.need(tool, action)?;
        let o = self.d.scall(tool, args);
        self.reply(action, &o)
    }

    fn windows(&mut self, p: &Value) -> Result<Value, String> {
        let o = self.d.scall("list_windows", json!({"on_screen_only": p["includeOffscreen"] != true}));
        self.wins.clear();
        let mut rows = vec![];
        for (i, w) in windows(&o).into_iter().enumerate() {
            let r = format!("w{}", i + 1);
            rows.push(json!({"windowRef": r, "app": w.app, "title": w.title, "pid": w.pid, "windowId": w.wid, "offScreen": w.off_screen}));
            self.wins.insert(r, w);
        }
        Ok(json!({"ok": true, "windows": rows, "count": rows.len()}))
    }

    fn apps(&mut self) -> Result<Value, String> {
        let o = self.d.scall("list_apps", json!({}));
        if o.is_error {
            return self.reply("list_apps", &o);
        }
        let rows = o.structured["apps"].as_array().or(o.data["apps"].as_array()).cloned().unwrap_or_default();
        Ok(json!({"ok": true, "apps": rows, "count": rows.len()}))
    }

    /// `windowRef` → newest observation (elementRefs + element tokens, image when the driver has one).
    fn window_state(&mut self, p: &Value) -> Result<Value, String> {
        let w = self.win(p)?.ok_or("get_window_state requires windowRef from list_windows")?;
        self.check_observation(p)?;
        let mut a = json!({"pid": w.pid, "window_id": w.wid});
        if let Some(n) = p["maxElements"].as_u64() {
            a["max_elements"] = json!(n);
        }
        if let Some(q) = p["query"].as_str().filter(|q| !q.is_empty()) {
            a["query"] = json!(q);
        }
        if let Some(d) = p["depth"].as_u64() {
            a["max_depth"] = json!(d);
        }
        self.need("get_window_state", "get_window_state")?;
        let o = self.d.scall("get_window_state", a);
        if o.is_error {
            return self.reply("get_window_state", &o);
        }
        let elements = match o.structured["elements"].as_array().filter(|a| !a.is_empty()) {
            Some(a) => parse_structured(a),
            None => parse_tree(o.data.as_str().and_then(|t| t.split_once('\n').map(|x| x.1)).unwrap_or("")),
        };
        self.seq += 1;
        let obs = format!("obs-{}", self.seq);
        let wref = p["windowRef"].as_str().unwrap_or("").to_string();
        let mut rows = vec![];
        for e in &elements {
            let r = format!("e{}", e.index);
            if !e.handle.is_empty() {
                self.tokens.insert(r.clone(), (wref.clone(), e.handle.clone()));
            }
            rows.push(json!({"elementRef": r, "index": e.index, "role": e.role, "label": e.label, "bounds": e.bounds}));
        }
        self.obs.insert(wref, obs.clone());
        let mut v = json!({"ok": true, "observation": {
            "kind": "window", "observationId": obs, "windowRef": p["windowRef"],
            "coordinateSpace": "screen-pixels", "elements": rows,
        }});
        if let Some((img, mime)) = o.image() {
            let (iw, ih) = image_size(&img).unwrap_or((0, 0));
            v["observation"]["base64"] = json!(seagent_net::crypto::b64(&img));
            v["observation"]["format"] = json!(if mime == "image/jpeg" { "jpeg" } else { "png" });
            v["observation"]["width"] = json!(iw);
            v["observation"]["height"] = json!(ih);
        }
        Ok(v)
    }

    /// Every element of the target window as one flat tree (no image).
    fn accessibility_tree(&mut self, p: &Value) -> Result<Value, String> {
        let mut v = self.window_state(p)?;
        if let Some(o) = v["observation"].as_object_mut() {
            o.remove("base64");
            o.insert("kind".into(), json!("tree"));
        }
        v["ok"] = json!(true);
        Ok(v)
    }

    /// `computer.act` wire params → the driver's tool + args.
    fn dispatch(&mut self, p: &Value) -> Result<Value, String> {
        let action = p["action"].as_str().unwrap_or("");
        match action {
            "list_windows" => return self.windows(p),
            "list_apps" => return self.apps(),
            "get_window_state" => return self.window_state(p),
            "get_accessibility_tree" => return self.accessibility_tree(p),
            "get_cursor_position" => return self.act_driver("get_cursor_position", action, json!({})),
            _ => {}
        }
        self.check_observation(p)?;
        let mut args = json!({});
        let (tool, need_window) = match action {
            "left_click" => ("click", false),
            "right_click" => ("click", false),
            "middle_click" => ("click", false),
            "double_click" => ("double_click", false),
            "triple_click" => ("click", false),
            "mouse_move" => ("move_mouse", false),
            "left_click_drag" => ("drag", false),
            "left_mouse_down" => ("mouse_down", false),
            "left_mouse_up" => ("mouse_up", false),
            "scroll" => ("scroll", false),
            "type" => ("type_text", true),
            "key" => ("press_key", true),
            "hold_key" => ("hold_key", true),
            "set_value" => ("set_value", true),
            "launch_app" => ("launch_app", false),
            "kill_app" => ("kill_app", false),
            "bring_to_front" => ("bring_to_front", true),
            "zoom" => ("zoom", false),
            "invoke_menu" => ("invoke_menu", true),
            "escalate_scope" => ("escalate_scope", false),
            "get_recording_state" => ("get_recording_state", false),
            "start_recording" => ("start_recording", false),
            "stop_recording" => ("stop_recording", false),
            "replay_trajectory" => ("replay_trajectory", false),
            a => return Err(format!("COMPUTER_UNSUPPORTED_ACTION: `{a}` has no cua-driver mapping on this gateway")),
        };
        self.target(p, &mut args, need_window)?;
        match action {
            "left_click" | "right_click" | "middle_click" | "triple_click" | "mouse_move" | "left_mouse_down" | "left_mouse_up" => {
                let button = match action {
                    "right_click" => "right",
                    "middle_click" => "middle",
                    _ => "left",
                };
                if tool == "click" {
                    args["button"] = json!(button);
                }
                for k in ["x", "y"] {
                    if !p[k].is_null() {
                        args[k] = p[k].clone();
                    }
                }
                if action == "triple_click" {
                    args["click_count"] = json!(3);
                }
                if let Some(m) = p["modifiers"].as_str().filter(|m| !m.is_empty()) {
                    args["modifier"] = json!(m);
                }
            }
            "double_click" => {
                for k in ["x", "y"] {
                    if !p[k].is_null() {
                        args[k] = p[k].clone();
                    }
                }
            }
            "left_click_drag" => {
                args["from_x"] = p["fromX"].clone();
                args["from_y"] = p["fromY"].clone();
                args["to_x"] = p["x"].clone();
                args["to_y"] = p["y"].clone();
            }
            "scroll" => {
                args["direction"] = p["scrollDirection"].clone();
                if !p["scrollAmount"].is_null() {
                    args["amount"] = p["scrollAmount"].clone();
                }
                for k in ["x", "y"] {
                    if !p[k].is_null() && self.d.supports_cap("input.scroll.coordinates", Some("scroll")) {
                        args[k] = p[k].clone();
                    }
                }
            }
            "type" => {
                args["text"] = p["text"].clone();
                if p["deliveryMode"] == "foreground" && self.d.supports_prop("type_text", "delivery_mode") {
                    args["delivery_mode"] = json!("foreground");
                }
            }
            "key" => {
                let (key, mods) = parse_key_combo(p["keys"].as_str().unwrap_or(""));
                match (key, mods.is_empty()) {
                    (Some(k), true) => args["key"] = json!(k),
                    (Some(k), false) => {
                        let mut all = mods;
                        all.push(k);
                        args = json!({"keys": all});
                        self.target(p, &mut args, need_window)?;
                    }
                    (None, _) => return Err(format!("could not parse the key chord `{}`", p["keys"].as_str().unwrap_or(""))),
                }
            }
            "hold_key" => {
                args["key"] = p["text"].clone();
                if !p["durationMs"].is_null() {
                    args["durationMs"] = p["durationMs"].clone();
                }
            }
            "set_value" => {
                if let Some(i) = p["elementRef"].as_str().and_then(|e| e.strip_prefix('e')).and_then(|i| i.parse::<u64>().ok()) {
                    args["element_index"] = json!(i);
                }
                args["value"] = p["value"].clone();
            }
            "launch_app" => args["app"] = p["app"].clone(),
            "kill_app" => {
                if let Some(a) = p["app"].as_str() {
                    args["app"] = json!(a);
                }
                if let Some(t) = self.win(p)? {
                    args["pid"] = json!(t.pid);
                }
            }
            "bring_to_front" => {}
            "zoom" => {
                for k in ["x1", "y1", "x2", "y2"] {
                    args[k] = p[k].clone();
                }
            }
            "invoke_menu" => {
                args["path"] = p["path"].clone();
                if p["deliveryMode"] == "foreground" {
                    args["delivery_mode"] = json!("foreground");
                }
            }
            "escalate_scope" => {
                if let Some(r) = p["reason"].as_str() {
                    args["reason"] = json!(r);
                }
            }
            "start_recording" => {
                if let Some(v) = p["recordVideo"].as_bool() {
                    args["recordVideo"] = json!(v);
                }
            }
            "replay_trajectory" => {
                for k in ["delayMs", "stopOnError"] {
                    if !p[k].is_null() {
                        args[k] = p[k].clone();
                    }
                }
            }
            _ => {}
        }
        if action == "zoom" {
            self.need("zoom", action)?;
            let o = self.d.scall("zoom", args);
            if o.is_error {
                return self.reply("zoom", &o);
            }
            let (img, mime) = o.image().ok_or_else(|| "cua-driver zoom returned no image".to_string())?;
            let (w, h) = image_size(&img).unwrap_or((0, 0));
            return Ok(json!({"ok": true, "observation": {"kind": "region", "base64": seagent_net::crypto::b64(&img), "format": if mime == "image/jpeg" { "jpeg" } else { "png" }, "width": w, "height": h}, "details": {"region": [p["x1"], p["y1"], p["x2"], p["y2"]], "coordinateSpace": "screen-pixels"}}));
        }
        self.act_driver(tool, action, args)
    }
}

impl super::openclaw::Desk for CuaDesk {
    fn name(&self) -> &'static str {
        "cua"
    }

    fn screenshot(&mut self) -> Result<super::openclaw::Shot, String> {
        self.need("get_desktop_state", "screenshot")?;
        let o = self.d.scall("get_desktop_state", json!({}));
        if o.is_error {
            return Err(format!("COMPUTER_DRIVER_ERROR: cua-driver desktop capture failed: {}", o.text()));
        }
        let (bytes, mime) = o.image().ok_or("cua-driver get_desktop_state returned no image (is a display reachable?)")?;
        let (w, h) = image_size(&bytes).unwrap_or((0, 0));
        Ok(super::openclaw::Shot { bytes, mime, width: w, height: h, native_w: w, native_h: h })
    }

    fn act(&mut self, p: &Value) -> Result<Value, String> {
        self.dispatch(p)
    }
}

impl Backend for CuaBackend {
    fn name(&self) -> &'static str {
        "cua"
    }

    fn capture(&mut self, mode: &str, app: Option<&str>, pid: Option<i64>, window_id: Option<i64>) -> Result<Capture, String> {
        // Schema-filler ids (models zero-fill optional integers) are not a targeting request.
        let (pid, window_id) = (pid.filter(|p| *p > 0), window_id.filter(|w| *w > 0));
        let exact = pid.is_some() || window_id.is_some();
        if !exact && app.is_some_and(|a| FULL_SCREEN.contains(&a.trim().to_lowercase().as_str())) {
            return Ok(self.full_screen(mode));
        }
        let candidates = if exact {
            let (Some(p), Some(w)) = (pid, window_id) else { return Ok(self.failed(mode, "<capture targeting requires both pid and window_id>")) };
            vec![Win { app: app.unwrap_or("").into(), pid: p, wid: w, off_screen: false, title: String::new(), z: 0.0 }]
        } else {
            let ws = self.list_windows_raw();
            if ws.is_empty() {
                let why = if std::env::var_os("DISPLAY").is_none() { "no DISPLAY is set — X11/XWayland is not reachable from this process" } else { "window discovery returned no windows; run `seagent computer-use doctor` (display reachability, AX capability)" };
                return Ok(self.failed(mode, why));
            }
            match app.map(str::trim).filter(|a| !a.is_empty()) {
                None => ws,
                Some(a) if a.eq_ignore_ascii_case("desktop") => {
                    let mut d: Vec<Win> = ws.into_iter().filter(|w| desktop_window(w, DESKTOP_NAMES)).collect();
                    d.sort_by_key(|w| !desktop_window(w, DESKTOP_BACKDROP));
                    if d.is_empty() {
                        return Ok(self.failed(mode, &format!("<no desktop/shell window found for app='{a}'; cua-driver captures one window at a time and exposes no whole-virtual-desktop or per-monitor capture. Call list_apps / capture(app='<AppName>') to target a specific window instead.>")));
                    }
                    d
                }
                Some(a) => {
                    let m = self.match_app(&ws, a);
                    if m.is_empty() {
                        return Ok(self.failed(mode, &format!("<no on-screen window matched app='{a}'; call list_apps to see available app names (some Linux/Qt apps only resolve via list_apps metadata)>")));
                    }
                    m
                }
            }
        };
        let active = if !exact && app.is_none() && std::env::var_os("DISPLAY").is_some() { x11_active_window() } else { None };
        let Some(target) = select_target(&candidates, app.is_some(), exact, active) else { return Ok(self.failed(mode, "<no window>")) };
        self.set_target(&target);
        if app.is_some() || self.last_app.is_none() {
            self.last_app = Some(if target.app.is_empty() { app.unwrap_or("").to_string() } else { target.app.clone() });
        }
        let (mut img, mut elements, mut title) = (None, vec![], String::new());
        let tree_title = |o: &Out| -> String {
            let t = o.data.as_str().unwrap_or("");
            let tree = t.split_once('\n').map(|x| x.1).unwrap_or("");
            tree.find("AXWindow \"").and_then(|i| tree[i + 10..].split('"').next().map(str::to_string)).unwrap_or_default()
        };
        if mode == "vision" {
            if self.d.has_tool("screenshot") || !self.d.discovered() {
                let o = self.d.scall("screenshot", json!({"window_id": self.wid, "format": "jpeg", "quality": 85}));
                img = o.image().filter(|_| !o.is_error);
            }
            if img.is_none() {
                let o = self.d.scall("get_window_state", self.gws_args());
                if o.is_error {
                    self.clear();
                    return Err(format!("cua-driver get_window_state failed: {}", o.text()));
                }
                img = o.image();
                title = tree_title(&o);
            }
        } else {
            let o = self.d.scall("get_window_state", self.gws_args());
            if o.is_error {
                self.clear();
                return Err(format!("cua-driver get_window_state failed: {}", o.text()));
            }
            title = tree_title(&o);
            elements = match o.structured["elements"].as_array().filter(|a| !a.is_empty()) {
                Some(a) => parse_structured(a),
                None => parse_tree(o.data.as_str().and_then(|t| t.split_once('\n').map(|x| x.1)).unwrap_or("")),
            };
            self.tokens = elements.iter().filter(|e| !e.handle.is_empty()).map(|e| (e.index, e.handle.clone())).collect();
            img = o.image();
        }
        let (width, height) = img.as_ref().and_then(|(b, _)| image_size(b)).unwrap_or((0, 0));
        let (image, mime) = match img {
            Some((b, m)) => (Some(b), m),
            None => (None, String::new()),
        };
        for e in &mut elements {
            e.app = target.app.clone();
        }
        Ok(Capture { mode: mode.into(), width, height, image, mime, elements, app: target.app, window_title: title, note: String::new(), ax_max_elements: if mode == "vision" { 0 } else { self.ax_max as usize } })
    }

    fn click(&mut self, at: Point, button: &str, count: u32, modifiers: &[String], d: &Delivery) -> ActionResult {
        let mut args = match self.target_args("click", false) {
            Ok(a) => a,
            Err(r) => return *r,
        };
        let b = button.to_lowercase();
        if !matches!(b.as_str(), "left" | "right" | "middle") {
            return ActionResult::refuse("click", format!("unknown button '{button}' — expected left, right, middle."));
        }
        let tool = if count == 2 { "double_click" } else { "click" };
        args["button"] = json!(b);
        if let Err(r) = self.pointer(tool, &mut args, at, Some("click requires element= or x/y.")) {
            return *r;
        }
        if !modifiers.is_empty() {
            args["modifier"] = json!(modifiers);
        }
        self.run_input(tool, args, d)
    }

    fn drag(&mut self, from: Point, to: Point, _button: &str, _modifiers: &[String], d: &Delivery) -> ActionResult {
        let mut args = match self.target_args("drag", false) {
            Ok(a) => a,
            Err(r) => return *r,
        };
        let extra = match (from, to) {
            (Point::Element(a), Point::Element(b)) => json!({"from_element": a, "to_element": b}),
            (Point::Xy(fx, fy), Point::Xy(tx, ty)) => json!({"from_x": fx, "from_y": fy, "to_x": tx, "to_y": ty}),
            _ => return ActionResult::refuse("drag", "drag requires from_element/to_element or from_coordinate/to_coordinate."),
        };
        let Some(w) = self.wid else { return ActionResult::refuse("drag", "No active window_id for coordinate drag.") };
        merge(&mut args, extra);
        args["window_id"] = json!(w);
        self.run_input("drag", args, d)
    }

    fn scroll(&mut self, direction: &str, amount: u32, at: Point, _modifiers: &[String], d: &Delivery) -> ActionResult {
        let mut args = match self.target_args("scroll", false) {
            Ok(a) => a,
            Err(r) => return *r,
        };
        args["direction"] = json!(direction);
        args["amount"] = json!(amount.clamp(1, 50));
        let at = match at {
            Point::Element(_) if self.wid.is_none() => Point::None,
            // Some driver schemas reject x/y on scroll: only send them when advertised.
            Point::Xy(..) if !self.d.supports_cap("input.scroll.coordinates", Some("scroll")) => {
                if let Some(w) = self.wid {
                    args["window_id"] = json!(w);
                }
                Point::None
            }
            p => p,
        };
        if let Err(r) = self.pointer("scroll", &mut args, at, None) {
            return *r;
        }
        self.run_input("scroll", args, d)
    }

    fn type_text(&mut self, text: &str, d: &Delivery) -> ActionResult {
        match self.target_args("type_text", true) {
            Ok(mut a) => {
                a["text"] = json!(text);
                self.run_input("type_text", a, d)
            }
            Err(r) => *r,
        }
    }

    fn key(&mut self, keys: &str, d: &Delivery) -> ActionResult {
        let mut a = match self.target_args("key", true) {
            Ok(a) => a,
            Err(r) => return *r,
        };
        let (key, mods) = parse_key_combo(keys);
        let Some(key) = key else { return ActionResult::refuse("key", format!("Could not parse key from '{keys}'.")) };
        if mods.is_empty() {
            a["key"] = json!(key);
            self.run_input("press_key", a, d)
        } else {
            let mut all = mods;
            all.push(key);
            a["keys"] = json!(all);
            self.run_input("hotkey", a, d)
        }
    }

    fn set_value(&mut self, value: &str, element: Option<u32>) -> ActionResult {
        let mut a = match self.target_args("set_value", true) {
            Ok(a) => a,
            Err(r) => return *r,
        };
        let Some(e) = element else { return ActionResult::refuse("set_value", "set_value requires element= (element index).") };
        a["element_index"] = json!(e);
        a["value"] = json!(value);
        self.act("set_value", a, true)
    }

    fn list_apps(&mut self) -> Result<Vec<Value>, String> {
        let o = self.d.scall("list_apps", json!({}));
        let cands = [o.structured["apps"].clone(), o.data.clone(), o.data["apps"].clone()];
        if let Some(a) = cands.iter().find_map(|c| c.as_array().filter(|a| !a.is_empty())) {
            return Ok(a.clone());
        }
        let mut seen = HashSet::new();
        let from_windows: Vec<Value> = windows(&o).into_iter().filter(|w| !w.app.is_empty() && seen.insert((w.app.clone(), w.pid))).map(|w| json!({"name": w.app, "pid": w.pid})).collect();
        if !from_windows.is_empty() {
            return Ok(from_windows);
        }
        if o.is_error {
            return Err(o.text());
        }
        // Old text-only drivers: "Name (pid 123)".
        Ok(o.data.as_str().unwrap_or("").lines().filter_map(|l| {
            let i = l.rfind("(pid ")?;
            let pid: i64 = l[i + 5..].trim_end_matches(')').trim().parse().ok()?;
            Some(json!({"name": l[..i].trim(), "pid": pid}))
        }).collect())
    }

    fn list_windows(&mut self) -> Result<Vec<Value>, String> {
        Ok(self.list_windows_raw().into_iter().map(|w| json!({"app_name": w.app, "pid": w.pid, "window_id": w.wid, "off_screen": w.off_screen, "title": w.title, "z_index": w.z})).collect())
    }

    fn focus_app(&mut self, app: &str, raise: bool) -> ActionResult {
        let ws = self.list_windows_raw();
        let m = self.match_app(&ws, app);
        let Some(t) = m.first().cloned() else {
            self.clear();
            return ActionResult::refuse("focus_app", format!("No on-screen window found for app '{app}'."));
        };
        self.set_target(&t);
        self.last_app = Some(if t.app.is_empty() { app.into() } else { t.app.clone() });
        if !raise {
            return ActionResult::ok("focus_app", format!("Targeted {} (pid {}, window {}) without raising window.", t.app, t.pid, t.wid));
        }
        if !self.d.has_tool("bring_to_front") {
            return ActionResult::refuse("focus_app", BTF_UNSUPPORTED).code("bring_to_front_unsupported");
        }
        let mut f = self.act("bring_to_front", json!({"pid": t.pid, "window_id": t.wid}), false);
        if f.ok {
            f.action = "focus_app".into();
            f.meta.insert("target_selected".into(), json!(true));
        }
        f
    }

    fn last_app(&self) -> Option<String> {
        self.last_app.clone()
    }
    fn last_target(&self) -> Option<(i64, i64)> {
        self.target
    }
    fn stop(&mut self) {
        self.d.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_tree_labels_in_all_four_forms() {
        let t = "[1] AXButton \"OK\"\n  - [2] AXTextField = \"hello\"\n[3] AXCheckBox (Remember me)\n[4] AXLink (7) id=Docs\n[5] AXGroup";
        let e = parse_tree(t);
        let labels: Vec<(u32, &str, &str)> = e.iter().map(|e| (e.index, e.role.as_str(), e.label.as_str())).collect();
        assert_eq!(labels, [(1, "AXButton", "OK"), (2, "AXTextField", "hello"), (3, "AXCheckBox", "Remember me"), (4, "AXLink", "Docs"), (5, "AXGroup", "")]);
    }

    #[test]
    fn window_rows_are_normalised_and_frontmost_first() {
        let o = Out { structured: json!({"windows": [
            {"app_name": "panel", "pid": null, "window_id": 5},
            {"app_name": "Back", "pid": 10, "window_id": 11, "z_index": 1},
            {"app_name": "Front", "pid": "20", "window_id": 21, "z_index": 3, "is_on_screen": true},
            {"app_name": "Hidden", "pid": 30, "window_id": 31, "z_index": 9, "is_on_screen": false}
        ]}), ..Default::default() };
        let w = windows(&o);
        assert_eq!(w.iter().map(|w| w.app.as_str()).collect::<Vec<_>>(), ["Hidden", "Front", "Back"]);
        assert_eq!(select_target(&w, false, false, None).unwrap().app, "Front", "off-screen windows are skipped");
        let flat = vec![Win { app: "GNOME Shell".into(), pid: 1, wid: 2, off_screen: false, title: "GNOME Shell".into(), z: 0.0 }, Win { app: "gedit".into(), pid: 3, wid: 4, off_screen: false, title: "notes".into(), z: 0.0 }, Win { app: "xterm".into(), pid: 5, wid: 6, off_screen: false, title: "sh".into(), z: 0.0 }];
        assert_eq!(select_target(&flat, false, false, Some(6)).unwrap().app, "xterm", "X11 _NET_ACTIVE_WINDOW wins on uninformative z");
        assert_eq!(select_target(&flat, false, false, None).unwrap().app, "gedit", "shell helper windows are skipped");
    }

    #[test]
    fn key_combos_and_verdicts_parse_like_hermes() {
        assert_eq!(parse_key_combo("cmd+s"), (Some("s".into()), vec!["cmd".to_string()]));
        assert_eq!(parse_key_combo("Control-Alt-t"), (Some("t".into()), vec!["ctrl".to_string(), "option".to_string()]));
        assert_eq!(parse_key_combo("return"), (Some("return".into()), vec![]));
        let o = Out { data: json!({"message": "clicked"}), structured: json!({"effect": "suspected_noop", "escalation": {"recommended": "px"}, "reason_code": "ax_miss"}), is_error: false, images: vec![] };
        let r = action_result("click", &o, Some("background"));
        assert_eq!((r.message.as_str(), r.effect.as_deref(), r.code.as_deref(), r.delivery_mode.as_deref()), ("clicked", Some("suspected_noop"), Some("ax_miss"), Some("background")));
        assert_eq!(r.verdict()["recommended"], "px");
        let f = flatten(&json!({"content": [{"type": "text", "text": "{\"a\": 1}"}, {"type": "image", "data": "aGk=", "mimeType": "image/png"}], "isError": false}));
        assert_eq!((f.data["a"].as_i64(), f.images.len()), (Some(1), 1));
    }
}
