//! Native driver: on Linux xdotool (X11) / ydotool (Wayland) input, `import`/`grim` captures and
//! AT-SPI accessibility; on Windows `SendInput` + GDI captures, on macOS CGEvent / cliclick +
//! `screencapture` (`node::host_os`, no accessibility tree yet) — the same code the paired-node
//! `computer.act` runs (`node.rs`, `node/a11y.rs`), here on the gateway itself. Every command runs under the env the caller
//! applies with `node::with_env` (the Bot Desktop's DISPLAY / XAUTHORITY / session bus).
//!
//! Input is global XTest/uinput injection: there is no background (focus-preserving)
//! delivery, so results report `effect: "unverifiable"` and the model re-captures to verify.

use super::backend::{image_size, mime_of, ActionResult, Backend, Capture, Delivery, Element, Point};
use crate::node::{self, a11y, Input};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

/// `k` as commands spawned under `env` see it (`""` in env = removed).
pub fn env_get(env: &[(String, String)], k: &str) -> Option<String> {
    match env.iter().rev().find(|(n, _)| n == k) {
        Some((_, v)) if v.is_empty() => None,
        Some((_, v)) => Some(v.clone()),
        None => std::env::var(k).ok().filter(|v| !v.is_empty()),
    }
}

pub fn which_in(env: &[(String, String)], bin: &str) -> Option<PathBuf> {
    env_get(env, "PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(bin)).find(|f| f.is_file()))
}

/// Windows / macOS drive input natively (`node::host_os`: SendInput / CGEvent), never
/// through xdotool or ydotool.
#[cfg(any(windows, target_os = "macos"))]
pub fn input_tool(_backend: &str, _env: &[(String, String)]) -> Option<Input> {
    None
}

/// Is OS-native input available (Windows / macOS) when [`input_tool`] finds no tool?
pub fn os_input() -> bool {
    cfg!(any(windows, target_os = "macos"))
}

/// One `computer.act` step through the OS-native input ([`os_input`]).
pub fn run_os(p: &Value, t: Duration) -> Result<String, String> {
    #[cfg(any(windows, target_os = "macos"))]
    {
        node::host_os::act(p, t)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = (p, t);
        Err(NO_INPUT.into())
    }
}

/// The input tool for `backend` (auto/native: ydotool on Wayland, xdotool with a DISPLAY).
#[cfg(not(any(windows, target_os = "macos")))]
pub fn input_tool(backend: &str, env: &[(String, String)]) -> Option<Input> {
    let (x, y) = (which_in(env, "xdotool").is_some(), which_in(env, "ydotool").is_some());
    match backend {
        "xdotool" => x.then_some(Input::Xdotool),
        "ydotool" => y.then_some(Input::Ydotool),
        _ => {
            let wayland = env_get(env, "WAYLAND_DISPLAY").is_some() && env_get(env, "DISPLAY").is_none();
            match (wayland, x, y) {
                (true, _, true) => Some(Input::Ydotool),
                (false, true, _) if env_get(env, "DISPLAY").is_some() => Some(Input::Xdotool),
                (_, _, true) => Some(Input::Ydotool),
                _ => None,
            }
        }
    }
}

#[cfg(not(target_os = "ios"))]
pub const NO_INPUT: &str = "no input tool: install xdotool (X11) or ydotool (Wayland, needs ydotoold), or install cua-driver (`seagent computer-use install`)";
#[cfg(target_os = "ios")]
pub const NO_INPUT: &str = "desktop input is not available on iOS (no input injection from an app); use a paired computer node";

/// Run the commands of one `computer.act` step (node.rs `computer_argv`).
pub fn run_steps(b: Input, p: &Value, t: Duration) -> Result<String, String> {
    let mut out = String::new();
    for argv in node::computer_argv(b, p)? {
        let a: Vec<&str> = argv.iter().map(String::as_str).collect();
        out.push_str(&node::run_cmd(&a, t)?);
    }
    Ok(out)
}

/// A region of the desktop (Windows / macOS: the screenshot, cropped in memory).
#[cfg(any(windows, target_os = "macos"))]
pub fn crop(_env: &[(String, String)], x: i64, y: i64, w: i64, h: i64, t: Duration) -> Result<Vec<u8>, String> {
    node::host_os::crop(x, y, w, h, t)
}

/// A region of the desktop (`import -crop` / `grim -g`), for OpenClaw `zoom`.
#[cfg(not(any(windows, target_os = "macos")))]
pub fn crop(env: &[(String, String)], x: i64, y: i64, w: i64, h: i64, t: Duration) -> Result<Vec<u8>, String> {
    if w <= 0 || h <= 0 {
        return Err("zoom region must have x2 > x1 and y2 > y1".into());
    }
    let tmp = node::tmp_file("zoom", "png");
    let path = tmp.display().to_string();
    let x11 = env_get(env, "DISPLAY").is_some();
    if which_in(env, "grim").is_some() && (!x11 || which_in(env, "import").is_none()) {
        node::run_cmd(&["grim", "-g", &format!("{x},{y} {w}x{h}"), &path], t)?;
    } else {
        node::run_cmd(&["import", "-window", "root", "-crop", &format!("{w}x{h}+{x}+{y}"), &path], t)?;
    }
    let b = std::fs::read(&tmp).map_err(|e| format!("zoom capture: {e}"));
    let _ = std::fs::remove_file(&tmp);
    b
}

/// Roles that are layout, not targets (dropped from the SOM list).
const LAYOUT_ROLES: &[&str] = &["filler", "panel", "frame", "window", "application", "section", "label", "static", "scroll pane", "viewport", "layered pane", "root pane", "separator", "unknown", "desktop frame", "redundant object", "grouping", "invalid", "tool bar", "status bar", "html container"];

/// AT-SPI elements → SOM elements (1-based, layout roles dropped).
pub fn som(raw: &[Value], app: &str) -> Vec<Element> {
    raw.iter()
        .filter(|e| !LAYOUT_ROLES.contains(&e["role"].as_str().unwrap_or("")))
        .enumerate()
        .map(|(i, e)| {
            let b = &e["bounds"];
            let n = |k: &str| b[k].as_i64().unwrap_or(0);
            Element {
                index: i as u32 + 1,
                role: e["role"].as_str().unwrap_or("").to_string(),
                label: e["label"].as_str().or(e["value"].as_str()).unwrap_or("").to_string(),
                bounds: if b.is_object() { [n("x"), n("y"), n("width"), n("height")] } else { [0; 4] },
                app: app.to_string(),
                handle: e["elementRef"].as_str().unwrap_or("").to_string(),
            }
        })
        .collect()
}

pub struct NativeBackend {
    input: Option<Input>,
    t: Duration,
    ax_max: u32,
    elements: Vec<Element>,
    /// Sticky target: (app, AT-SPI window ref).
    target: Option<(String, String)>,
}

impl NativeBackend {
    pub fn new(backend: &str, env: &[(String, String)], ax_max: u32, t: Duration) -> NativeBackend {
        NativeBackend { input: input_tool(backend, env), t, ax_max, elements: vec![], target: None }
    }

    fn element(&self, i: u32) -> Option<&Element> {
        self.elements.iter().find(|e| e.index == i)
    }

    fn xy(&self, at: Point, action: &str) -> Result<Option<(i64, i64)>, Box<ActionResult>> {
        match at {
            Point::Xy(x, y) => Ok(Some((x, y))),
            Point::None => Ok(None),
            Point::Element(i) => match self.element(i) {
                None => Err(Box::new(ActionResult::refuse(action, format!("element {i} is not in the last capture; re-capture with mode='som' first.")).code("stale_element"))),
                Some(e) => Ok(e.center()),
            },
        }
    }

    fn raise(&self, d: &Delivery, action: &str) -> Result<(), Box<ActionResult>> {
        if !d.bring_to_front {
            return Ok(());
        }
        if d.mode.as_deref() != Some("foreground") {
            return Err(Box::new(ActionResult::refuse(action, "bring_to_front requires delivery_mode='foreground'.").code("bring_to_front_requires_foreground")));
        }
        let Some((_, w)) = &self.target else { return Err(Box::new(ActionResult::refuse(action, "Capture an exact target before requesting persistent foreground focus.").code("bring_to_front_target_required"))) };
        a11y::act(&json!({"action": "bring_to_front", "windowRef": w})).map(|_| ()).map_err(|e| Box::new(ActionResult::refuse(action, e)))
    }

    /// Run one wire step; the verdict is `unverifiable` (global injection, no read-back).
    fn step(&self, action: &str, p: Value, d: &Delivery) -> ActionResult {
        if let Some(m) = d.mode.as_deref().filter(|m| !matches!(*m, "background" | "foreground")) {
            return ActionResult::refuse(action, format!("unknown delivery_mode '{m}' — use background|foreground.")).code("bad_delivery_mode");
        }
        if let Err(r) = self.raise(d, action) {
            return *r;
        }
        let (ran, path) = match self.input {
            Some(b) => (run_steps(b, &p, self.t), format!("{}_global", format!("{b:?}").to_lowercase())),
            None if os_input() => (run_os(&p, self.t), "os_global".to_string()),
            None => return ActionResult::refuse(action, NO_INPUT).code("background_unavailable"),
        };
        match ran {
            Ok(_) => {
                let mut r = ActionResult::ok(action, "");
                r.effect = Some("unverifiable".into());
                r.path = Some(path);
                r.delivery_mode = d.mode.clone();
                r.meta.insert("note".into(), json!("native input is injected globally (XTest/uinput); there is no background routing"));
                r
            }
            Err(e) => ActionResult::refuse(action, e),
        }
    }

    fn windows(&self) -> Result<Vec<Value>, String> {
        Ok(a11y::act(&json!({"action": "list_windows"}))?["windows"].as_array().cloned().unwrap_or_default())
    }

    fn find_window(&self, app: &str) -> Result<Option<(String, String)>, String> {
        let want = app.trim().to_lowercase();
        let ws = self.windows()?;
        let name = |w: &Value| w["app"].as_str().unwrap_or("").to_lowercase();
        let hit = ws.iter().find(|w| name(w) == want).or_else(|| ws.iter().find(|w| name(w).contains(&want))).or_else(|| ws.iter().find(|w| w["title"].as_str().unwrap_or("").to_lowercase().contains(&want)));
        Ok(hit.map(|w| (w["app"].as_str().unwrap_or(app).to_string(), w["windowRef"].as_str().unwrap_or("").to_string())))
    }
}

impl Backend for NativeBackend {
    fn name(&self) -> &'static str {
        "native"
    }

    fn capture(&mut self, mode: &str, app: Option<&str>, _pid: Option<i64>, _window_id: Option<i64>) -> Result<Capture, String> {
        let app = app.map(str::trim).filter(|a| !a.is_empty());
        let full = app.is_some_and(|a| ["screen", "fullscreen", "full screen", "all"].contains(&a.to_lowercase().as_str()));
        let mut cap = Capture { mode: mode.into(), ..Default::default() };
        if let Some(a) = app.filter(|_| !full) {
            match self.find_window(a) {
                Ok(Some(t)) => self.target = Some(t),
                Ok(None) => {
                    self.target = None;
                    self.elements.clear();
                    cap.window_title = format!("<no on-screen window matched app='{a}'; call list_apps to see available app names>");
                    return Ok(cap);
                }
                Err(e) => cap.note = format!("accessibility is unavailable ({e}); app= cannot be resolved, capturing the whole screen"),
            }
        }
        if mode != "ax" {
            let png = node::snapshot(self.t)?;
            let (w, h) = image_size(&png).unwrap_or((0, 0));
            cap.mime = mime_of(&png).into();
            (cap.width, cap.height) = (w, h);
            cap.image = Some(png);
        }
        if full {
            cap.mode = "vision".into();
            cap.app = "screen".into();
            cap.window_title = "Full screen (composited)".into();
            cap.note = super::cua::FULL_SCREEN_NOTE.into();
            return Ok(cap);
        }
        if let Some((a, _)) = &self.target {
            cap.app = a.clone();
        }
        if mode != "vision" {
            let root = self.target.as_ref().map(|t| json!(t.1)).unwrap_or(Value::Null);
            let limit = if self.ax_max == 0 { 2000 } else { self.ax_max };
            match a11y::act(&json!({"action": "get_accessibility_tree", "windowRef": root, "maxElements": limit, "depth": 25})) {
                Ok(v) => {
                    self.elements = som(v["observation"]["elements"].as_array().map(Vec::as_slice).unwrap_or(&[]), &cap.app);
                    cap.elements = self.elements.clone();
                    cap.ax_max_elements = limit as usize;
                }
                Err(e) => {
                    self.elements.clear();
                    cap.note = format!("accessibility tree unavailable ({e}); act by coordinate on the screenshot");
                }
            }
        }
        if let Some(t) = &self.target {
            cap.window_title = self.windows().ok().and_then(|ws| ws.into_iter().find(|w| w["windowRef"] == t.1.as_str())).and_then(|w| w["title"].as_str().map(str::to_string)).unwrap_or_default();
        }
        Ok(cap)
    }

    fn click(&mut self, at: Point, button: &str, count: u32, modifiers: &[String], d: &Delivery) -> ActionResult {
        let action = match (button, count) {
            ("right", _) => "right_click",
            ("middle", _) => "middle_click",
            ("left", 2) => "double_click",
            ("left", 3) => "triple_click",
            ("left", _) => "left_click",
            _ => return ActionResult::refuse("click", format!("unknown button '{button}' — expected left, right, middle.")),
        };
        let xy = match self.xy(at, "click") {
            Ok(v) => v,
            Err(r) => return *r,
        };
        match (xy, at) {
            (Some((x, y)), _) => self.step("click", json!({"action": action, "x": x, "y": y, "modifiers": modifiers.join("+")}), d),
            // Geometry unknown: the element's own AT-SPI action (left single click only).
            (None, Point::Element(i)) if action == "left_click" && modifiers.is_empty() => {
                let h = self.element(i).map(|e| e.handle.clone()).unwrap_or_default();
                match a11y::act(&json!({"action": "left_click", "elementRef": h})) {
                    Ok(v) => {
                        let mut r = ActionResult::ok("click", format!("activated element #{i} through AT-SPI"));
                        r.verified = v["ok"].as_bool();
                        r.path = Some("ax".into());
                        r
                    }
                    Err(e) => ActionResult::refuse("click", e).code("ax_action_failed"),
                }
            }
            (None, Point::Element(i)) => ActionResult::refuse("click", format!("element #{i} has no known bounds; only a plain left click can go through its accessibility action")).code("bounds_unknown"),
            (None, _) => ActionResult::refuse("click", "click requires element= or x/y."),
        }
    }

    fn drag(&mut self, from: Point, to: Point, _button: &str, _modifiers: &[String], d: &Delivery) -> ActionResult {
        let (a, b) = match (self.xy(from, "drag"), self.xy(to, "drag")) {
            (Ok(Some(a)), Ok(Some(b))) => (a, b),
            (Err(r), _) | (_, Err(r)) => return *r,
            _ => return ActionResult::refuse("drag", "drag requires from_element/to_element or from_coordinate/to_coordinate."),
        };
        self.step("drag", json!({"action": "left_click_drag", "fromX": a.0, "fromY": a.1, "x": b.0, "y": b.1}), d)
    }

    fn scroll(&mut self, direction: &str, amount: u32, at: Point, _modifiers: &[String], d: &Delivery) -> ActionResult {
        let xy = match self.xy(at, "scroll") {
            Ok(v) => v,
            Err(r) => return *r,
        };
        let mut p = json!({"action": "scroll", "scrollDirection": direction, "scrollAmount": amount.clamp(1, 50)});
        if let Some((x, y)) = xy {
            p["x"] = json!(x);
            p["y"] = json!(y);
        }
        self.step("scroll", p, d)
    }

    fn type_text(&mut self, text: &str, d: &Delivery) -> ActionResult {
        self.step("type", json!({"action": "type", "text": text}), d)
    }

    fn key(&mut self, keys: &str, d: &Delivery) -> ActionResult {
        // xdotool spells chords with '+'; Hermes also accepts '-' (ctrl-alt-t).
        let combo = if keys.contains('+') || keys.len() <= 1 { keys.to_string() } else { keys.replace('-', "+") };
        self.step("key", json!({"action": "key", "keys": combo}), d)
    }

    fn set_value(&mut self, value: &str, element: Option<u32>) -> ActionResult {
        let Some(i) = element else { return ActionResult::refuse("set_value", "set_value requires element= (element index).") };
        let Some(e) = self.element(i) else { return ActionResult::refuse("set_value", format!("element {i} is not in the last capture; re-capture with mode='som' first.")).code("stale_element") };
        match a11y::act(&json!({"action": "set_value", "elementRef": e.handle, "value": value})) {
            Ok(v) => {
                let ok = v["ok"] == true;
                let mut r = if ok { ActionResult::ok("set_value", format!("set element #{i}")) } else { ActionResult::refuse("set_value", format!("element #{i} did not accept the value (not an editable text)")) };
                r.verified = Some(ok);
                r.effect = Some(if ok { "confirmed" } else { "suspected_noop" }.into());
                r.path = Some("ax".into());
                r
            }
            Err(e) => ActionResult::refuse("set_value", e),
        }
    }

    fn list_apps(&mut self) -> Result<Vec<Value>, String> {
        Ok(a11y::act(&json!({"action": "list_apps"}))?["apps"].as_array().cloned().unwrap_or_default().into_iter().map(|a| json!({"name": a["app"], "windowRef": a["windowRef"], "windows": a["windows"]})).collect())
    }

    fn list_windows(&mut self) -> Result<Vec<Value>, String> {
        self.windows()
    }

    fn focus_app(&mut self, app: &str, raise: bool) -> ActionResult {
        match self.find_window(app) {
            Ok(Some((a, w))) => {
                self.target = Some((a.clone(), w.clone()));
                if !raise {
                    return ActionResult::ok("focus_app", format!("Targeted {a} without raising window."));
                }
                match a11y::act(&json!({"action": "bring_to_front", "windowRef": w})) {
                    Ok(v) => {
                        let mut r = ActionResult::ok("focus_app", format!("Raised {a}."));
                        r.verified = v["ok"].as_bool();
                        r
                    }
                    Err(e) => ActionResult::refuse("focus_app", e),
                }
            }
            Ok(None) => ActionResult::refuse("focus_app", format!("No on-screen window found for app '{app}'.")),
            Err(e) => ActionResult::refuse("focus_app", e),
        }
    }

    fn last_app(&self) -> Option<String> {
        self.target.as_ref().map(|t| t.0.clone())
    }
}
