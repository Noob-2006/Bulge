//! The `computer_use` tool (Hermes `tools/computer_use/{tool,schema}.py`, MIT): one tool with
//! an `action` discriminator. Order per call: Bot Desktop lease → hard blocks → backend →
//! dispatch under the session's call lock → lease fence → response shaping. Approval for
//! state-changing actions (and, separately, for foreground focus) is asked by the kernel's
//! gates from [`ComputerUseTool::effects`] before `call` runs.

use super::backend::{ActionResult, Backend, Capture, Delivery, Element, Point};
use super::config::ComputerUseConfig;
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Schema text is the model contract (Hermes `schema.py`, byte-for-byte descriptions).
pub fn schema() -> Value {
    json!({"type": "object", "properties": {
        "action": {"type": "string", "enum": ["capture", "click", "double_click", "right_click", "middle_click", "drag", "scroll", "type", "key", "set_value", "wait", "list_apps", "list_windows", "focus_app"],
            "description": "Which action to perform. `capture` is free (no side effects). All other actions require approval unless auto-approved. Use `set_value` for select/popup elements and sliders — it selects the matching option directly without opening the native menu (no focus steal)."},
        "mode": {"type": "string", "enum": ["som", "vision", "ax"], "description": "Capture mode. `som` (default) is a screenshot with numbered overlays on every interactable element plus the AX tree — best for vision models, lets you click by element index. `vision` is a plain screenshot. `ax` is the accessibility tree only (no image; useful for text-only models)."},
        "app": {"type": "string", "description": "Optional. Limit capture/action to one app (name e.g. 'Safari', or bundle ID). Omitted = frontmost window. app='screen' = composited full-screen grab (image only, no clickable elements); app='desktop' = the OS desktop/shell surface (wallpaper, icons, taskbar) with its elements."},
        "pid": {"type": "integer", "description": "Optional exact process target for action='capture'. Pair with window_id when discovery cannot resolve an X11 app."},
        "window_id": {"type": "integer", "description": "Optional exact native window target for action='capture'. Pair with pid when an external cua-driver list_windows lookup has already identified the window."},
        "element": {"type": "integer", "description": "The 1-based SOM index returned by the last `capture(mode='som')` call. Strongly preferred over raw coordinates."},
        "coordinate": {"type": "array", "items": {"type": "integer"}, "minItems": 2, "maxItems": 2, "description": "Pixel coordinates [x, y] relative to the captured window screenshot (top-left origin). Only use this if no element index is available."},
        "button": {"type": "string", "enum": ["left", "right", "middle"], "description": "Mouse button. Defaults to left."},
        "modifiers": {"type": "array", "items": {"type": "string", "enum": ["cmd", "shift", "option", "alt", "ctrl", "fn", "win", "windows", "super", "meta"]}, "description": "Modifier keys held during the action."},
        "from_element": {"type": "integer", "description": "Source element index (drag)."},
        "to_element": {"type": "integer", "description": "Target element index (drag)."},
        "from_coordinate": {"type": "array", "items": {"type": "integer"}, "minItems": 2, "maxItems": 2, "description": "Source [x,y] (drag; use when no element available)."},
        "to_coordinate": {"type": "array", "items": {"type": "integer"}, "minItems": 2, "maxItems": 2, "description": "Target [x,y] (drag; use when no element available)."},
        "direction": {"type": "string", "enum": ["up", "down", "left", "right"], "description": "Scroll direction."},
        "amount": {"type": "integer", "description": "Scroll wheel ticks. Default 3."},
        "value": {"type": "string", "description": "For action='set_value': the value to set on the element. For AXPopUpButton / select dropdowns, pass the option's display label (e.g. 'Blue'). For sliders and other AXValue-settable elements, pass the numeric or string value."},
        "text": {"type": "string", "description": "Text to type (respects the current layout)."},
        "keys": {"type": "string", "description": "Key combo, e.g. 'cmd+s', 'ctrl+alt+t', 'return', 'escape', 'tab'. Use '+' to combine."},
        "seconds": {"type": "number", "description": "wait: seconds to pause (max 30)."},
        "raise_window": {"type": "boolean", "description": "Only for action='focus_app'. If true, brings the window to front (DISRUPTS the user). Default false — input is routed to the app without raising, matching the background co-work model."},
        "delivery_mode": {"type": "string", "enum": ["background", "foreground"], "description": "For input actions (click, type, key, drag, scroll). `background` (DEFAULT) delivers without raising the window or stealing focus. `foreground` briefly fronts the window then restores focus — a visible change needing its own approval; use it only when a result's verdict tells you to escalate there. Each result's `verdict` carries the next step; follow it rather than guessing."},
        "bring_to_front": {"type": "boolean", "description": "Optional and only valid with delivery_mode='foreground'. Explicitly invokes cua-driver's standalone bring_to_front tool before the input; it is never passed as an input property. This persistent focus change has a separate approval scope. Default false."},
        "capture_after": {"type": "boolean", "description": "If true, take a follow-up capture after the action and include it in the response. Saves a round-trip when you need to verify an action's effect."}
    }, "required": ["action"]})
}

pub const DESCRIPTION: &str = "Drive the desktop via cua-driver — screenshots, mouse, keyboard, scroll, drag — on macOS, Windows, and Linux. Input is background-FIRST, not background-only: the default delivery routes to the target window without stealing the user's cursor or focus (works even on hidden/minimized windows), and when a result's `verdict` says to escalate you climb — pixel coordinates, or delivery_mode='foreground' (briefly fronts the window; separate approval). Each result carries a `verdict` with the next step; follow it — never repeat confirmed input, and re-capture to verify an unverifiable one before retrying. Workflow: action='capture' (mode='som' gives numbered element overlays), then click by `element` index; re-capture after state-changing actions (or pass capture_after=true). Image captures include a shareable `screenshot_path`; deliver it via the platform's MEDIA syntax when the user asks to see it — not for captures used only for control.";

// ───────────────────────── safety (Hermes `_reject_unsafe`) ─────────────────────────

const BLOCKED_COMBOS: &[&[&str]] = &[&["cmd", "shift", "backspace"], &["cmd", "option", "backspace"], &["cmd", "ctrl", "q"], &["cmd", "shift", "q"], &["cmd", "option", "shift", "q"], &["win", "l"], &["ctrl", "option", "delete"], &["ctrl", "option", "del"], &["option", "f4"]];
const BLOCKED_TYPE: &[&str] = &[r"curl\s+[^|]*\|\s*bash", r"curl\s+[^|]*\|\s*sh", r"wget\s+[^|]*\|\s*bash", r"\bsudo\s+rm\s+-[rf]", r"\brm\s+-rf\s+/\s*$", r":\s*\(\)\s*\{\s*:\|:\s*&\s*\}"];

/// Canonical key set: split on '+' AND '-' (cua-driver accepts hyphenated combos), aliases folded.
pub fn canon_combo(keys: &str) -> Vec<String> {
    keys.split(['+', '-'])
        .map(|p| p.trim().to_lowercase())
        .filter(|p| !p.is_empty())
        .map(|p| match p.as_str() {
            "command" | "⌘" => "cmd".into(),
            "control" => "ctrl".into(),
            "alt" | "⌥" => "option".into(),
            "windows" | "super" | "meta" => "win".into(),
            _ => p,
        })
        .collect()
}

/// JSON error for hard-blocked input (runs before any approval prompt), else None.
pub fn reject_unsafe(action: &str, args: &Value) -> Option<Value> {
    if action == "type" {
        let text = args["text"].as_str().unwrap_or("");
        for p in BLOCKED_TYPE {
            if regex::RegexBuilder::new(p).case_insensitive(true).build().is_ok_and(|r| r.is_match(text)) {
                return Some(json!({"error": format!("blocked pattern in type text: '{p}'"), "hint": "Dangerous shell patterns cannot be typed via computer_use."}));
            }
        }
    }
    if action == "key" {
        let have = canon_combo(args["keys"].as_str().unwrap_or(""));
        if let Some(b) = BLOCKED_COMBOS.iter().find(|b| b.iter().all(|k| have.iter().any(|h| h == k))) {
            let mut s: Vec<&str> = b.to_vec();
            s.sort();
            return Some(json!({"error": format!("blocked key combo: {s:?}"), "hint": "Destructive system shortcuts are hard-blocked."}));
        }
    }
    if args["bring_to_front"] == true && args["delivery_mode"] != "foreground" {
        return Some(json!({"error": "bring_to_front requires delivery_mode='foreground'", "code": "bring_to_front_requires_foreground"}));
    }
    None
}

const INPUT: &[&str] = &["click", "double_click", "right_click", "middle_click", "drag", "scroll", "type", "key", "set_value"];
const ACTIONS: &[&str] = &["capture", "click", "double_click", "right_click", "middle_click", "drag", "scroll", "type", "key", "set_value", "wait", "list_apps", "list_windows", "focus_app"];

fn destructive(a: &str) -> bool {
    INPUT.contains(&a) || a == "focus_app"
}

fn suggestion(a: &str) -> Option<&'static str> {
    Some(match a {
        "hotkey" | "press_key" | "keypress" | "key_combo" | "shortcut" => "key",
        "type_text" | "input_text" => "type",
        "screenshot" | "get_window_state" => "capture",
        "left_click" | "mouse_click" => "click",
        _ => return None,
    })
}

fn coord(v: &Value) -> Option<(i64, i64)> {
    Some((v.get(0)?.as_i64()?, v.get(1)?.as_i64()?))
}

pub fn summarize(action: &str, a: &Value) -> String {
    let fg = if a["delivery_mode"] == "foreground" { " [FOREGROUND — briefly raises the window / changes focus]" } else { "" };
    let at = |a: &Value| match (a["element"].as_i64(), coord(&a["coordinate"])) {
        (Some(e), _) => format!(" element #{e}"),
        (None, Some((x, y))) => format!(" at ({x}, {y})"),
        _ => String::new(),
    };
    match action {
        "click" | "double_click" | "right_click" | "middle_click" => format!("{action}{}{fg}", at(a)),
        "drag" => {
            let s = |e: &str, c: &str| a[e].as_i64().map(|v| v.to_string()).unwrap_or_else(|| a[c].to_string());
            format!("drag {} → {}{fg}", s("from_element", "from_coordinate"), s("to_element", "to_coordinate"))
        }
        "scroll" => format!("scroll {} x{}{fg}", a["direction"].as_str().unwrap_or("?"), a["amount"].as_i64().unwrap_or(3)),
        "type" => {
            let t = a["text"].as_str().unwrap_or("");
            let head: String = t.chars().take(60).collect();
            format!("type '{head}'{}{fg}", if t.chars().count() > 60 { "..." } else { "" })
        }
        "key" => format!("key '{}'{fg}", a["keys"].as_str().unwrap_or("")),
        "focus_app" => format!("focus '{}'{}", a["app"].as_str().unwrap_or(""), if a["raise_window"] == true { " (raise)" } else { "" }),
        _ => format!("{action}{fg}"),
    }
}

// ───────────────────────── response shaping ─────────────────────────

const MAX_LABEL: usize = 120;
const MIN_IMAGE_DIM: u32 = 8;
const DEDUP_MAX_STREAK: u32 = 2;
const VISION_PROMPT: &str = "Describe what is visible in this desktop application screenshot in concise but specific terms. Mention the app name and window title if visible, the overall layout, any labelled buttons, menus or text fields, and any prominent text content the user would need to know about. Do not invent details that are not actually visible.\n\nAX/SOM index for cross-reference:\n";

fn cut(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn element_json(e: &Element) -> Value {
    let mut v = json!({"index": e.index, "role": e.role, "label": cut(&e.label, MAX_LABEL), "bounds": if e.bounds_unknown() && e.bounds.iter().all(|b| *b == 0) { Value::Null } else { json!(e.bounds) }, "app": e.app});
    if e.label.chars().count() > MAX_LABEL {
        v["label_truncated"] = json!(true);
    }
    v
}

fn element_lines(es: &[Element], max: usize) -> Vec<String> {
    let mut out: Vec<String> = es
        .iter()
        .take(max)
        .map(|e| {
            let where_ = if e.bounds.iter().all(|b| *b == 0) { "@ bounds-unknown (click by element index)".to_string() } else { format!("@ ({}, {}, {}, {})", e.bounds[0], e.bounds[1], e.bounds[2], e.bounds[3]) };
            format!("  #{} {} '{}' {where_}{}", e.index, e.role, cut(&e.label.replace('\n', " "), 60), if e.app.is_empty() { String::new() } else { format!(" [{}]", e.app) })
        })
        .collect();
    if es.len() > max {
        out.push(format!("  ... +{} more (call capture with app= to narrow)", es.len() - max));
    }
    out
}

/// (scale, note) when element bounds live in a different space than the screenshot.
fn bounds_hints(es: &[Element], w: u32, h: u32) -> (Option<f64>, Option<String>) {
    if es.is_empty() || w == 0 || h == 0 {
        return (None, None);
    }
    let (mx, my) = es.iter().fold((0i64, 0i64), |(x, y), e| (x.max(e.bounds[0] + e.bounds[2]), y.max(e.bounds[1] + e.bounds[3])));
    if mx as f64 <= w as f64 * 1.05 && my as f64 <= h as f64 * 1.05 {
        return (None, None);
    }
    let note = format!("element bounds are in native desktop coordinates (extend to ~{mx}x{my}), NOT screenshot pixels ({w}x{h}). coordinate= clicks expect the native space — derive click points from element bounds, or scale screenshot positions up accordingly");
    let scale = ((mx as f64 / w as f64).max(my as f64 / h as f64) * 100.0).round() / 100.0;
    (Some(scale), Some(note))
}

/// A capture's response: text JSON, or text + the screenshot attached for the model.
pub enum Shaped {
    Text(Value),
    Image { summary: String, path: String, mime: String, meta: Value },
}

impl Shaped {
    pub fn render(self) -> String {
        match self {
            Shaped::Text(v) => v.to_string(),
            Shaped::Image { summary, path, mime, meta } => format!("{summary}\n{}\n{}", json!({"meta": meta}), ark_core::tool::image_marker(&mime, Path::new(&path))),
        }
    }
}

/// Last-seen screenshot digest, its `(app, window_title)` target and the repeat streak.
type DedupEntry = (String, (String, String), u32);

pub struct ComputerUseTool {
    pub cfg: Arc<ComputerUseConfig>,
    /// Extra env for spawned commands after the Bot Desktop's (tests inject a fake PATH here).
    pub extra_env: Vec<(String, String)>,
    sessions: Mutex<HashMap<String, Arc<Mutex<Slot>>>>,
    dedup: Mutex<HashMap<String, DedupEntry>>,
}

struct Slot {
    backend: Box<dyn Backend>,
    display: String,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.backend.stop();
    }
}

impl ComputerUseTool {
    pub fn new(cfg: Arc<ComputerUseConfig>) -> Self {
        ComputerUseTool { cfg, extra_env: vec![], sessions: Mutex::default(), dedup: Mutex::default() }
    }

    fn env(&self, home: &Path) -> Vec<(String, String)> {
        let mut e = super::desktop_env(&self.cfg, home);
        e.extend(self.extra_env.iter().cloned());
        e
    }

    /// The session's backend, rebuilt when the desktop it was spawned against moved.
    fn backend(&self, sid: &str, home: &Path, env: &[(String, String)]) -> Result<Arc<Mutex<Slot>>, String> {
        let display = super::display_of(env);
        let mut m = self.sessions.lock().unwrap();
        if let Some(s) = m.get(sid) {
            if s.lock().unwrap().display == display {
                return Ok(s.clone());
            }
            m.remove(sid);
        }
        let backend: Box<dyn Backend> = match super::driver_kind(&self.cfg, home) {
            "cua" => Box::new(super::cua::CuaBackend::start(&self.cfg, home, env)?),
            _ => Box::new(super::native::NativeBackend::new(&self.cfg.backend, env, self.cfg.ax_max_elements, self.cfg.timeout())),
        };
        let s = Arc::new(Mutex::new(Slot { backend, display }));
        m.insert(sid.to_string(), s.clone());
        Ok(s)
    }

    /// Forget a session's backend (its cua-driver session ends).
    pub fn release(&self, sid: &str) -> bool {
        self.dedup.lock().unwrap().remove(sid);
        self.sessions.lock().unwrap().remove(sid).is_some()
    }

    fn dedup_hit(&self, sid: &str, digest: &str, target: (String, String)) -> bool {
        if sid.is_empty() {
            return false;
        }
        let mut m = self.dedup.lock().unwrap();
        if let Some(st) = m.get_mut(sid) {
            if st.0 == digest && st.1 == target && st.2 < DEDUP_MAX_STREAK {
                st.2 += 1;
                return true;
            }
        }
        m.insert(sid.into(), (digest.into(), target, 0));
        false
    }

    fn capture_response(&self, ctx: &ToolCtx, cap: &Capture) -> Shaped {
        let max = self.cfg.max_elements.max(1);
        let visible: Vec<Element> = cap.elements.iter().take(max).cloned().collect();
        let dims = cap.image.as_deref().and_then(super::backend::image_size);
        let (w, h) = dims.unwrap_or((cap.width, cap.height));
        let (scale, note) = bounds_hints(&visible, w, h);
        let lost = cap.elements.len() > visible.len() || visible.iter().any(|e| e.label.chars().count() > MAX_LABEL);
        let too_small = dims.is_some_and(|(a, b)| a.min(b) < MIN_IMAGE_DIM);
        let has_image = cap.image.is_some() && cap.mode != "ax" && !too_small;
        let ax_capped = if cap.ax_max_elements > 0 && cap.elements.len() >= cap.ax_max_elements { cap.ax_max_elements } else { 0 };
        let elements_file = lost.then(|| self.spill(&ctx.home, cap)).flatten();
        let shot = if has_image { super::persist_image(&ctx.home, "computer_use", cap.image.as_deref().unwrap_or(&[]), &cap.mime).map(|p| p.display().to_string()) } else { None };
        let total = cap.elements.len();
        let mut head = format!("capture mode={} {w}x{h}", cap.mode);
        if !cap.app.is_empty() {
            head.push_str(&format!(" app={}", cap.app));
        }
        if !cap.window_title.is_empty() {
            head.push_str(&format!(" window='{}'", cap.window_title));
        }
        let mut lines = vec![head, format!("{total} interactable element(s):")];
        let notes = [
            note.clone().map(|n| n + &scale.map(|s| format!("; estimated scale ~{s}x (screenshot position x {s} ≈ native coordinate)")).unwrap_or_default()),
            shot.as_ref().map(|p| format!("shareable screenshot saved to {p}")),
            Some(cap.note.clone()).filter(|n| !n.is_empty()),
            elements_file.as_ref().map(|f| format!("{}element tree with untruncated labels saved to {f} — read it if you need dropped label text or elements beyond the cap", if ax_capped > 0 { "" } else { "full " })),
            (ax_capped > 0).then(|| format!("accessibility walk capped at {ax_capped} elements; pass app= to narrow")),
        ];
        lines.extend(notes.into_iter().flatten().map(|n| format!("  ({n})")));
        lines.extend(element_lines(&visible, 40));
        if let Some((a, b)) = dims.filter(|_| too_small) {
            lines.push(format!("  (screenshot omitted: {a}x{b} is below the {MIN_IMAGE_DIM}x{MIN_IMAGE_DIM} provider minimum)"));
        }
        let mut extra = Map::new();
        if has_image {
            let img = cap.image.as_deref().unwrap_or(&[]);
            let digest = ark_net::crypto::hex(&ark_net::crypto::sha256(&[cap.mime.as_bytes(), b":", img].concat()));
            if self.dedup_hit(&ctx.session_id, &digest, (cap.app.clone(), cap.window_title.clone())) {
                lines.push("  (screen unchanged since the previous capture — image omitted to save context; the previous capture's screenshot/analysis still shows the current state. Element indices below are fresh and remain the preferred way to act.)".into());
                extra.insert("screen_unchanged".into(), json!(true));
            } else if !self.cfg.vision {
                if let Some(p) = &shot {
                    let mut meta = json!({"mode": cap.mode, "width": w, "height": h, "elements": total, "png_bytes": img.len(), "screenshot_path": p});
                    if let Some(f) = &elements_file {
                        meta["elements_file"] = json!(f);
                    }
                    if let Some(s) = scale {
                        meta["bounds_scale"] = json!(s);
                    }
                    return Shaped::Image { summary: lines.join("\n"), path: p.clone(), mime: cap.mime.clone(), meta };
                }
                lines.push("  (vision unavailable: the screenshot could not be stored for the model; element-index actions still work — drive via the element list above.)".into());
                extra.insert("vision_unavailable".into(), json!(true));
            } else {
                // Pre-analyse through the session's vision model (Hermes auxiliary.vision routing).
                let summary = lines.join("\n");
                match ctx.host.analyze_image(&format!("{VISION_PROMPT}{summary}"), &cap.mime, &ark_net::crypto::b64(img)) {
                    Ok(a) if !a.trim().is_empty() => {
                        extra.insert("vision_analysis".into(), json!(a.trim()));
                        extra.insert("vision_analysis_routed_via".into(), json!("auxiliary.vision"));
                    }
                    _ => {
                        lines.push("  (vision unavailable: the auxiliary vision model could not be reached; screenshot omitted. Element-index actions still work — drive via the element list above.)".into());
                        extra.insert("vision_unavailable".into(), json!(true));
                    }
                }
            }
        }
        let truncated = total - visible.len();
        if truncated > 0 {
            lines.push(format!("  (response truncated to {} of {total} elements; the full tree is in elements_file — read it, or pass app= to narrow scope)", visible.len()));
        }
        let mut v = json!({"mode": cap.mode, "width": w, "height": h, "app": cap.app, "window_title": cap.window_title, "elements": visible.iter().map(element_json).collect::<Vec<_>>(), "total_elements": total, "summary": lines.join("\n")});
        let m = v.as_object_mut().unwrap();
        m.extend(extra);
        if truncated > 0 {
            m.insert("truncated_elements".into(), json!(truncated));
        }
        if let Some(f) = elements_file {
            m.insert("elements_file".into(), json!(f));
        }
        if let Some(p) = shot {
            m.insert("screenshot_path".into(), json!(p));
        }
        if let Some(s) = scale {
            m.insert("bounds_scale".into(), json!(s));
        }
        Shaped::Text(v)
    }

    /// The full element tree (untruncated labels) for read-on-demand.
    fn spill(&self, home: &Path, cap: &Capture) -> Option<String> {
        let p = super::cache_file(home, "cache/computer_use", &format!("elements_{}.json", ark_net::crypto::random_token(16)), "elements_", 20)?;
        let payload = json!({"app": cap.app, "window_title": cap.window_title, "total_elements": cap.elements.len(), "elements": cap.elements.iter().map(|e| json!({"index": e.index, "role": e.role, "label": e.label, "bounds": e.bounds, "app": e.app})).collect::<Vec<_>>()});
        super::write_private(&p, serde_json::to_string_pretty(&payload).ok()?.as_bytes())?;
        Some(p.display().to_string())
    }
}

/// What one dispatch produced (shaped after the lease fence).
enum Raw {
    Json(Value),
    Cap(Capture),
    Act(Box<ActionResult>, Option<Capture>),
}

fn dispatch(b: &mut dyn Backend, action: &str, a: &Value, follow_mode: &str) -> Result<Raw, String> {
    if !ACTIONS.contains(&action) {
        let hint = suggestion(action).map(|h| format!(" — did you mean '{h}'? See the action enum in the tool schema.")).unwrap_or_default();
        return Ok(Raw::Json(json!({"error": format!("unknown action '{action}'{hint}")})));
    }
    // app= guard: input goes to the sticky target; refuse a provable mismatch.
    if INPUT.contains(&action) {
        if let Some(want) = a["app"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
            if let Some(cur) = b.last_app().filter(|c| !c.trim().is_empty()) {
                let (c, w) = (cur.trim().to_lowercase(), want.to_lowercase());
                if !c.contains(&w) && !w.contains(&c) {
                    return Ok(Raw::Json(json!({"ok": false, "action": action, "code": "input_target_mismatch", "error": format!("{action} would go to the current target '{cur}', not '{want}' — input actions always hit the sticky target from the last capture/focus_app. Call capture(app='{want}') or focus_app first, then retry.")})));
                }
            }
        }
    }
    let d = Delivery { mode: a["delivery_mode"].as_str().map(str::to_string), bring_to_front: a["bring_to_front"] == true };
    let mods: Vec<String> = a["modifiers"].as_array().into_iter().flatten().filter_map(|m| m.as_str().map(str::to_string)).collect();
    let point = |a: &Value| match (a["element"].as_u64(), coord(&a["coordinate"])) {
        (Some(e), _) => Point::Element(e as u32),
        (None, Some((x, y))) => Point::Xy(x, y),
        _ => Point::None,
    };
    let res = match action {
        "capture" => {
            let mode = a["mode"].as_str().unwrap_or("som");
            if !matches!(mode, "som" | "vision" | "ax") {
                return Ok(Raw::Json(json!({"error": format!("bad mode '{mode}'; use som|vision|ax")})));
            }
            return Ok(Raw::Cap(b.capture(mode, a["app"].as_str(), a["pid"].as_i64(), a["window_id"].as_i64())?));
        }
        "list_apps" | "list_windows" => {
            let items = if action == "list_apps" { b.list_apps()? } else { b.list_windows()? };
            let key = if action == "list_apps" { "apps" } else { "windows" };
            return Ok(Raw::Json(json!({key: items, "count": items.len()})));
        }
        "wait" => return Ok(Raw::Json(b.wait(a["seconds"].as_f64().unwrap_or(1.0)).payload())),
        "click" | "double_click" | "right_click" | "middle_click" => {
            let (button, count) = match action {
                "double_click" => (a["button"].as_str().unwrap_or("left"), 2),
                "right_click" => ("right", 1),
                "middle_click" => ("middle", 1),
                _ => (a["button"].as_str().unwrap_or("left"), 1),
            };
            b.click(point(a), button, count, &mods, &d)
        }
        "drag" => {
            let (from, to) = match (a["from_element"].as_u64(), a["to_element"].as_u64(), coord(&a["from_coordinate"]), coord(&a["to_coordinate"])) {
                (Some(f), Some(t), _, _) => (Point::Element(f as u32), Point::Element(t as u32)),
                (_, _, Some(f), Some(t)) => (Point::Xy(f.0, f.1), Point::Xy(t.0, t.1)),
                _ => return Ok(Raw::Json(json!({"error": "drag requires from_coordinate/to_coordinate or from_element/to_element"}))),
            };
            b.drag(from, to, a["button"].as_str().unwrap_or("left"), &mods, &d)
        }
        "scroll" => b.scroll(a["direction"].as_str().unwrap_or("down"), a["amount"].as_u64().unwrap_or(3) as u32, point(a), &mods, &d),
        "type" => b.type_text(a["text"].as_str().unwrap_or(""), &d),
        "key" => b.key(a["keys"].as_str().unwrap_or(""), &d),
        "set_value" => match &a["value"] {
            Value::Null => return Ok(Raw::Json(json!({"error": "set_value requires `value`"}))),
            v => b.set_value(&v.as_str().map(str::to_string).unwrap_or_else(|| v.to_string()), a["element"].as_u64().map(|e| e as u32)),
        },
        "focus_app" => match a["app"].as_str().filter(|s| !s.is_empty()) {
            None => return Ok(Raw::Json(json!({"error": "focus_app requires `app`"}))),
            Some(app) => b.focus_app(app, a["raise_window"] == true),
        },
        _ => unreachable!(),
    };
    // No follow-up capture after a failed action: a normal-looking screenshot would suggest success.
    if a["capture_after"] != true || !res.ok {
        return Ok(Raw::Act(Box::new(res), None));
    }
    let cap = match b.last_target() {
        Some((p, w)) => b.capture(follow_mode, None, Some(p), Some(w)),
        None => {
            let app = b.last_app();
            b.capture(follow_mode, app.as_deref(), None, None)
        }
    };
    Ok(Raw::Act(Box::new(res), cap.ok()))
}

fn out(v: Value) -> ToolOutput {
    let err = v.get("error").is_some();
    ToolOutput { content: v.to_string(), is_error: err, ui_resource: None }
}

impl Tool for ComputerUseTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec { name: "computer_use".into(), description: DESCRIPTION.into(), input_schema: schema(), parallel_safe: false, idempotent: false, pinned: false }
    }

    /// Approval scopes (Hermes `cua:<action>:<mode>`): the state-changing action, then a
    /// separate scope for persistent foreground focus. Hard-blocked input asks nothing.
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let action = input["action"].as_str().unwrap_or("").trim().to_lowercase();
        if reject_unsafe(&action, input).is_some() {
            return vec![];
        }
        let mode = if input["delivery_mode"] == "foreground" { "foreground" } else { "background" };
        let mut e = vec![];
        if destructive(&action) {
            e.push(Effect::Remote { dest: format!("desktop:cua:{action}:{mode}"), reason: format!("Allow computer_use to perform `{action}`? computer_use: {}", summarize(&action, input)) });
        }
        if input["bring_to_front"] == true || (action == "focus_app" && input["raise_window"] == true) {
            e.push(Effect::Remote { dest: "desktop:cua:bring_to_front:foreground".into(), reason: format!("Allow computer_use to perform `bring_to_front`? computer_use: {}", summarize(&action, input)) });
        }
        e
    }

    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let action = input["action"].as_str().unwrap_or("").trim().to_lowercase();
        if action.is_empty() {
            return out(json!({"error": "missing `action`"}));
        }
        // Bot Desktop lease: while a human drives the screen every action, capture included, is refused.
        let admitted = match ark_browser::lease::agent_may_act(&ctx.home) {
            Ok(e) => e,
            Err(e) => return ToolOutput::err(super::refused(&action, &e)),
        };
        let env = self.env(&ctx.home);
        if let Some(e) = reject_unsafe(&action, &input) {
            return out(e);
        }
        if let Some(e) = super::backend_error(&self.cfg) {
            return out(json!({"error": e}));
        }
        let slot = match self.backend(&ctx.session_id, &ctx.home, &env) {
            Ok(s) => s,
            Err(e) => {
                let mut v = json!({"error": format!("computer_use backend unavailable: {e}")});
                if super::driver_kind(&self.cfg, &ctx.home) == "cua" {
                    v["hint"] = json!("If the cua-driver binary is missing, run `ark computer-use install`.");
                }
                return out(v);
            }
        };
        let mut s = slot.lock().unwrap();
        // Re-check under the call lock: a human may have taken over while we waited.
        if let Err(e) = ark_browser::lease::agent_may_act(&ctx.home) {
            return ToolOutput::err(super::refused(&action, &e));
        }
        let raw = crate::node::with_env(&env, || dispatch(s.backend.as_mut(), &action, &input, &self.cfg.capture_after_mode));
        drop(s);
        // Any lease transition since admission voids the result: it may picture what the human typed.
        if ark_browser::lease::fence(&ctx.home, admitted).is_err() {
            return ToolOutput::err(super::refused(&action, super::TAKEOVER));
        }
        match raw {
            Err(e) => out(json!({"error": format!("{action} failed: {e}")})),
            Ok(Raw::Json(v)) => out(v),
            Ok(Raw::Cap(c)) => ToolOutput::ok(self.capture_response(ctx, &c).render()),
            Ok(Raw::Act(r, None)) => ToolOutput { content: r.payload().to_string(), is_error: !r.ok, ui_resource: None },
            Ok(Raw::Act(r, Some(c))) => {
                let payload = r.payload();
                match self.capture_response(ctx, &c) {
                    Shaped::Text(mut v) => {
                        if let (Some(m), Value::Object(p)) = (v.as_object_mut(), payload) {
                            m.extend(p);
                        }
                        ToolOutput::ok(v.to_string())
                    }
                    Shaped::Image { summary, path, mime, mut meta } => {
                        meta["action_result"] = payload.clone();
                        ToolOutput::ok(Shaped::Image { summary: format!("{payload}\n\n{summary}"), path, mime, meta }.render())
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// G9: a real Hermes action path over a recording cua-driver — capture lists the driver's
    /// elements, click goes to that element's token, type/key reach the driver, and the
    /// post-action capture round-trips. No desktop, no real driver.
    #[test]
    fn actions_reach_the_cua_driver_and_are_recorded() {
        use crate::computer::fake_driver::{self, FakeDriver};
        let home = ark_core::tmp::scratch_path(format!("ark-cu-hermes-{}-{}", std::process::id(), ark_net::crypto::random_token(4)));
        let _ = std::fs::create_dir_all(&home);
        let Some(f) = FakeDriver::install(&home, "cua-driver") else {
            eprintln!("skipped: python3 is unavailable");
            return;
        };
        let cfg = Arc::new(fake_driver::cfg(&f, "cua"));
        let mut t = ComputerUseTool::new(cfg);
        t.extra_env = f.env();
        let c = fake_driver::ctx(&home, "sess-cu");

        // capture → the driver's window state, rendered as the model-facing element list.
        let (o, _) = fake_driver::run(&t, &c, json!({"action": "capture", "mode": "som"}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("2 interactable element(s)"), "{}", o.content);
        assert!(o.content.contains("#1 button 'Sign in' @ (10, 10, 100, 30)"), "{}", o.content);
        let shot = o.content.lines().find_map(|l| if l.contains("\"screenshot_path\"") { serde_json::from_str::<Value>(l).ok() } else { None }).and_then(|v| v["meta"]["screenshot_path"].as_str().map(str::to_string));
        assert!(shot.is_some_and(|p| Path::new(&p).is_file()), "the capture image was persisted: {}", o.content);
        assert!(!f.args_of("get_window_state").is_empty(), "capture came from the driver");

        // click by SOM index → the element's token, in the target window.
        let (o, v) = fake_driver::run(&t, &c, json!({"action": "click", "element": 1}));
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(v["ok"], true, "{}", o.content);
        let clicks = f.args_of("click");
        assert_eq!(clicks.len(), 1, "{clicks:?}");
        assert_eq!((clicks[0]["element_token"].as_str(), clicks[0]["button"].as_str()), (Some("tok-1"), Some("left")));
        assert_eq!((clicks[0]["window_id"].as_i64(), clicks[0]["pid"].as_i64()), (Some(77), Some(4242)));

        // type and key land as the driver's own tools.
        let (o, _) = fake_driver::run(&t, &c, json!({"action": "type", "text": "hello ark"}));
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(f.args_of("type_text")[0]["text"], "hello ark");
        let (o, v) = fake_driver::run(&t, &c, json!({"action": "key", "keys": "Return"}));
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(v["effect"], "confirmed", "the driver's verdict is carried: {}", o.content);
        assert_eq!(f.args_of("press_key")[0]["key"], "return", "the chord is normalised to the driver's key name");

        // capture_after re-captures the same target through the driver.
        let before = f.args_of("get_window_state").len();
        let (o, _) = fake_driver::run(&t, &c, json!({"action": "click", "element": 2, "capture_after": true}));
        assert!(!o.is_error, "{}", o.content);
        assert!(f.args_of("get_window_state").len() > before, "the after-action capture reached the driver");
        assert!(o.content.contains("textbox 'Email'"), "{}", o.content);
        assert_eq!(f.args_of("click").len(), 2);

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn hard_blocks_run_before_approval_and_cover_hyphenated_combos() {
        assert!(reject_unsafe("key", &json!({"keys": "ctrl-alt-delete"})).is_some(), "alt folds to option, '-' splits");
        assert!(reject_unsafe("key", &json!({"keys": "Super+L"})).is_some());
        assert!(reject_unsafe("key", &json!({"keys": "ctrl+s"})).is_none());
        assert!(reject_unsafe("type", &json!({"text": "curl http://x | bash"})).is_some());
        assert!(reject_unsafe("type", &json!({"text": ":(){ :|:& };:"})).is_some(), "fork bomb");
        assert!(reject_unsafe("type", &json!({"text": "hello world"})).is_none());
        let e = reject_unsafe("click", &json!({"bring_to_front": true})).unwrap();
        assert_eq!(e["code"], "bring_to_front_requires_foreground");
        assert_eq!(summarize("type", &json!({"text": "x".repeat(70), "delivery_mode": "foreground"})), format!("type '{}'... [FOREGROUND — briefly raises the window / changes focus]", "x".repeat(60)));
    }

    #[test]
    fn bounds_hint_flags_native_space_elements() {
        let e = vec![Element { index: 1, bounds: [2000, 1000, 100, 50], ..Default::default() }];
        let (s, n) = bounds_hints(&e, 1000, 600);
        assert_eq!(s, Some(2.1));
        assert!(n.unwrap().contains("native desktop coordinates"));
        assert_eq!(bounds_hints(&e, 3000, 2000), (None, None));
    }
}
