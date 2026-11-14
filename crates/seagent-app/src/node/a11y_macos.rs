//! computer.act v2 accessibility on macOS: the substitute for AT-SPI (`a11y.rs`), through the
//! macOS Accessibility API as System Events exposes it to JXA (`osascript -l JavaScript`,
//! present on every Mac; needs the Accessibility grant for seagent / its terminal).
//!
//! | action | System Events |
//! |---|---|
//! | `list_apps` | `applicationProcesses.whose({backgroundOnly: false})` |
//! | `list_windows` | each process's `windows` (AXWindow: title, position, size) |
//! | `get_accessibility_tree` / `get_window_state` | `uiElements` walked from the window |
//! | element click | the element's `AXPress` action, else `click` |
//! | `set_value` | the element's `value` |
//! | `bring_to_front` | `frontmost = true` + the window's `AXRaise` |
//!
//! Refs are stateless: `ax:<pid>:<window index>` for a window, `ax:<pid>:<window>:<i.j.k>` for
//! the element reached by those `uiElements` indexes. Roles are mapped into AT-SPI's
//! vocabulary (`AXStaticText` → `label`, `AXGroup` → `grouping`, …) so the SOM filter treats
//! layout the same everywhere. Parameters reach the script as one JSON argv, never spliced in.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use serde_json::{json, Value};

/// The JXA program: `run(argv)` with one JSON argument `{op, ref, depth, limit, query, value}`.
pub const SCRIPT: &str = r#"
function run(argv) {
  const a = JSON.parse(argv[0]);
  const se = Application('System Events');
  const procs = () => se.applicationProcesses.whose({backgroundOnly: false})();
  const safe = (f, d) => { try { const v = f(); return v === undefined || v === null ? d : v; } catch (e) { return d; } };
  const bounds = (e) => { const p = safe(() => e.position(), null), s = safe(() => e.size(), null); return p && s && s[0] > 0 ? {x: p[0], y: p[1], width: s[0], height: s[1]} : null; };
  const proc = (pid) => { const m = se.applicationProcesses.whose({unixId: pid})(); if (!m.length) throw new Error('process ' + pid + ' is gone; call list_windows again'); return m[0]; };
  function resolve(r) {
    const p = proc(r.pid);
    const ws = p.windows();
    if (r.win >= ws.length) throw new Error('window ' + r.win + ' of process ' + r.pid + ' is gone; call list_windows again');
    let e = ws[r.win];
    for (const i of r.path) { const k = e.uiElements(); if (i >= k.length) throw new Error('element is no longer in its window; call get_accessibility_tree again'); e = k[i]; }
    return {p: p, w: ws[r.win], e: e};
  }
  if (a.op === 'apps') return JSON.stringify(procs().map(p => ({app: safe(() => p.name(), ''), pid: safe(() => p.unixId(), 0), windows: safe(() => p.windows.length, 0)})));
  if (a.op === 'windows') {
    const out = [];
    for (const p of procs()) {
      const pid = safe(() => p.unixId(), 0), name = safe(() => p.name(), ''), front = safe(() => p.frontmost(), false);
      safe(() => p.windows(), []).forEach((w, i) => out.push({app: name, pid: pid, win: i, title: safe(() => w.name(), ''), bounds: bounds(w), minimized: safe(() => w.attributes.byName('AXMinimized').value(), false), focused: front && i === 0}));
    }
    return JSON.stringify(out);
  }
  if (a.op === 'tree') {
    const t = resolve(a.ref), out = [], q = (a.query || '').toLowerCase();
    let visits = 0;
    function walk(e, path) {
      visits++;
      if (out.length >= a.limit || visits > a.limit * 4) return;
      const role = safe(() => e.role(), ''), name = safe(() => e.name(), '') || safe(() => e.description(), '') || safe(() => e.title(), '');
      let value = safe(() => e.value(), '');
      value = (typeof value === 'string' || typeof value === 'number') ? String(value).slice(0, 500) : '';
      const el = {path: path.slice(), role: role, label: name, value: value, bounds: bounds(e)};
      if (!q || (name + ' ' + role + ' ' + value).toLowerCase().includes(q)) out.push(el);
      if (path.length >= a.depth) return;
      safe(() => e.uiElements(), []).slice(0, 500).forEach((c, i) => { if (out.length < a.limit) { path.push(i); walk(c, path); path.pop(); } });
    }
    walk(t.e, a.ref.path.slice());
    return JSON.stringify(out);
  }
  if (a.op === 'press') {
    const t = resolve(a.ref);
    const press = safe(() => t.e.actions.byName('AXPress'), null);
    if (press && safe(() => { press.perform(); return true; }, false)) return JSON.stringify({ok: true, via: 'AXPress'});
    se.click(t.e);
    return JSON.stringify({ok: true, via: 'click'});
  }
  if (a.op === 'set') {
    const t = resolve(a.ref);
    t.e.value = a.value;
    return JSON.stringify({ok: true, verified: safe(() => t.e.value(), null) === a.value});
  }
  if (a.op === 'front') {
    const t = resolve(a.ref);
    t.p.frontmost = true;
    safe(() => { t.w.actions.byName('AXRaise').perform(); return true; }, false);
    return JSON.stringify({ok: safe(() => t.p.frontmost(), false)});
  }
  throw new Error('unknown op ' + a.op);
}
"#;

/// A parsed ref: process id, window index, element path (empty = the window itself).
#[derive(Debug, Clone, PartialEq)]
pub struct AxRef {
    pub pid: i64,
    pub win: usize,
    pub path: Vec<usize>,
}

impl AxRef {
    pub fn to_ref(&self) -> String {
        if self.path.is_empty() {
            format!("ax:{}:{}", self.pid, self.win)
        } else {
            format!("ax:{}:{}:{}", self.pid, self.win, self.path.iter().map(usize::to_string).collect::<Vec<_>>().join("."))
        }
    }
    fn json(&self) -> Value {
        json!({"pid": self.pid, "win": self.win, "path": self.path})
    }
}

/// `ax:<pid>:<win>` or `ax:<pid>:<win>:<i.j.k>`.
pub fn parse_ref(r: &str) -> Option<AxRef> {
    let mut it = r.strip_prefix("ax:")?.splitn(3, ':');
    let pid: i64 = it.next()?.parse().ok().filter(|p| *p > 0)?;
    let win: usize = it.next()?.parse().ok()?;
    let path = match it.next() {
        None | Some("") => vec![],
        Some(p) => p.split('.').map(|i| i.parse().ok()).collect::<Option<Vec<usize>>>()?,
    };
    (path.len() <= 64).then_some(AxRef { pid, win, path })
}

/// An `AXRole` in AT-SPI's vocabulary (`native::LAYOUT_ROLES` drops the layout ones).
pub fn ax_role(role: &str) -> String {
    let mapped = match role {
        "AXButton" | "AXPopUpButton" | "AXMenuButton" => "push button",
        "AXStaticText" => "label",
        "AXTextField" | "AXSearchField" | "AXSecureTextField" => "entry",
        "AXTextArea" => "text",
        "AXGroup" | "AXRadioGroup" => "grouping",
        "AXScrollArea" => "scroll pane",
        "AXSplitGroup" | "AXLayoutArea" | "AXLayoutItem" => "panel",
        "AXWindow" | "AXSheet" | "AXDrawer" => "window",
        "AXToolbar" => "tool bar",
        "AXCheckBox" => "check box",
        "AXRadioButton" => "radio button",
        "AXComboBox" => "combo box",
        "AXLink" => "link",
        "AXImage" => "image",
        "AXMenuBar" => "menu bar",
        "AXMenuBarItem" | "AXMenuItem" => "menu item",
        "AXMenu" => "menu",
        "AXTabGroup" => "page tab list",
        "AXTab" => "page tab",
        "AXSlider" => "slider",
        "AXIncrementor" => "spin button",
        "AXList" | "AXOutline" => "list",
        "AXRow" | "AXCell" => "list item",
        "AXTable" => "table",
        "AXSplitter" => "separator",
        "AXWebArea" => "document",
        "AXUnknown" | "" => "unknown",
        other => return other.strip_prefix("AX").unwrap_or(other).chars().fold(String::new(), |mut s, c| {
            if c.is_uppercase() && !s.is_empty() {
                s.push(' ');
            }
            s.push(c.to_ascii_lowercase());
            s
        }),
    };
    mapped.to_string()
}

/// The script's `windows` output → the AT-SPI module's window objects.
pub fn windows_json(raw: &Value) -> Vec<Value> {
    raw.as_array()
        .into_iter()
        .flatten()
        .map(|w| {
            let r = AxRef { pid: w["pid"].as_i64().unwrap_or(0), win: w["win"].as_u64().unwrap_or(0) as usize, path: vec![] };
            json!({"app": w["app"], "pid": w["pid"], "windowRef": r.to_ref(), "title": w["title"], "role": "window", "bounds": w["bounds"], "minimized": w["minimized"], "focused": w["focused"]})
        })
        .collect()
}

/// The script's `apps` output → `{app, windowRef, windows, pid}` (windowRef: its first window).
pub fn apps_json(raw: &Value) -> Vec<Value> {
    raw.as_array().into_iter().flatten().map(|a| json!({"app": a["app"], "pid": a["pid"], "windows": a["windows"], "windowRef": AxRef { pid: a["pid"].as_i64().unwrap_or(0), win: 0, path: vec![] }.to_ref()})).collect()
}

/// The script's `tree` output → AT-SPI-shaped elements under the window `root`.
pub fn tree_json(root: &AxRef, raw: &Value) -> Vec<Value> {
    raw.as_array()
        .into_iter()
        .flatten()
        .map(|e| {
            let path: Vec<usize> = e["path"].as_array().into_iter().flatten().filter_map(|i| i.as_u64().map(|i| i as usize)).collect();
            let depth = path.len();
            let mut o = json!({"elementRef": AxRef { pid: root.pid, win: root.win, path }.to_ref(), "role": ax_role(e["role"].as_str().unwrap_or("")), "depth": depth});
            for k in ["label", "value"] {
                if e[k].as_str().is_some_and(|s| !s.is_empty()) {
                    o[k] = e[k].clone();
                }
            }
            if e["bounds"].is_object() {
                o["bounds"] = e["bounds"].clone();
            }
            o
        })
        .collect()
}

/// An osascript failure in words the model can act on (the Accessibility grant is the usual one).
pub fn explain(err: &str) -> String {
    if err.contains("-1719") || err.contains("-25211") || err.contains("assistive access") || err.contains("not allowed") {
        format!("macOS refused accessibility access ({}): grant Accessibility to seagent (or the terminal / app that runs it) in System Settings → Privacy & Security → Accessibility, then retry", err.trim())
    } else {
        format!("macOS accessibility (System Events): {}", err.trim())
    }
}

fn run(args: &Value) -> Result<Value, String> {
    let out = super::run_cmd(&["osascript", "-l", "JavaScript", "-e", SCRIPT, &args.to_string()], std::time::Duration::from_secs(30)).map_err(|e| explain(&e))?;
    serde_json::from_str(out.lines().last().unwrap_or("")).map_err(|e| format!("macOS accessibility: unexpected reply ({e}): {}", out.trim()))
}

fn need_ref(p: &Value, keys: &[&str], action: &str) -> Result<AxRef, String> {
    let r = keys.iter().find_map(|k| p[*k].as_str()).ok_or_else(|| format!("{action} needs {}", keys.join(" or ")))?;
    parse_ref(r).ok_or_else(|| format!("bad ref `{r}` (expected ax:<pid>:<window>[:<path>] from list_windows / get_accessibility_tree)"))
}

/// `list_apps` / `list_windows` / `get_accessibility_tree` / `get_window_state` / `set_value` /
/// `bring_to_front` / element click -- the AT-SPI module's contract.
pub fn act(p: &Value) -> Result<Value, String> {
    let action = p["action"].as_str().unwrap_or("");
    match action {
        "list_apps" => Ok(json!({"apps": apps_json(&run(&json!({"op": "apps"}))?)})),
        "list_windows" => Ok(json!({"windows": windows_json(&run(&json!({"op": "windows"}))?)})),
        "get_accessibility_tree" | "get_window_state" => {
            // No windowRef: the frontmost app's first window.
            let root = match p["windowRef"].as_str().or(p["elementRef"].as_str()) {
                Some(_) => need_ref(p, &["windowRef", "elementRef"], action)?,
                None => windows_json(&run(&json!({"op": "windows"}))?).into_iter().find(|w| w["focused"] == true).and_then(|w| w["windowRef"].as_str().and_then(parse_ref)).ok_or("no frontmost window; pass windowRef from list_windows")?,
            };
            let depth = p["depth"].as_u64().unwrap_or(8).min(64) as usize + root.path.len();
            let limit = p["maxElements"].as_u64().unwrap_or(200).clamp(1, 2000);
            let raw = run(&json!({"op": "tree", "ref": root.json(), "depth": depth, "limit": limit, "query": p["query"].as_str().unwrap_or("")}))?;
            Ok(json!({"observation": {"kind": "window", "observationId": seagent_net::crypto::random_token(8), "elements": tree_json(&root, &raw)}}))
        }
        "set_value" => {
            let r = need_ref(p, &["elementRef"], action)?;
            let v = p["value"].as_str().ok_or("set_value needs value")?;
            if v.len() > 4000 {
                return Err("value longer than 4000 bytes".into());
            }
            let mut o = run(&json!({"op": "set", "ref": r.json(), "value": v}))?;
            o["elementRef"] = json!(r.to_ref());
            Ok(o)
        }
        "bring_to_front" => {
            let mut r = need_ref(p, &["windowRef", "elementRef"], action)?;
            r.path.clear();
            let mut o = run(&json!({"op": "front", "ref": r.json()}))?;
            o["windowRef"] = json!(r.to_ref());
            Ok(o)
        }
        _ => {
            let r = need_ref(p, &["elementRef"], action)?;
            let mut o = run(&json!({"op": "press", "ref": r.json()}))?;
            o["elementRef"] = json!(r.to_ref());
            Ok(o)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refs_round_trip_and_reject_garbage() {
        let w = AxRef { pid: 412, win: 0, path: vec![] };
        assert_eq!(w.to_ref(), "ax:412:0");
        assert_eq!(parse_ref("ax:412:0"), Some(w));
        let e = AxRef { pid: 412, win: 1, path: vec![0, 4, 2] };
        assert_eq!(e.to_ref(), "ax:412:1:0.4.2");
        assert_eq!(parse_ref("ax:412:1:0.4.2"), Some(e));
        for bad in ["", "ax:", "ax:0:0", "ax:-3:0", "ax:12", "ax:12:x", "ax:12:0:1..2", "hwnd:5", ":1.3|/org/a11y"] {
            assert!(parse_ref(bad).is_none(), "{bad}");
        }
        assert!(parse_ref(&format!("ax:1:0:{}", vec!["0"; 65].join("."))).is_none());
    }

    #[test]
    fn roles_use_the_atspi_vocabulary() {
        assert_eq!(ax_role("AXButton"), "push button");
        assert_eq!(ax_role("AXTextField"), "entry");
        assert_eq!(ax_role("AXMenuItem"), "menu item");
        assert_eq!(ax_role("AXDisclosureTriangle"), "disclosure triangle", "unknown roles are spelled out");
        for layout in ["AXStaticText", "AXGroup", "AXScrollArea", "AXSplitGroup", "AXWindow", "AXToolbar", "AXUnknown"] {
            assert!(crate::computer::native::LAYOUT_ROLES.contains(&ax_role(layout).as_str()), "{layout}");
        }
        for target in ["AXButton", "AXTextField", "AXCheckBox", "AXLink", "AXMenuItem", "AXTab", "AXRow"] {
            assert!(!crate::computer::native::LAYOUT_ROLES.contains(&ax_role(target).as_str()), "{target}");
        }
    }

    #[test]
    fn script_output_becomes_the_atspi_shapes() {
        let apps = apps_json(&json!([{"app": "TextEdit", "pid": 77, "windows": 2}]));
        assert_eq!(apps, vec![json!({"app": "TextEdit", "pid": 77, "windows": 2, "windowRef": "ax:77:0"})]);
        let ws = windows_json(&json!([{"app": "TextEdit", "pid": 77, "win": 1, "title": "Untitled", "bounds": {"x": 1, "y": 2, "width": 3, "height": 4}, "minimized": false, "focused": false}]));
        assert_eq!(ws[0]["windowRef"], "ax:77:1");
        assert_eq!(ws[0]["role"], "window");
        assert_eq!(ws[0]["bounds"]["width"], 3);
        let root = AxRef { pid: 77, win: 1, path: vec![] };
        let t = tree_json(&root, &json!([{"path": [], "role": "AXWindow", "label": "Untitled", "value": "", "bounds": null}, {"path": [0, 2], "role": "AXButton", "label": "Save", "value": "", "bounds": {"x": 5, "y": 6, "width": 7, "height": 8}}]));
        assert_eq!(t[0], json!({"elementRef": "ax:77:1", "role": "window", "depth": 0, "label": "Untitled"}));
        assert_eq!(t[1], json!({"elementRef": "ax:77:1:0.2", "role": "push button", "depth": 2, "label": "Save", "bounds": {"x": 5, "y": 6, "width": 7, "height": 8}}));
        let som = crate::computer::native::som(&t, "TextEdit");
        assert_eq!(som.len(), 1, "the window itself is layout");
        assert_eq!((som[0].role.as_str(), som[0].label.as_str(), som[0].center()), ("push button", "Save", Some((8, 10))));
    }

    #[test]
    fn a_missing_grant_is_explained() {
        assert!(explain("execution error: System Events got an error: osascript is not allowed assistive access. (-1719)").contains("Privacy & Security → Accessibility"));
        assert!(explain("boom").starts_with("macOS accessibility"));
        assert!(SCRIPT.contains("function run(argv)") && !SCRIPT.contains("${"), "parameters arrive as argv only");
    }
}
