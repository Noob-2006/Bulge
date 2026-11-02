//! computer.act v2 accessibility actions on Linux (OpenClaw computer-use v2 `list_apps`,
//! `get_accessibility_tree`, `set_value`, element clicks, MIT): AT-SPI over D-Bus. The tree
//! comes from python3-gi (`Atspi`, one process) when importable, else from `gdbus` calls
//! walked here; actions are single `gdbus` calls. Element refs are `<bus name>|<object path>`.

use super::{run_cmd, which};
use serde_json::{json, Value};
use std::time::Duration;

const T: Duration = Duration::from_secs(5);

/// The tree walker for python3-gi (stdlib + gi only; params as one JSON argv).
const TREE_PY: &str = r#"import json, sys
import gi
gi.require_version("Atspi", "2.0")
from gi.repository import Atspi
a = json.loads(sys.argv[1])
want, depth, limit, root = (a.get("query") or "").lower(), a.get("depth", 8), a.get("maxElements", 200), a.get("windowRef")
out = []
def ref(x):
    return x.app.bus_name + "|" + x.path
def walk(x, d):
    if len(out) >= limit or d > depth:
        return
    try:
        name, role = x.get_name() or "", x.get_role_name() or ""
    except Exception:
        return
    e = {"elementRef": ref(x), "role": role, "depth": d}
    if name: e["label"] = name
    try:
        t = x.get_text_iface()
        if t is not None:
            v = t.get_text(0, min(t.get_character_count(), 500))
            if v: e["value"] = v
    except Exception:
        pass
    try:
        r = x.get_extents(Atspi.CoordType.SCREEN)
        if r.width > 0: e["bounds"] = {"x": r.x, "y": r.y, "width": r.width, "height": r.height}
    except Exception:
        pass
    if not want or want in (name + " " + role + " " + e.get("value", "")).lower():
        out.append(e)
    for i in range(min(x.get_child_count(), 500)):
        c = x.get_child_at_index(i)
        if c is not None:
            walk(c, d + 1)
desk = Atspi.get_desktop(0)
apps = [c for c in (desk.get_child_at_index(i) for i in range(desk.get_child_count())) if c is not None]
if a.get("apps"):
    print(json.dumps([{"app": c.get_name(), "windowRef": ref(c), "windows": c.get_child_count()} for c in apps]))
    sys.exit()
start = desk
if root:
    for app in apps:
        if ref(app) == root: start = app; break
        for w in (app.get_child_at_index(j) for j in range(app.get_child_count())):
            if w is not None and ref(w) == root: start = w; break
walk(start, 0)
print(json.dumps(out))
"#;

fn python_gi() -> bool {
    which("python3").is_some() && run_cmd(&["python3", "-I", "-c", "import gi; gi.require_version('Atspi', '2.0')"], T).is_ok()
}

/// The accessibility bus (`org.a11y.Bus.GetAddress` on the session bus).
fn bus() -> Result<String, String> {
    which("gdbus").ok_or("AT-SPI needs python3-gi (Atspi) or gdbus (glib2); neither is installed")?;
    let out = run_cmd(&["gdbus", "call", "--session", "--dest", "org.a11y.Bus", "--object-path", "/org/a11y/bus", "--method", "org.a11y.Bus.GetAddress"], T).map_err(|e| format!("no accessibility bus (is at-spi2-core running in a desktop session?): {e}"))?;
    strings(&out).into_iter().next().ok_or_else(|| format!("unexpected GetAddress reply: {out}"))
}

/// The quoted strings of a gdbus (GVariant text) reply, unescaped.
pub fn strings(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c != '\'' && c != '"' {
            continue;
        }
        let mut cur = String::new();
        while let Some(d) = it.next() {
            match d {
                '\\' => {
                    if let Some(e) = it.next() {
                        cur.push(match e {
                            'n' => '\n',
                            't' => '\t',
                            other => other,
                        });
                    }
                }
                d if d == c => break,
                d => cur.push(d),
            }
        }
        out.push(cur);
    }
    out
}

/// `([(':1.5', objectpath '/org/…'), (':1.6', '/org/…')],)` → refs.
pub fn children(s: &str) -> Vec<String> {
    strings(s).chunks(2).filter(|c| c.len() == 2 && c[1].starts_with('/')).map(|c| format!("{}|{}", c[0], c[1])).collect()
}

/// `((10, 20, 300, 40),)` → bounds.
pub fn extents(s: &str) -> Option<Value> {
    let n: Vec<i64> = s.split(|c: char| !(c.is_ascii_digit() || c == '-')).filter(|x| !x.is_empty()).filter_map(|x| x.parse().ok()).collect();
    (n.len() == 4 && n[2] > 0).then(|| json!({"x": n[0], "y": n[1], "width": n[2], "height": n[3]}))
}

fn split_ref(r: &str) -> Result<(&str, &str), String> {
    let (b, p) = r.split_once('|').ok_or("elementRef must be `<bus>|<path>` (from get_accessibility_tree)")?;
    let ok = b.starts_with(|c: char| c == ':' || c.is_ascii_alphabetic()) && b.chars().all(|c| c.is_ascii_alphanumeric() || ".:_-".contains(c)) && p.starts_with('/') && p.chars().all(|c| c.is_ascii_alphanumeric() || "/_".contains(c));
    if ok {
        Ok((b, p))
    } else {
        Err(format!("bad elementRef `{r}`"))
    }
}

fn call(addr: &str, r: &str, method: &str, args: &[&str]) -> Result<String, String> {
    let (b, p) = split_ref(r)?;
    let mut argv = vec!["gdbus", "call", "--address", addr, "--dest", b, "--object-path", p, "--method", method];
    argv.extend(args);
    run_cmd(&argv, T)
}

fn tree_gdbus(p: &Value) -> Result<Value, String> {
    let addr = bus()?;
    let depth = p["depth"].as_u64().unwrap_or(8).min(64) as usize;
    let limit = p["maxElements"].as_u64().unwrap_or(150).clamp(1, 2000) as usize;
    let want = p["query"].as_str().unwrap_or("").to_lowercase();
    let root = p["windowRef"].as_str().unwrap_or("org.a11y.atspi.Registry|/org/a11y/atspi/accessible/root").to_string();
    let mut out = Vec::new();
    let mut stack = vec![(root, 0usize)];
    let mut visited = 0;
    while let Some((r, d)) = stack.pop() {
        visited += 1;
        if out.len() >= limit || visited > limit * 4 {
            break;
        }
        let role = call(&addr, &r, "org.a11y.atspi.Accessible.GetRoleName", &[]).map(|s| strings(&s).into_iter().next().unwrap_or_default()).unwrap_or_default();
        let name = call(&addr, &r, "org.freedesktop.DBus.Properties.Get", &["org.a11y.atspi.Accessible", "Name"]).map(|s| strings(&s).into_iter().next().unwrap_or_default()).unwrap_or_default();
        let mut e = json!({"elementRef": r, "role": role, "depth": d});
        if !name.is_empty() {
            e["label"] = json!(name);
        }
        if let Some(b) = call(&addr, &r, "org.a11y.atspi.Component.GetExtents", &["0"]).ok().and_then(|s| extents(&s)) {
            e["bounds"] = b;
        }
        if want.is_empty() || format!("{name} {role}").to_lowercase().contains(&want) {
            out.push(e);
        }
        if d < depth {
            let kids = call(&addr, &r, "org.a11y.atspi.Accessible.GetChildren", &[]).map(|s| children(&s)).unwrap_or_default();
            stack.extend(kids.into_iter().rev().map(|k| (k, d + 1)));
        }
    }
    Ok(json!(out))
}

fn py(args: &Value) -> Result<Value, String> {
    let out = run_cmd(&["python3", "-I", "-c", TREE_PY, &args.to_string()], Duration::from_secs(30))?;
    serde_json::from_str(out.lines().last().unwrap_or("")).map_err(|e| format!("AT-SPI walker: {e}"))
}

/// `list_apps` / `list_windows` / `get_accessibility_tree` / `set_value` / element click.
pub fn act(p: &Value) -> Result<Value, String> {
    let action = p["action"].as_str().unwrap_or("");
    match action {
        "list_apps" | "list_windows" => {
            let apps = if python_gi() {
                py(&json!({"apps": true}))?
            } else {
                let addr = bus()?;
                let out = run_cmd(&["gdbus", "call", "--address", &addr, "--dest", "org.a11y.atspi.Registry", "--object-path", "/org/a11y/atspi/accessible/root", "--method", "org.a11y.atspi.Accessible.GetChildren"], T)?;
                json!(children(&out).into_iter().map(|r| {
                    let name = call(&addr, &r, "org.freedesktop.DBus.Properties.Get", &["org.a11y.atspi.Accessible", "Name"]).map(|s| strings(&s).into_iter().next().unwrap_or_default()).unwrap_or_default();
                    json!({"app": name, "windowRef": r})
                }).collect::<Vec<_>>())
            };
            if action == "list_apps" {
                return Ok(json!({"apps": apps}));
            }
            // Windows: each app's top-level frames.
            let mut wins = Vec::new();
            for a in apps.as_array().into_iter().flatten() {
                let tree = if python_gi() { py(&json!({"windowRef": a["windowRef"], "depth": 1, "maxElements": 50}))? } else { tree_gdbus(&json!({"windowRef": a["windowRef"], "depth": 1, "maxElements": 50}))? };
                for w in tree.as_array().into_iter().flatten().filter(|w| w["depth"] == 1) {
                    wins.push(json!({"app": a["app"], "windowRef": w["elementRef"], "title": w["label"], "role": w["role"], "bounds": w["bounds"]}));
                }
            }
            Ok(json!({"windows": wins}))
        }
        "get_accessibility_tree" | "get_window_state" => {
            let args = json!({"windowRef": p["windowRef"], "query": p["query"], "depth": p["depth"].as_u64().unwrap_or(8).min(64), "maxElements": p["maxElements"].as_u64().unwrap_or(200).clamp(1, 2000)});
            let elements = if python_gi() { py(&args)? } else { tree_gdbus(&args)? };
            Ok(json!({"observation": {"kind": "window", "observationId": ark_net::crypto::random_token(8), "elements": elements}}))
        }
        "set_value" => {
            let r = p["elementRef"].as_str().ok_or("set_value needs elementRef")?;
            let v = p["value"].as_str().ok_or("set_value needs value")?;
            if v.len() > 4000 {
                return Err("value longer than 4000 bytes".into());
            }
            let out = call(&bus()?, r, "org.a11y.atspi.EditableText.SetTextContents", &[&format!("{v:?}")])?;
            Ok(json!({"ok": out.contains("true"), "elementRef": r}))
        }
        "bring_to_front" => {
            let r = p["windowRef"].as_str().ok_or("bring_to_front needs windowRef")?;
            let out = call(&bus()?, r, "org.a11y.atspi.Component.GrabFocus", &[])?;
            Ok(json!({"ok": out.contains("true"), "windowRef": r}))
        }
        // A click on an element (no coordinates): its first AT-SPI action ("click", "press", "activate").
        _ => {
            let r = p["elementRef"].as_str().ok_or("needs elementRef")?;
            let out = call(&bus()?, r, "org.a11y.atspi.Action.DoAction", &["0"])?;
            Ok(json!({"ok": out.contains("true"), "elementRef": r}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gdbus_replies_parse() {
        assert_eq!(strings("('unix:path=/run/user/1000/at-spi/bus,guid=65b9',)"), ["unix:path=/run/user/1000/at-spi/bus,guid=65b9"]);
        assert_eq!(strings(r#"(<"it's">,)"#), ["it's"]);
        assert_eq!(strings(r"(<'a \'b\' c'>,)"), ["a 'b' c"]);
        let kids = children("([(':1.0', objectpath '/org/a11y/atspi/accessible/root'), (':1.3', '/org/a11y/atspi/accessible/42')],)");
        assert_eq!(kids, [":1.0|/org/a11y/atspi/accessible/root", ":1.3|/org/a11y/atspi/accessible/42"]);
        assert!(children("(@a(so) [],)").is_empty());
        assert_eq!(extents("((10, -20, 300, 40),)").unwrap(), json!({"x": 10, "y": -20, "width": 300, "height": 40}));
        assert!(extents("((0, 0, 0, 0),)").is_none());
    }

    #[test]
    fn element_refs_are_checked_before_reaching_gdbus() {
        assert!(split_ref(":1.3|/org/a11y/atspi/accessible/42").is_ok());
        assert!(split_ref("org.a11y.atspi.Registry|/org/a11y/atspi/accessible/root").is_ok());
        for bad in ["nobar", ":1.3|relative", "--dest|/x", ":1.3|/x y", "|/x"] {
            assert!(split_ref(bad).is_err(), "{bad}");
        }
    }

    /// Read-only, against the desktop this runs on: `cargo test -p ark-app live_desktop -- --ignored`.
    #[test]
    #[ignore]
    fn live_desktop_tree_both_backends() {
        let apps = act(&json!({"action": "list_apps"})).unwrap();
        assert!(!apps["apps"].as_array().unwrap().is_empty(), "{apps}");
        let t = tree_gdbus(&json!({"depth": 2, "maxElements": 10})).unwrap();
        assert!(t.as_array().unwrap().iter().any(|e| e["role"] == "application"), "{t}");
        let t = act(&json!({"action": "get_accessibility_tree", "depth": 2, "maxElements": 10})).unwrap();
        assert!(!t["observation"]["elements"].as_array().unwrap().is_empty(), "{t}");
    }
}
