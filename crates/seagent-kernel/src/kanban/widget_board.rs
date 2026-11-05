//! OpenClaw `src/boards`: per-session boards of widgets (tabs + a 12-column grid)
//! that agents and the UI arrange — HTML views, MCP-app views, plugin widgets and the
//! data-only `session:report` / `session:website` kinds. Stored one JSON file per
//! session under `<data>/boards/`; served over ARP (`board.get`, `board.update`,
//! `board.widget_put`, `board.widget_grant`).

use crate::automation::with_list;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const HTML_MAX_BYTES: usize = 10 * 1024 * 1024;
pub const PROPS_MAX_BYTES: usize = 8 * 1024;
pub const MAX_WIDGETS: usize = 48;
pub const REPORT_KIND: &str = "session:report";
pub const WEBSITE_KIND: &str = "session:website";

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Tab {
    pub tab_id: String,
    pub title: String,
    pub position: usize,
    pub chat_dock: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Widget {
    pub name: String,
    pub tab_id: String,
    pub title: Option<String>,
    /// html | mcp-app | plugin
    pub content_kind: String,
    pub plugin_kind: Option<String>,
    pub props: Option<Value>,
    pub presentation: Option<String>,
    pub height_mode: Option<String>,
    pub size_w: i64,
    pub size_h: i64,
    pub position: usize,
    /// none | pending | granted | rejected
    pub grant_state: String,
    pub revision: u64,
    pub instance_id: String,
    pub declared: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    pub sha256: Option<String>,
    pub descriptor: Option<Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Snapshot {
    pub session_key: String,
    pub revision: u64,
    pub tabs: Vec<Tab>,
    pub widgets: Vec<Widget>,
}

fn file(data: &Path, session: &str) -> PathBuf {
    let h = session.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
    data.join("boards").join(format!("{h:016x}.json"))
}

fn valid_name(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}
fn valid_tab(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn normalize(s: &mut Snapshot) {
    s.tabs.sort_by_key(|t| t.position);
    for (i, t) in s.tabs.iter_mut().enumerate() {
        t.position = i;
    }
    let pos: std::collections::HashMap<String, usize> = s.tabs.iter().map(|t| (t.tab_id.clone(), t.position)).collect();
    s.widgets.sort_by_key(|w| (pos.get(&w.tab_id).copied().unwrap_or(usize::MAX), w.position));
    let mut next: std::collections::HashMap<String, usize> = Default::default();
    for w in s.widgets.iter_mut() {
        let p = next.entry(w.tab_id.clone()).or_insert(0);
        w.position = *p;
        *p += 1;
    }
}

fn move_widget(s: &mut Snapshot, name: &str, tab: &str, position: Option<usize>, after: Option<&str>) -> Result<(), String> {
    if !s.tabs.iter().any(|t| t.tab_id == tab) {
        return Err(format!("not_found: board tab not found: {tab}"));
    }
    if position.is_some() && after.is_some() {
        return Err("invalid_operation: widget_move accepts either position or after, not both".into());
    }
    let i = s.widgets.iter().position(|w| w.name == name).ok_or_else(|| format!("not_found: board widget not found: {name}"))?;
    let mut w = s.widgets.remove(i);
    let mut target: Vec<Widget> = vec![];
    let mut others = vec![];
    for x in s.widgets.drain(..) {
        if x.tab_id == tab {
            target.push(x)
        } else {
            others.push(x)
        }
    }
    target.sort_by_key(|x| x.position);
    let mut at = target.len();
    if let Some(a) = after {
        if a == name {
            return Err("invalid_operation: widget cannot be placed after itself".into());
        }
        at = target.iter().position(|x| x.name == a).ok_or_else(|| format!("not_found: board widget anchor not found on tab {tab}: {a}"))? + 1;
    } else if let Some(p) = position {
        at = p.min(target.len());
    }
    w.tab_id = tab.into();
    target.insert(at, w);
    for (i, x) in target.iter_mut().enumerate() {
        x.position = i;
    }
    others.extend(target);
    s.widgets = others;
    Ok(())
}

/// Apply layout ops atomically (tab_create/update/delete, tabs_reorder, widget_move/resize/remove).
pub fn apply_ops(s: &mut Snapshot, ops: &[Value]) -> Result<(), String> {
    let mut next = s.clone();
    for op in ops {
        let str_ = |k: &str| op.get(k).and_then(|v| v.as_str());
        match str_("kind").unwrap_or("") {
            "tab_create" => {
                let id = str_("tabId").filter(|t| valid_tab(t)).ok_or("invalid_operation: tabId must match ^[a-z0-9-]{1,40}$")?;
                if next.tabs.iter().any(|t| t.tab_id == id) {
                    return Err(format!("conflict: board tab already exists: {id}"));
                }
                let title = str_("title").filter(|t| !t.is_empty() && t.chars().count() <= 80).ok_or("invalid_operation: title must be 1..80 characters")?;
                let pos = next.tabs.len();
                next.tabs.push(Tab { tab_id: id.into(), title: title.into(), position: pos, chat_dock: str_("chatDock").unwrap_or("right").into() });
            }
            "tab_update" => {
                let id = str_("tabId").unwrap_or("");
                let ti = next.tabs.iter().position(|t| t.tab_id == id).ok_or_else(|| format!("not_found: board tab not found: {id}"))?;
                if op.get("title").is_none() && op.get("chatDock").is_none() && op.get("position").is_none() {
                    return Err("invalid_operation: tab_update has no changes".into());
                }
                if let Some(t) = str_("title") {
                    next.tabs[ti].title = t.into();
                }
                if let Some(d) = str_("chatDock") {
                    if !matches!(d, "left" | "right" | "bottom" | "hidden") {
                        return Err("invalid_operation: chatDock must be left, right, bottom or hidden".into());
                    }
                    next.tabs[ti].chat_dock = d.into();
                }
                if let Some(p) = op.get("position").and_then(|v| v.as_u64()) {
                    let mut t = next.tabs.remove(ti);
                    let at = (p as usize).min(next.tabs.len());
                    t.position = at;
                    next.tabs.insert(at, t);
                    for (i, t) in next.tabs.iter_mut().enumerate() {
                        t.position = i;
                    }
                }
            }
            "tab_delete" => {
                let id = str_("tabId").unwrap_or("").to_string();
                if !next.tabs.iter().any(|t| t.tab_id == id) {
                    return Err(format!("not_found: board tab not found: {id}"));
                }
                next.tabs.retain(|t| t.tab_id != id);
                let has = next.widgets.iter().any(|w| w.tab_id == id);
                if next.tabs.is_empty() && has {
                    return Err("invalid_operation: cannot delete the last board tab while it contains widgets".into());
                }
                if let Some(fb) = next.tabs.first().map(|t| t.tab_id.clone()) {
                    for w in next.widgets.iter_mut().filter(|w| w.tab_id == id) {
                        w.tab_id = fb.clone();
                        w.position = usize::MAX;
                    }
                }
            }
            "tabs_reorder" => {
                let ids: Vec<&str> = op["tabIds"].as_array().map(|a| a.iter().filter_map(|v| v.as_str()).collect()).unwrap_or_default();
                let uniq: std::collections::HashSet<&&str> = ids.iter().collect();
                if ids.len() != next.tabs.len() || uniq.len() != ids.len() || ids.iter().any(|i| !next.tabs.iter().any(|t| t.tab_id == *i)) {
                    return Err("invalid_operation: tabs_reorder must contain every tab exactly once".into());
                }
                for t in next.tabs.iter_mut() {
                    t.position = ids.iter().position(|i| *i == t.tab_id).unwrap();
                }
            }
            "widget_move" => {
                let name = str_("name").unwrap_or("");
                let cur = next.widgets.iter().find(|w| w.name == name).map(|w| w.tab_id.clone()).ok_or_else(|| format!("not_found: board widget not found: {name}"))?;
                let tab = str_("tabId").map(String::from).unwrap_or(cur);
                move_widget(&mut next, name, &tab, op.get("position").and_then(|v| v.as_u64()).map(|p| p as usize), str_("after"))?;
            }
            "widget_resize" => {
                let name = str_("name").unwrap_or("");
                let w = next.widgets.iter_mut().find(|w| w.name == name).ok_or_else(|| format!("not_found: board widget not found: {name}"))?;
                w.size_w = op["sizeW"].as_i64().unwrap_or(w.size_w).clamp(1, 12);
                w.size_h = op["sizeH"].as_i64().unwrap_or(w.size_h).clamp(1, 20);
                w.height_mode = Some(str_("heightMode").unwrap_or("fixed").into());
            }
            "widget_remove" => {
                let name = str_("name").unwrap_or("").to_string();
                if !next.widgets.iter().any(|w| w.name == name) {
                    return Err(format!("not_found: board widget not found: {name}"));
                }
                next.widgets.retain(|w| w.name != name);
            }
            k => return Err(format!("invalid_operation: unknown board op {k:?}")),
        }
        normalize(&mut next);
    }
    *s = next;
    Ok(())
}

fn str_len(v: &Value, k: &str, min: usize, max: usize) -> Result<(), String> {
    let n = v.get(k).and_then(|x| x.as_str()).map(|s| s.chars().count());
    match n {
        Some(n) if (min..=max).contains(&n) => Ok(()),
        None if min == 0 => Ok(()),
        _ => Err(format!("invalid_operation: {k} must be a string of {min}..{max} characters")),
    }
}

/// Data-only reports: text / metrics / table / chart / links, ≤ 8KB JSON.
pub fn validate_report(v: &Value) -> Result<(), String> {
    if v.to_string().len() > PROPS_MAX_BYTES {
        return Err("invalid_operation: Report exceeds 8KB JSON budget".into());
    }
    let blocks = v.get("blocks").and_then(|b| b.as_array()).filter(|b| (1..=24).contains(&b.len())).ok_or("invalid_operation: report needs 1..24 blocks")?;
    if v.as_object().is_some_and(|o| o.len() != 1) {
        return Err("invalid_operation: report props contain only blocks".into());
    }
    for b in blocks {
        str_len(b, "title", 0, 120)?;
        match b["type"].as_str() {
            Some("text") => str_len(b, "text", 1, 4000)?,
            Some("metrics") => {
                let items = b["items"].as_array().filter(|a| (1..=8).contains(&a.len())).ok_or("invalid_operation: metrics need 1..8 items")?;
                for i in items {
                    str_len(i, "label", 1, 160)?;
                    str_len(i, "value", 1, 80)?;
                    str_len(i, "detail", 0, 240)?;
                }
            }
            Some("table") => {
                let cols = b["columns"].as_array().filter(|a| (1..=8).contains(&a.len())).ok_or("invalid_operation: table needs 1..8 columns")?;
                let rows = b["rows"].as_array().filter(|a| a.len() <= 40).ok_or("invalid_operation: table allows at most 40 rows")?;
                if rows.iter().any(|r| r.as_array().is_none_or(|r| r.len() != cols.len() || r.iter().any(|c| c.as_str().is_none_or(|s| s.chars().count() > 500)))) {
                    return Err("invalid_operation: Every table row must match the columns".into());
                }
            }
            Some("chart") => {
                let pts = b["points"].as_array().filter(|a| (1..=40).contains(&a.len())).ok_or("invalid_operation: chart needs 1..40 points")?;
                if pts.iter().any(|p| p["value"].as_f64().is_none()) {
                    return Err("invalid_operation: chart values are numbers".into());
                }
                if b.get("style").is_some_and(|s| s != "bar" && s != "line") {
                    return Err("invalid_operation: chart style is bar or line".into());
                }
            }
            Some("links") => {
                let items = b["items"].as_array().filter(|a| (1..=20).contains(&a.len())).ok_or("invalid_operation: links need 1..20 items")?;
                if items.iter().any(|i| i["url"].as_str().is_none_or(|u| !(u.starts_with("https://") || u.starts_with("http://")) || u.len() > 2048)) {
                    return Err("invalid_operation: Links must be HTTP(S)".into());
                }
            }
            _ => return Err("invalid_operation: Every block needs its type".into()),
        }
    }
    Ok(())
}

pub fn validate_website(v: &Value) -> Result<(), String> {
    let o = v.as_object().filter(|o| o.len() == 1).ok_or("invalid_operation: Website props must contain only a valid HTTPS url of at most 2048 characters")?;
    let u = o.get("url").and_then(|u| u.as_str()).filter(|u| u.starts_with("https://") && u.len() <= 2048 && u.len() > 8).ok_or("invalid_operation: Website props must contain only a valid HTTPS url of at most 2048 characters")?;
    let auth = u[8..].split(['/', '?', '#']).next().unwrap_or("");
    if auth.contains('@') {
        return Err("invalid_operation: Website URLs must not contain embedded credentials".into());
    }
    Ok(())
}

fn rmw(data: &Path, session: &str, f: impl FnOnce(&mut Snapshot) -> Result<(), String>) -> Result<Snapshot, String> {
    with_list(&file(data, session), |v: &mut Vec<Snapshot>| {
        if v.is_empty() {
            v.push(Snapshot { session_key: session.into(), ..Default::default() });
        }
        let mut s = v[0].clone();
        f(&mut s)?;
        if s != v[0] {
            // Bump before handing the snapshot back: callers must see the stored revision.
            s.revision += 1;
            v[0] = s.clone();
        }
        Ok(s)
    })?
}

pub fn get(data: &Path, session: &str) -> Result<Snapshot, String> {
    Ok(crate::automation::read_list::<Snapshot>(&file(data, session))?.into_iter().next().unwrap_or(Snapshot { session_key: session.into(), ..Default::default() }))
}

pub fn update(data: &Path, session: &str, ops: &[Value]) -> Result<Snapshot, String> {
    rmw(data, session, |s| apply_ops(s, ops))
}

/// Create or replace a widget (same content kind only); returns the snapshot.
pub fn widget_put(data: &Path, session: &str, p: &Value) -> Result<Snapshot, String> {
    let name = p["name"].as_str().filter(|n| valid_name(n, 64)).ok_or("invalid_operation: widget name must match ^[a-z0-9][a-z0-9._-]{0,63}$")?.to_string();
    let content = &p["content"];
    let kind = content["kind"].as_str().unwrap_or("");
    let mut w = Widget { name: name.clone(), title: p["title"].as_str().map(String::from), presentation: p["presentation"].as_str().map(String::from), height_mode: p["heightMode"].as_str().map(String::from), grant_state: "none".into(), declared: p.get("declared").filter(|d| d.is_object()).cloned(), ..Default::default() };
    match kind {
        "html" => {
            let html = content["html"].as_str().ok_or("invalid_operation: html content needs html")?;
            if html.len() > HTML_MAX_BYTES {
                return Err(format!("invalid_operation: board widget HTML exceeds {HTML_MAX_BYTES} UTF-8 bytes"));
            }
            w.content_kind = "html".into();
            // Content fingerprint (FNV-1a + length): grants are frozen to approved bytes.
            w.sha256 = Some(format!("{:016x}{:016x}", html.len(), html.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3))));
            w.html = Some(html.into());
        }
        "plugin" => {
            let pk = content["pluginKind"].as_str().ok_or("invalid_operation: plugin content needs pluginKind")?;
            let ok = pk.split_once(':').is_some_and(|(a, b)| valid_name(a, 64) && !a.contains(['.', '_']) && valid_name(b, 64));
            if !ok {
                return Err("invalid_operation: pluginKind must look like plugin:widget".into());
            }
            let props = content.get("props").cloned().unwrap_or(json!({}));
            if props.to_string().len() > PROPS_MAX_BYTES {
                return Err("invalid_operation: widget props exceed 8KB".into());
            }
            match pk {
                REPORT_KIND => validate_report(&props)?,
                WEBSITE_KIND => validate_website(&props)?,
                _ => {}
            }
            w.content_kind = "plugin".into();
            w.plugin_kind = Some(pk.into());
            w.props = Some(props);
        }
        "mcp-app" => {
            let d = content.get("descriptor").filter(|d| ["serverName", "toolName", "uiResourceUri", "toolCallId"].iter().all(|k| d[*k].as_str().is_some_and(|s| !s.is_empty()))).ok_or("invalid_operation: mcp-app content needs descriptor {serverName, toolName, uiResourceUri, toolCallId}")?;
            w.content_kind = "mcp-app".into();
            w.descriptor = Some(d.clone());
        }
        _ => return Err("invalid_operation: content kind must be html, plugin or mcp-app".into()),
    }
    rmw(data, session, |s| {
        if s.tabs.is_empty() {
            s.tabs.push(Tab { tab_id: "main".into(), title: "Main".into(), position: 0, chat_dock: "right".into() });
        }
        let existing = s.widgets.iter().find(|x| x.name == name).cloned();
        if let Some(e) = &existing {
            if e.content_kind != w.content_kind || e.plugin_kind != w.plugin_kind {
                return Err(format!("invalid_operation: board widget {name} contains {} content; update it with the same content kind or remove it before replacing it", e.plugin_kind.clone().unwrap_or(e.content_kind.clone())));
            }
        } else if s.widgets.len() >= MAX_WIDGETS {
            return Err(format!("invalid_operation: board cannot contain more than {MAX_WIDGETS} widgets"));
        }
        let tab = p["placement"]["tabId"].as_str().map(String::from).or(existing.as_ref().map(|e| e.tab_id.clone())).unwrap_or_else(|| s.tabs[0].tab_id.clone());
        if !s.tabs.iter().any(|t| t.tab_id == tab) {
            return Err(format!("not_found: board tab not found: {tab}"));
        }
        let (sw, sh) = match p["placement"]["size"].as_str().unwrap_or("md") {
            "sm" => (3, 3),
            "lg" => (8, 6),
            "xl" | "full" => (12, 8),
            _ => (6, 4),
        };
        let mut w = w.clone();
        w.tab_id = tab.clone();
        w.revision = existing.as_ref().map(|e| e.revision).unwrap_or(0) + 1;
        w.instance_id = crate::util::random_hex(16);
        (w.size_w, w.size_h) = existing.as_ref().map(|e| (e.size_w, e.size_h)).unwrap_or((sw, sh));
        // Grants are frozen to approved content; any change (or a widened declaration) re-asks.
        w.grant_state = match &existing {
            Some(e) if e.grant_state == "granted" && e.sha256 == w.sha256 && e.declared == w.declared => "granted".into(),
            _ if w.declared.is_some() => "pending".into(),
            _ => "none".into(),
        };
        match existing {
            Some(e) => {
                w.position = e.position;
                *s.widgets.iter_mut().find(|x| x.name == name).unwrap() = w;
                if p["placement"]["tabId"].is_string() || p["placement"]["after"].is_string() {
                    move_widget(s, &name, &tab, None, p["placement"]["after"].as_str())?;
                }
            }
            None => {
                s.widgets.push(w);
                move_widget(s, &name, &tab, None, p["placement"]["after"].as_str())?;
            }
        }
        normalize(s);
        Ok(())
    })
}

/// Grant or reject a pending widget's declared capabilities (revision + instance must match).
pub fn widget_grant(data: &Path, session: &str, name: &str, decision: &str, revision: u64, instance: &str) -> Result<Snapshot, String> {
    if decision != "granted" && decision != "rejected" {
        return Err("invalid_operation: decision must be granted or rejected".into());
    }
    rmw(data, session, |s| {
        let w = s.widgets.iter_mut().find(|w| w.name == name).ok_or_else(|| format!("not_found: board widget not found: {name}"))?;
        if w.revision != revision || w.instance_id != instance {
            return Err("conflict: widget changed since it was shown; reload the board".into());
        }
        if w.grant_state != "pending" {
            return Err("invalid_operation: widget has no pending grant".into());
        }
        w.grant_state = decision.into();
        Ok(())
    })
}

/// Snapshot for clients: HTML bodies are not inlined (fetched per widget).
pub fn to_json(s: &Snapshot) -> Value {
    let mut v = serde_json::to_value(s).unwrap_or_default();
    if let Some(ws) = v["widgets"].as_array_mut() {
        for w in ws {
            if let Some(o) = w.as_object_mut() {
                o.remove("html");
            }
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widgets_layout_and_validation() {
        let d = crate::kanban::testutil::data();
        let s = widget_put(&d, "sess", &json!({"name": "status", "content": {"kind": "html", "html": "<p>ok</p>"}})).unwrap();
        assert_eq!(s.tabs[0].tab_id, "main");
        assert_eq!((s.widgets[0].size_w, s.widgets[0].size_h), (6, 4));
        let s = widget_put(&d, "sess", &json!({"name": "report", "content": {"kind": "plugin", "pluginKind": "session:report", "props": {"blocks": [{"type": "metrics", "items": [{"label": "tests", "value": "12"}]}]}}, "placement": {"size": "sm"}})).unwrap();
        assert_eq!(s.widgets.len(), 2);
        assert!(widget_put(&d, "sess", &json!({"name": "status", "content": {"kind": "plugin", "pluginKind": "x:y"}})).unwrap_err().contains("same content kind"));
        assert!(widget_put(&d, "sess", &json!({"name": "bad", "content": {"kind": "plugin", "pluginKind": "session:report", "props": {"blocks": [{"type": "table", "columns": ["a"], "rows": [["1", "2"]]}]}}})).is_err());
        assert!(widget_put(&d, "sess", &json!({"name": "site", "content": {"kind": "plugin", "pluginKind": "session:website", "props": {"url": "https://u:p@x.com/"}}})).unwrap_err().contains("credentials"));
        assert!(widget_put(&d, "sess", &json!({"name": "site", "content": {"kind": "plugin", "pluginKind": "session:website", "props": {"url": "http://x.com/"}}})).is_err());
        let s = update(&d, "sess", &[json!({"kind": "tab_create", "tabId": "ops", "title": "Ops"}), json!({"kind": "widget_move", "name": "report", "tabId": "ops"}), json!({"kind": "widget_resize", "name": "status", "sizeW": 99, "sizeH": 0})]).unwrap();
        assert_eq!(s.widgets.iter().find(|w| w.name == "report").unwrap().tab_id, "ops");
        let st = s.widgets.iter().find(|w| w.name == "status").unwrap();
        assert_eq!((st.size_w, st.size_h, st.height_mode.as_deref()), (12, 1, Some("fixed")));
        let rev = s.revision;
        assert!(update(&d, "sess", &[json!({"kind": "tab_create", "tabId": "x", "title": "X"}), json!({"kind": "widget_remove", "name": "nope"})]).is_err());
        assert_eq!(get(&d, "sess").unwrap().revision, rev, "ops are atomic");
        let s = update(&d, "sess", &[json!({"kind": "tab_delete", "tabId": "ops"})]).unwrap();
        assert!(s.widgets.iter().all(|w| w.tab_id == "main"), "widgets move to the remaining tab");
        assert!(update(&d, "sess", &[json!({"kind": "tab_delete", "tabId": "main"})]).unwrap_err().contains("last board tab"));
        // Grants: declared caps start pending; content change re-asks.
        let s = widget_put(&d, "sess", &json!({"name": "app", "content": {"kind": "html", "html": "<b>1</b>"}, "declared": {"tools": ["x"]}})).unwrap();
        let w = s.widgets.iter().find(|w| w.name == "app").unwrap().clone();
        assert_eq!(w.grant_state, "pending");
        assert!(widget_grant(&d, "sess", "app", "granted", w.revision, "stale").is_err());
        let s = widget_grant(&d, "sess", "app", "granted", w.revision, &w.instance_id).unwrap();
        assert_eq!(s.widgets.iter().find(|w| w.name == "app").unwrap().grant_state, "granted");
        let s = widget_put(&d, "sess", &json!({"name": "app", "content": {"kind": "html", "html": "<b>1</b>"}, "declared": {"tools": ["x"]}})).unwrap();
        assert_eq!(s.widgets.iter().find(|w| w.name == "app").unwrap().grant_state, "granted", "same bytes keep the grant");
        let s = widget_put(&d, "sess", &json!({"name": "app", "content": {"kind": "html", "html": "<b>2</b>"}, "declared": {"tools": ["x"]}})).unwrap();
        assert_eq!(s.widgets.iter().find(|w| w.name == "app").unwrap().grant_state, "pending");
        assert!(to_json(&s)["widgets"][0].get("html").is_none());
    }
}
