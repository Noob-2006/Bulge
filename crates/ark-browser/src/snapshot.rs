//! Accessibility-tree role snapshots with `[ref=eN]` handles (OpenClaw
//! `cdp-role-snapshot*.ts` + `pw-role-snapshot.ts` `finalizeRoleSnapshot`, MIT; the
//! same refs serve Hermes' `@eN`). Input is `Accessibility.getFullAXTree` nodes.

use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

pub const INTERACTIVE: &[&str] = &["button", "checkbox", "combobox", "link", "listbox", "menuitem", "menuitemcheckbox", "menuitemradio", "option", "radio", "searchbox", "slider", "spinbutton", "switch", "tab", "textbox", "treeitem"];
pub const CONTENT: &[&str] = &["article", "cell", "columnheader", "gridcell", "heading", "listitem", "main", "navigation", "region", "rowheader"];
pub const STRUCTURAL: &[&str] = &["application", "directory", "document", "generic", "grid", "group", "ignored", "list", "menu", "menubar", "none", "presentation", "row", "rowgroup", "table", "tablist", "toolbar", "tree", "treegrid", "rootwebarea", "webarea", "section", "div", "paragraph", "linebreak"];
pub const MAX_DEPTH: usize = 100;
pub const TRUNCATED_MARKER: &str = "\n\n[...TRUNCATED - page too large]";
pub const DEFAULT_MAX_CHARS: usize = 40_000;
pub const EFFICIENT_MAX_CHARS: usize = 8_000;
pub const EFFICIENT_DEPTH: usize = 6;

#[derive(Debug, Clone, Default)]
pub struct Opts {
    pub interactive: bool,
    pub compact: bool,
    pub max_depth: Option<usize>,
    pub urls: bool,
}

/// Cursor-interactive element found by DOM scan (no interactive role, but clickable).
#[derive(Debug, Clone, Default)]
pub struct Cursor {
    pub text: String,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ref {
    pub role: String,
    pub name: String,
    pub nth: usize,
    pub backend: i64,
    /// CDP session of the frame the node lives in (None = the page session).
    pub session: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Line {
    pub text: String,
    pub depth: usize,
    /// An iframe whose document should be spliced in after this line.
    pub iframe: Option<i64>,
    pub ref_id: Option<String>,
}

pub fn ax_str(v: &Value) -> String {
    match &v["value"] {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        o => o.to_string(),
    }
}

fn prop<'a>(n: &'a Value, name: &str) -> Option<&'a Value> {
    n["properties"].as_array()?.iter().find(|p| p["name"] == name).map(|p| &p["value"]["value"])
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

pub fn is_interactive(role: &str) -> bool {
    INTERACTIVE.contains(&lower(role).as_str())
}

/// Render AX nodes into snapshot lines, allocating refs (`counter` is shared across frames).
pub fn render(nodes: &[Value], cursor: &HashMap<i64, Cursor>, o: &Opts, session: Option<&str>, counter: &mut usize, refs: &mut Vec<(String, Ref)>, base_depth: usize) -> (Vec<Line>, bool) {
    let by_id: HashMap<&str, &Value> = nodes.iter().filter_map(|n| Some((n["nodeId"].as_str()?, n))).collect();
    let mut has_parent = HashSet::new();
    for n in nodes {
        for c in n["childIds"].as_array().into_iter().flatten() {
            if let Some(c) = c.as_str() {
                has_parent.insert(c);
            }
        }
    }
    let roots: Vec<&Value> = nodes.iter().filter(|n| n["nodeId"].as_str().is_some_and(|id| !has_parent.contains(id))).collect();
    let mut lines = Vec::new();
    let mut too_deep = false;
    let mut stack: Vec<(&Value, usize, String)> = roots.into_iter().rev().map(|n| (n, base_depth, String::new())).collect();
    let mut seen = HashSet::new();
    while let Some((n, depth, parent_name)) = stack.pop() {
        let Some(id) = n["nodeId"].as_str() else { continue };
        if !seen.insert(id) {
            continue;
        }
        let role_raw = ax_str(&n["role"]);
        let role = if role_raw.is_empty() { "unknown".to_string() } else { role_raw };
        let lr = lower(&role);
        let name = ax_str(&n["name"]).split_whitespace().collect::<Vec<_>>().join(" ");
        let backend = n["backendDOMNodeId"].as_i64().unwrap_or(0);
        let cur = cursor.get(&backend);
        let name = if name.is_empty() { cur.map(|c| c.text.clone()).unwrap_or_default() } else { name };
        let ignored = n["ignored"] == true;
        let transparent = ignored || matches!(lr.as_str(), "none" | "presentation" | "inlinetextbox" | "fragment") || (lr == "generic" && name.is_empty() && cur.is_none());
        let redundant_text = lr == "statictext" && (name.is_empty() || name == parent_name);
        let kids: Vec<&Value> = n["childIds"].as_array().into_iter().flatten().filter_map(|c| by_id.get(c.as_str()?).copied()).collect();
        let skip_line = transparent || redundant_text;
        if skip_line {
            for k in kids.into_iter().rev() {
                stack.push((k, depth, parent_name.clone()));
            }
            continue;
        }
        if depth > MAX_DEPTH {
            too_deep = true;
            continue;
        }
        if o.max_depth.is_some_and(|m| depth > m + base_depth) {
            continue;
        }
        let is_iframe = lr == "iframe";
        let wants_ref = backend != 0 && (is_interactive(&role) || (CONTENT.contains(&lr.as_str()) && !name.is_empty()) || is_iframe || cur.is_some());
        let keep = if o.interactive { is_interactive(&role) || is_iframe || cur.is_some() } else { !(o.compact && STRUCTURAL.contains(&lr.as_str()) && name.is_empty() && !wants_ref) };
        if keep {
            let mut t = format!("{}- {role}", "  ".repeat(if o.interactive { base_depth } else { depth }));
            if !name.is_empty() {
                t.push(' ');
                t.push_str(&crate::util::json_str(crate::util::cut(&name, 300)));
            }
            let mut ref_id = None;
            if wants_ref {
                *counter += 1;
                let r = format!("e{counter}");
                t.push_str(&format!(" [ref={r}]"));
                refs.push((r.clone(), Ref { role: role.clone(), name: name.clone(), nth: 0, backend, session: session.map(str::to_string) }));
                ref_id = Some(r);
            }
            for p in ["checked", "disabled", "expanded", "pressed", "selected", "level", "invalid"] {
                match prop(n, p) {
                    Some(Value::Bool(true)) => t.push_str(&format!(" [{p}]")),
                    Some(Value::String(s)) if p == "invalid" && s != "false" => t.push_str(&format!(" [invalid={s}]")),
                    Some(Value::String(s)) if s == "mixed" => t.push_str(&format!(" [{p}=mixed]")),
                    Some(Value::String(s)) if s == "true" => t.push_str(&format!(" [{p}]")),
                    Some(Value::Number(x)) if p == "level" => t.push_str(&format!(" [level={x}]")),
                    _ => {}
                }
            }
            let value = ax_str(&n["value"]);
            let url = prop(n, "url").and_then(|v| v.as_str()).map(str::to_string).or_else(|| (lr == "link" && value.contains("://")).then(|| value.clone()));
            if !value.is_empty() && lr != "link" {
                t.push_str(&format!(" value={}", crate::util::json_str(crate::util::cut(&value, 200))));
            }
            if o.urls {
                if let Some(u) = &url {
                    t.push_str(&format!(" [url={u}]"));
                }
            }
            if let Some(c) = cur {
                if !c.flags.is_empty() {
                    t.push_str(&format!(" [cursor:{}]", c.flags.join(", ")));
                }
            }
            lines.push(Line { text: t, depth, iframe: is_iframe.then_some(backend), ref_id });
        }
        for k in kids.into_iter().rev() {
            stack.push((k, depth + 1, name.clone()));
        }
    }
    (lines, too_deep)
}

/// `nth` per role+name; dropped when the key is unique.
pub fn assign_nth(refs: &mut [(String, Ref)]) -> HashMap<String, usize> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for (_, r) in refs.iter() {
        *counts.entry(format!("{}\0{}", r.role, r.name)).or_default() += 1;
    }
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut nth = HashMap::new();
    for (id, r) in refs.iter_mut() {
        let k = format!("{}\0{}", r.role, r.name);
        let i = seen.entry(k.clone()).or_default();
        r.nth = if counts[&k] > 1 { *i } else { 0 };
        if r.nth > 0 {
            nth.insert(id.clone(), r.nth);
        }
        *i += 1;
    }
    nth
}

pub struct Finished {
    pub text: String,
    pub stats: Value,
    pub truncated: bool,
    pub new_elements: Option<usize>,
    pub keys: HashSet<String>,
    pub visible_refs: HashSet<String>,
}

/// Delta markers, truncation and stats (OpenClaw `finalizeRoleSnapshot`).
pub fn finish(lines: Vec<Line>, refs: &[(String, Ref)], prev: Option<&HashSet<String>>, max_chars: Option<usize>, too_deep: bool, empty: &str) -> Finished {
    let by: HashMap<&str, &Ref> = refs.iter().map(|(k, r)| (k.as_str(), r)).collect();
    let mut keys = HashSet::new();
    let mut new_count = 0;
    let mut out: Vec<String> = Vec::new();
    for l in lines {
        let mut t = l.text;
        if let Some(r) = l.ref_id.as_deref().and_then(|id| by.get(id)) {
            if r.nth > 0 {
                t = t.replacen(&format!("[ref={}]", l.ref_id.as_deref().unwrap()), &format!("[ref={}] [nth={}]", l.ref_id.as_deref().unwrap(), r.nth), 1);
            }
            let key = format!("{}\0{}\0{}", r.role, r.name, r.nth);
            if prev.is_some_and(|p| !p.contains(&key)) {
                t.push_str(" [new]");
                new_count += 1;
            }
            keys.insert(key);
        }
        out.push(t);
    }
    let mut text = if out.is_empty() { empty.to_string() } else { out.join("\n") };
    if too_deep {
        text.push_str("\n\n[...TRUNCATED - accessibility tree too deep]");
    }
    let new_elements = prev.map(|_| new_count);
    if let Some(n) = new_elements.filter(|n| *n > 0) {
        text.push_str(&format!("\n{n} new element(s) since last snapshot"));
    }
    let mut truncated = false;
    if let Some(max) = max_chars.filter(|m| *m > 0 && text.len() > *m) {
        truncated = true;
        if max < TRUNCATED_MARKER.len() {
            text = "…".into();
        } else {
            let mut kept = String::new();
            for line in text.lines() {
                if kept.len() + line.len() + 1 + 2 + TRUNCATED_MARKER.len() > max {
                    break;
                }
                if !kept.is_empty() {
                    kept.push('\n');
                }
                kept.push_str(line);
            }
            text = kept + TRUNCATED_MARKER;
        }
    }
    let visible: HashSet<String> = parse_refs(&text);
    let interactive = refs.iter().filter(|(id, r)| visible.contains(id) && is_interactive(&r.role)).count();
    let stats = json!({"lines": text.lines().count(), "chars": text.len(), "refs": visible.len(), "interactive": interactive});
    Finished { text, stats, truncated, new_elements, keys, visible_refs: visible }
}

/// Refs present in snapshot text.
pub fn parse_refs(text: &str) -> HashSet<String> {
    let mut s = HashSet::new();
    for part in text.split("[ref=").skip(1) {
        if let Some(r) = part.split(']').next() {
            s.insert(r.to_string());
        }
    }
    s
}

/// Accept `e12`, `@e12`, `ref=e12`, `[ref=e12]`, or bare digits.
pub fn normalize_ref(r: &str) -> Option<String> {
    let t = r.trim().trim_start_matches('[').trim_end_matches(']');
    let t = t.strip_prefix("ref=").unwrap_or(t);
    let t = t.strip_prefix('@').unwrap_or(t);
    if !t.is_empty() && t.len() <= 9 && t.bytes().all(|b| b.is_ascii_digit()) {
        return Some(format!("e{t}"));
    }
    let d = t.strip_prefix('e')?;
    (!d.is_empty() && d.len() <= 9 && d.bytes().all(|b| b.is_ascii_digit())).then(|| t.to_string())
}

/// Keep lines containing every whitespace-separated token (case-insensitive).
pub fn query_lines(text: &str, q: &str) -> Vec<String> {
    let toks: Vec<String> = q.split_whitespace().map(lower).collect();
    text.lines().filter(|l| {
        let ll = l.to_lowercase();
        toks.iter().all(|t| ll.contains(t.as_str()))
    })
    .map(str::to_string)
    .collect()
}

/// Hermes truncate-and-store: cut at line boundaries, store the full tree for read paging.
pub fn truncate_store(text: &str, max: usize, store_dir: &std::path::Path) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let full = crate::policy::redact(text);
    let full = if full.len() > 2_000_000 { format!("{}\n\n[... stored copy truncated at 2,000,000 chars of {} ...]", crate::util::cut(&full, 2_000_000), full.len()) } else { full };
    let digest = ark_net::crypto::hex(&ark_net::crypto::sha256(full.as_bytes()))[..10].to_string();
    let path = store_dir.join(format!("browser-snapshot-{digest}.txt"));
    let stored = crate::util::write_private(&path, full.as_bytes()).is_ok().then(|| path.display().to_string());
    let reserve = (110 + stored.as_ref().map_or(0, |s| s.len())).min(max / 2);
    let lines: Vec<&str> = text.split('\n').collect();
    let mut out = Vec::new();
    let mut chars = 0;
    for l in &lines {
        if chars + l.len() + 1 > max - reserve {
            break;
        }
        out.push(l.to_string());
        chars += l.len() + 1;
    }
    let remaining = lines.len() - out.len();
    if remaining > 0 {
        match stored {
            Some(p) => out.push(format!("\n[... {remaining} more lines truncated — full snapshot: read path=\"{p}\" offset={} limit=200]", out.len() + 1)),
            None => out.push(format!("\n[... {remaining} more lines truncated, use browser_snapshot for full content]")),
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, role: &str, name: &str, kids: &[&str], backend: i64) -> Value {
        json!({"nodeId": id, "role": {"value": role}, "name": {"value": name}, "childIds": kids, "backendDOMNodeId": backend})
    }

    fn tree() -> Vec<Value> {
        let mut submit = node("4", "button", "Submit", &[], 14);
        submit["properties"] = json!([{"name": "disabled", "value": {"value": true}}]);
        let mut h = node("6", "heading", "Title", &[], 16);
        h["properties"] = json!([{"name": "level", "value": {"value": 2}}]);
        let mut tb = node("5", "textbox", "Email", &[], 15);
        tb["value"] = json!({"value": "a@b.c"});
        vec![
            node("1", "RootWebArea", "Page", &["2", "6"], 11),
            json!({"nodeId": "2", "ignored": true, "role": {"value": "none"}, "childIds": ["3"]}),
            node("3", "generic", "", &["4", "5", "7", "8"], 13),
            submit,
            tb,
            h,
            node("7", "button", "Go", &[], 17),
            node("8", "button", "Go", &[], 18),
        ]
    }

    #[test]
    fn renders_openclaw_line_format() {
        let mut refs = vec![];
        let mut n = 0;
        let (lines, deep) = render(&tree(), &HashMap::new(), &Opts::default(), None, &mut n, &mut refs, 0);
        assert!(!deep);
        assert_eq!(assign_nth(&mut refs).len(), 1);
        let f = finish(lines, &refs, None, None, false, "(empty page)");
        assert_eq!(f.text, "- RootWebArea \"Page\"\n  - button \"Submit\" [ref=e1] [disabled]\n  - textbox \"Email\" [ref=e2] value=\"a@b.c\"\n  - button \"Go\" [ref=e3]\n  - button \"Go\" [ref=e4] [nth=1]\n  - heading \"Title\" [ref=e5] [level=2]");
        assert_eq!(f.stats["interactive"], 4);
        assert_eq!(refs[3].1.backend, 18);
    }

    #[test]
    fn interactive_delta_and_truncation() {
        let mut refs = vec![];
        let mut n = 0;
        let o = Opts { interactive: true, ..Default::default() };
        let (lines, _) = render(&tree(), &HashMap::new(), &o, None, &mut n, &mut refs, 0);
        assign_nth(&mut refs);
        let first = finish(lines.clone(), &refs, None, None, false, "(no interactive elements)");
        assert!(first.text.starts_with("- button \"Submit\" [ref=e1]") && !first.text.contains("heading"));
        let mut prev = first.keys.clone();
        prev.retain(|k| !k.starts_with("textbox"));
        let second = finish(lines.clone(), &refs, Some(&prev), None, false, "");
        assert!(second.text.contains("textbox \"Email\" [ref=e2] value=\"a@b.c\" [new]") && second.text.ends_with("1 new element(s) since last snapshot"));
        let cut = finish(lines, &refs, None, Some(80), false, "");
        assert!(cut.truncated && cut.text.ends_with(TRUNCATED_MARKER) && cut.text.len() <= 80);
        assert!(cut.visible_refs.contains("e1") && !cut.visible_refs.contains("e4"));
    }

    #[test]
    fn cursor_nodes_refs_and_queries() {
        let nodes = vec![node("1", "RootWebArea", "", &["2"], 1), node("2", "generic", "", &[], 2)];
        let mut cur = HashMap::new();
        cur.insert(2, Cursor { text: "Open menu".into(), flags: vec!["cursor:pointer".into(), "onclick".into()] });
        let mut refs = vec![];
        let mut n = 0;
        let (lines, _) = render(&nodes, &cur, &Opts { compact: true, ..Default::default() }, Some("S2"), &mut n, &mut refs, 0);
        let f = finish(lines, &refs, None, None, false, "");
        assert!(f.text.contains("generic \"Open menu\" [ref=e1] [cursor:cursor:pointer, onclick]"), "{}", f.text);
        assert_eq!(refs[0].1.session.as_deref(), Some("S2"));
        for (i, o) in [("e12", "e12"), ("@e12", "e12"), ("ref=e12", "e12"), ("[ref=e3]", "e3"), ("7", "e7")] {
            assert_eq!(normalize_ref(i).as_deref(), Some(o));
        }
        assert!(normalize_ref("x'); evil(").is_none() && normalize_ref("e").is_none());
        assert_eq!(query_lines("- button \"Save\" [ref=e1]\n- link \"Home\"", "SAVE button"), vec!["- button \"Save\" [ref=e1]"]);
        let dir = std::env::temp_dir().join(format!("ark-snap-{}", std::process::id()));
        let big = (0..500).map(|i| format!("- button \"b{i}\" [ref=e{i}]")).collect::<Vec<_>>().join("\n");
        let t = truncate_store(&big, 2000, &dir);
        assert!(t.len() <= 2000 && t.contains("more lines truncated — full snapshot: read path="), "{t}");
    }
}
