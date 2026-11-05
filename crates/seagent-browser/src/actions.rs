//! Page operations over CDP: snapshots, the OpenClaw act kinds (click, type, press,
//! hover, drag, select, fill, resize, wait, evaluate, close, batch), screenshots,
//! PDF, upload, download, console / requests / errors, page text and emulation.
//! Semantics and limits follow OpenClaw `client-actions*.ts`, `act-policy.ts`,
//! `screenshot.ts` and Hermes `browser_tool.py` (MIT).

use crate::engine::Browser;
use crate::keys;
use crate::snapshot::{self, Cursor, Opts, Ref};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const ACT_MAX_BATCH_ACTIONS: usize = 100;
pub const ACT_MAX_BATCH_DEPTH: usize = 5;
pub const ACT_MAX_CLICK_DELAY_MS: u64 = 5000;
pub const ACT_MAX_WAIT_TIME_MS: u64 = 30_000;
pub const ACT_MAX_VIEWPORT_DIMENSION: u64 = 8192;
pub const SCREENSHOT_MAX_SIDE: f64 = 2000.0;
pub const SCREENSHOT_MAX_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_LABELS: usize = 150;
pub const NAV_GRACE: Duration = Duration::from_millis(250);

/// Cursor-interactive discovery (OpenClaw cdp-role-snapshot-dom.ts).
const CURSOR_JS: &str = r#"(() => {
  const skipTags = new Set(['A','BUTTON','INPUT','SELECT','TEXTAREA','DETAILS','SUMMARY']);
  const roles = new Set(['button','checkbox','combobox','link','listbox','menuitem','menuitemcheckbox','menuitemradio','option','radio','searchbox','slider','spinbutton','switch','tab','textbox','treeitem']);
  const out = []; let n = 0;
  for (const el of document.querySelectorAll('body *')) {
    if (skipTags.has(el.tagName) || roles.has((el.getAttribute('role')||'').toLowerCase())) continue;
    if (el.closest('[hidden],[aria-hidden="true"]')) continue;
    const cs = getComputedStyle(el);
    const pointer = cs.cursor === 'pointer';
    const onclick = el.hasAttribute('onclick');
    const ti = el.getAttribute('tabindex');
    const tabindex = ti !== null && ti !== '-1';
    const ce = el.isContentEditable && (!el.parentElement || !el.parentElement.isContentEditable);
    if (!(pointer || onclick || tabindex || ce)) continue;
    if (pointer && !onclick && !tabindex && !ce && el.parentElement && getComputedStyle(el.parentElement).cursor === 'pointer') continue;
    const r = el.getBoundingClientRect(); if (r.width <= 0 || r.height <= 0) continue;
    const hidden = el.querySelector('input[type=checkbox],input[type=radio]');
    const flags = []; if (pointer) flags.push('cursor:pointer'); if (onclick) flags.push('onclick'); if (tabindex) flags.push('tabindex'); if (ce) flags.push('contenteditable');
    if (hidden && getComputedStyle(hidden).display === 'none') flags.push('hidden-' + hidden.type);
    el.setAttribute('data-seagent-ci', String(n));
    out.push({i: n, text: (el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 100), flags}); n++;
    if (n >= 200) break;
  }
  return out;
})()"#;
const CURSOR_CLEAN_JS: &str = "document.querySelectorAll('[data-seagent-ci]').forEach(e => e.removeAttribute('data-seagent-ci'))";

pub struct SnapshotReq {
    pub opts: Opts,
    pub max_chars: Option<usize>,
    pub selector: Option<String>,
    pub frame: Option<String>,
    pub delta: bool,
}

pub struct SnapshotOut {
    pub text: String,
    pub stats: Value,
    pub truncated: bool,
    pub new_elements: Option<usize>,
    pub url: String,
    pub title: String,
}

fn backend_of_selector(b: &Browser, target: &str, sid: &str, sel: &str) -> Result<i64, String> {
    let doc = b.session_call(target, sid, "DOM.getDocument", json!({"depth": 0}), b.timeout)?;
    let root = doc["root"]["nodeId"].as_i64().ok_or("DOM.getDocument returned no root")?;
    let n = b.session_call(target, sid, "DOM.querySelector", json!({"nodeId": root, "selector": sel}), b.timeout)?;
    let id = n["nodeId"].as_i64().filter(|i| *i > 0).ok_or_else(|| format!("no element matches selector `{sel}`"))?;
    let d = b.session_call(target, sid, "DOM.describeNode", json!({"nodeId": id}), b.timeout)?;
    d["node"]["backendNodeId"].as_i64().ok_or_else(|| "DOM.describeNode returned no backendNodeId".into())
}

fn cursor_scan(b: &Browser, target: &str, sid: &str) -> HashMap<i64, Cursor> {
    let mut out = HashMap::new();
    let Ok(found) = b.eval(target, CURSOR_JS) else { return out };
    let list = found.as_array().cloned().unwrap_or_default();
    if !list.is_empty() {
        if let Ok(doc) = b.session_call(target, sid, "DOM.getDocument", json!({"depth": 0}), b.timeout) {
            let root = doc["root"]["nodeId"].as_i64().unwrap_or(0);
            if let Ok(q) = b.session_call(target, sid, "DOM.querySelectorAll", json!({"nodeId": root, "selector": "[data-seagent-ci]"}), b.timeout) {
                for id in q["nodeIds"].as_array().into_iter().flatten().filter_map(|v| v.as_i64()) {
                    let Ok(d) = b.session_call(target, sid, "DOM.describeNode", json!({"nodeId": id}), b.timeout) else { continue };
                    let attrs = d["node"]["attributes"].as_array().cloned().unwrap_or_default();
                    let idx = attrs.chunks(2).find(|kv| kv[0] == "data-seagent-ci").and_then(|kv| kv.get(1)).and_then(|v| v.as_str()).and_then(|v| v.parse::<usize>().ok());
                    if let (Some(i), Some(bk)) = (idx, d["node"]["backendNodeId"].as_i64()) {
                        if let Some(e) = list.get(i) {
                            out.insert(bk, Cursor { text: e["text"].as_str().unwrap_or("").into(), flags: e["flags"].as_array().into_iter().flatten().filter_map(|f| f.as_str().map(str::to_string)).collect() });
                        }
                    }
                }
            }
        }
    }
    let _ = b.eval(target, CURSOR_CLEAN_JS);
    out
}

fn subtree(nodes: &[Value], root_backend: i64) -> Option<Vec<Value>> {
    let root = nodes.iter().find(|n| n["backendDOMNodeId"].as_i64() == Some(root_backend))?;
    let by: HashMap<&str, &Value> = nodes.iter().filter_map(|n| Some((n["nodeId"].as_str()?, n))).collect();
    let mut out = vec![];
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        out.push(n.clone());
        for c in n["childIds"].as_array().into_iter().flatten() {
            if let Some(k) = c.as_str().and_then(|c| by.get(c)) {
                stack.push(k);
            }
        }
    }
    // The scoped root must look like a root to `render`.
    let ids: std::collections::HashSet<String> = out.iter().filter_map(|n| n["nodeId"].as_str().map(str::to_string)).collect();
    for n in out.iter_mut() {
        if let Some(kids) = n["childIds"].as_array().cloned() {
            n["childIds"] = kids.into_iter().filter(|k| k.as_str().is_some_and(|k| ids.contains(k))).collect();
        }
    }
    Some(out)
}

/// Accessibility snapshot of a page (refs stored on the page for later actions).
pub fn snapshot(b: &Browser, target: &str, req: &SnapshotReq) -> Result<SnapshotOut, String> {
    let sid = b.attach(target)?;
    let _ = b.session_call(target, &sid, "Accessibility.enable", json!({}), Duration::from_secs(5));
    let mut session = sid.clone();
    let mut params = json!({});
    if let Some(fsel) = req.frame.as_deref().filter(|s| !s.is_empty()) {
        let bk = backend_of_selector(b, target, &sid, fsel)?;
        let d = b.session_call(target, &sid, "DOM.describeNode", json!({"backendNodeId": bk}), b.timeout)?;
        let fid = d["node"]["frameId"].as_str().or(d["node"]["contentDocument"]["frameId"].as_str()).ok_or("Snapshot frame identity is unavailable; retry.")?.to_string();
        let child = b.page(target, |p| p.frames.get(&fid).and_then(|f| f.session.clone()));
        match child {
            Some(c) => session = c,
            None => params["frameId"] = fid.into(),
        }
    }
    let cursor = if req.selector.is_none() && req.frame.is_none() { cursor_scan(b, target, &sid) } else { HashMap::new() };
    let tree = b.session_call(target, &session, "Accessibility.getFullAXTree", params, b.timeout)?;
    let mut nodes = tree["nodes"].as_array().cloned().unwrap_or_default();
    if let Some(sel) = req.selector.as_deref().filter(|s| !s.is_empty()) {
        let bk = backend_of_selector(b, target, &session, sel)?;
        nodes = subtree(&nodes, bk).ok_or("Snapshot root is no longer present in the accessibility tree; retry.")?;
    }
    let mut refs: Vec<(String, Ref)> = vec![];
    let mut counter = 0;
    let child_sess = (session != sid).then_some(session.as_str());
    let (lines, mut too_deep) = snapshot::render(&nodes, &cursor, &req.opts, child_sess, &mut counter, &mut refs, 0);
    // Splice child frames (one level).
    let mut all = Vec::with_capacity(lines.len());
    for l in lines {
        let iframe = l.iframe;
        let depth = l.depth;
        all.push(l);
        let Some(bk) = iframe.filter(|_| req.frame.is_none()) else { continue };
        let Ok(d) = b.session_call(target, &sid, "DOM.describeNode", json!({"backendNodeId": bk}), Duration::from_secs(5)) else { continue };
        let Some(fid) = d["node"]["frameId"].as_str().or(d["node"]["contentDocument"]["frameId"].as_str()).map(str::to_string) else { continue };
        let child = b.page(target, |p| p.frames.get(&fid).and_then(|f| f.session.clone()));
        let (s2, p2) = match &child {
            Some(c) => (c.clone(), json!({})),
            None => (sid.clone(), json!({"frameId": fid})),
        };
        if let Ok(t) = b.session_call(target, &s2, "Accessibility.getFullAXTree", p2, Duration::from_secs(10)) {
            let sub = t["nodes"].as_array().cloned().unwrap_or_default();
            let (more, deep) = snapshot::render(&sub, &HashMap::new(), &req.opts, child.as_deref(), &mut counter, &mut refs, depth + 1);
            too_deep |= deep;
            all.extend(more);
        }
    }
    snapshot::assign_nth(&mut refs);
    let prev = if req.delta { b.page(target, |p| p.prev_keys.clone()) } else { None };
    let empty = if req.opts.interactive { "(no interactive elements)" } else if req.selector.is_some() { "(empty)" } else { "(empty page)" };
    let mut f = snapshot::finish(all, &refs, prev.as_ref(), req.max_chars, too_deep, empty);
    if req.opts.urls {
        let links: Vec<String> = refs.iter().filter(|(id, r)| f.visible_refs.contains(id) && r.role.eq_ignore_ascii_case("link")).filter_map(|(id, r)| f.text.lines().find(|l| l.contains(&format!("[ref={id}]"))).and_then(|l| l.split("[url=").nth(1)).map(|u| (r.name.clone(), u.split(']').next().unwrap_or("").to_string()))).enumerate().map(|(i, (n, u))| format!("{}. {n} -> {u}", i + 1)).collect();
        if !links.is_empty() {
            f.text.push_str(&format!("\n\nLinks:\n{}", links.join("\n")));
        }
    }
    let visible = f.visible_refs.clone();
    let keys = f.keys.clone();
    b.page(target, |p| {
        p.refs = refs.into_iter().filter(|(id, _)| visible.contains(id)).collect();
        p.prev_keys = Some(keys);
    });
    let (url, title) = b.url_title(target);
    Ok(SnapshotOut { text: f.text, stats: f.stats, truncated: f.truncated, new_elements: f.new_elements, url, title })
}

/// A resolved element: CDP session + backend node id.
pub struct El {
    pub session: String,
    pub backend: i64,
    pub child: bool,
}

pub fn element(b: &Browser, target: &str, r: Option<&str>, selector: Option<&str>) -> Result<El, String> {
    let sid = b.attach(target)?;
    if let Some(r) = r.filter(|r| !r.trim().is_empty()) {
        let id = snapshot::normalize_ref(r).ok_or_else(|| format!("bad ref `{r}` (use a ref like e12 from the latest snapshot)"))?;
        let rf = b.page(target, |p| p.refs.get(&id).cloned()).ok_or_else(|| format!("Unknown ref \"{id}\". Take a new snapshot; refs are only valid for the latest snapshot of this tab."))?;
        let child = rf.session.is_some();
        return Ok(El { session: rf.session.unwrap_or(sid), backend: rf.backend, child });
    }
    if let Some(sel) = selector.filter(|s| !s.trim().is_empty()) {
        return Ok(El { backend: backend_of_selector(b, target, &sid, sel)?, session: sid, child: false });
    }
    Err("requires ref or selector".into())
}

fn object_id(b: &Browser, target: &str, el: &El) -> Result<String, String> {
    let r = b.session_call(target, &el.session, "DOM.resolveNode", json!({"backendNodeId": el.backend}), b.timeout).map_err(|e| if e.contains("No node") || e.contains("not found") { "element is gone; take a new snapshot".to_string() } else { e })?;
    r["object"]["objectId"].as_str().map(str::to_string).ok_or_else(|| "element is gone; take a new snapshot".into())
}

/// Call `function(...)` with `this` = the element.
pub fn call_on(b: &Browser, target: &str, el: &El, func: &str, args: Vec<Value>) -> Result<Value, String> {
    let oid = object_id(b, target, el)?;
    let r = b.session_call(target, &el.session, "Runtime.callFunctionOn", json!({"objectId": oid, "functionDeclaration": func, "arguments": args.into_iter().map(|a| json!({"value": a})).collect::<Vec<_>>(), "returnByValue": true, "awaitPromise": true, "userGesture": true}), b.timeout)?;
    if let Some(e) = r.get("exceptionDetails") {
        return Err(format!("page script failed: {}", crate::util::cut(e["exception"]["description"].as_str().or(e["text"].as_str()).unwrap_or("exception"), 600)));
    }
    Ok(r["result"]["value"].clone())
}

/// Viewport center of an element (scrolled into view first).
pub fn center(b: &Browser, target: &str, el: &El) -> Result<(f64, f64), String> {
    let _ = b.session_call(target, &el.session, "DOM.scrollIntoViewIfNeeded", json!({"backendNodeId": el.backend}), b.timeout);
    let q = b.session_call(target, &el.session, "DOM.getContentQuads", json!({"backendNodeId": el.backend}), b.timeout);
    let quad = q.ok().and_then(|q| q["quads"].as_array().and_then(|a| a.first().cloned()));
    let quad = match quad {
        Some(q) => q,
        None => b.session_call(target, &el.session, "DOM.getBoxModel", json!({"backendNodeId": el.backend}), b.timeout).map_err(|_| "element is not visible (no layout box); scroll or take a new snapshot".to_string())?["model"]["content"].clone(),
    };
    let v: Vec<f64> = quad.as_array().ok_or("element has no box")?.iter().filter_map(|x| x.as_f64()).collect();
    if v.len() < 8 {
        return Err("element has no box".into());
    }
    Ok(((v[0] + v[2] + v[4] + v[6]) / 4.0, (v[1] + v[3] + v[5] + v[7]) / 4.0))
}

/// The button / click-count / modifier triple that CDP mouse events carry.
#[derive(Clone, Copy)]
pub struct Click<'a> {
    pub button: &'a str,
    pub count: i64,
    pub modifiers: i64,
}

impl Click<'_> {
    /// A bare pointer move: no button pressed, no click count.
    pub const MOVE: Click<'static> = Click { button: "none", count: 0, modifiers: 0 };
}

pub fn mouse(b: &Browser, target: &str, ty: &str, x: f64, y: f64, click: Click<'_>) -> Result<(), String> {
    let mut p = json!({"type": ty, "x": x, "y": y, "modifiers": click.modifiers});
    if ty != "mouseMoved" {
        p["button"] = click.button.into();
        p["clickCount"] = click.count.into();
    }
    b.page_call(target, "Input.dispatchMouseEvent", p).map(|_| ())
}

pub fn click_at(b: &Browser, target: &str, x: f64, y: f64, click: Click<'_>, hold: Duration) -> Result<(), String> {
    mouse(b, target, "mouseMoved", x, y, Click { button: "none", count: 0, modifiers: click.modifiers })?;
    for c in 1..=click.count {
        let pressed = Click { count: c, ..click };
        mouse(b, target, "mousePressed", x, y, pressed)?;
        if !hold.is_zero() {
            std::thread::sleep(hold);
        }
        mouse(b, target, "mouseReleased", x, y, pressed)?;
    }
    Ok(())
}

pub fn press(b: &Browser, target: &str, chord: &str) -> Result<(), String> {
    for ev in keys::chord_events(chord)? {
        b.page_call(target, "Input.dispatchKeyEvent", ev)?;
    }
    Ok(())
}

pub fn insert_text(b: &Browser, target: &str, text: &str) -> Result<(), String> {
    b.page_call(target, "Input.insertText", json!({"text": text})).map(|_| ()).map_err(|e| if e == crate::engine::BLOCKED_BY_DIALOG { e } else { "Unable to paste text into the browser. Focus an editable field and try again.".into() })
}

const SELECT_ALL_FN: &str = "function(){ this.focus(); if (typeof this.select === 'function' && 'value' in this) { this.select(); return 'value'; } if (this.isContentEditable) { const r = document.createRange(); r.selectNodeContents(this); const s = getSelection(); s.removeAllRanges(); s.addRange(r); return 'editable'; } return 'other'; }";

/// Clear and type (Playwright `fill`): focus, select all, insert (or delete).
pub fn fill_text(b: &Browser, target: &str, el: &El, text: &str) -> Result<(), String> {
    let kind = call_on(b, target, el, SELECT_ALL_FN, vec![])?;
    if kind == "other" {
        let _ = b.session_call(target, &el.session, "DOM.focus", json!({"backendNodeId": el.backend}), b.timeout);
    }
    if text.is_empty() {
        press(b, target, "Delete")?;
        call_on(b, target, el, "function(){ if ('value' in this && this.value) { this.value=''; this.dispatchEvent(new Event('input',{bubbles:true})); this.dispatchEvent(new Event('change',{bubbles:true})); } }", vec![])?;
        return Ok(());
    }
    if el.child {
        // OOPIF elements: Input domain events go to the main frame; set the value in the frame.
        call_on(b, target, el, "function(t){ if ('value' in this) { this.value = t; } else { this.textContent = t; } this.dispatchEvent(new Event('input',{bubbles:true})); this.dispatchEvent(new Event('change',{bubbles:true})); }", vec![json!(text)])?;
        return Ok(());
    }
    insert_text(b, target, text)
}

fn click_el(b: &Browser, target: &str, el: &El, button: &str, count: i64, modifiers: i64, delay: Duration) -> Result<(), String> {
    if el.child {
        call_on(b, target, el, "function(){ this.scrollIntoView({block:'center'}); this.click(); }", vec![])?;
        return Ok(());
    }
    let (x, y) = center(b, target, el)?;
    if !delay.is_zero() {
        mouse(b, target, "mouseMoved", x, y, Click { button: "none", count: 0, modifiers })?;
        std::thread::sleep(delay);
    }
    click_at(b, target, x, y, Click { button, count, modifiers }, Duration::ZERO)
}

/// OpenClaw evaluate-source normalization: function expressions run as is, statements
/// become an async body, other expressions are wrapped so a returned function is called.
pub fn normalize_fn(src: &str) -> String {
    let s = src.trim().trim_end_matches(';').trim();
    let is_fn = s.starts_with("function") || s.starts_with("async function") || {
        let head = s.split("=>").next().unwrap_or("");
        s.contains("=>") && (head.trim_start().starts_with('(') || head.trim_start().starts_with("async") || head.trim().chars().all(|c| c.is_alphanumeric() || c == '_' || c == '$')) && !head.contains(';') && !head.contains('\n')
    };
    if is_fn {
        return s.to_string();
    }
    let statements = s.contains(';') || s.contains('\n') || ["return ", "const ", "let ", "var ", "if (", "for (", "while (", "await "].iter().any(|k| s.starts_with(k) || s.contains(&format!("\n{k}")));
    if statements {
        format!("async (el) => {{\n{s}\n}}")
    } else {
        format!("(el) => {{ const r = ({s}); return typeof r === \"function\" ? r(el) : r; }}")
    }
}

pub fn evaluate(b: &Browser, target: &str, fn_src: &str, r: Option<&str>, timeout_ms: u64) -> Result<Value, String> {
    let f = normalize_fn(fn_src);
    let t = timeout_ms.clamp(1500, 120_500) - 500;
    let race = |call: &str| format!("Promise.race([Promise.resolve().then(() => {call}), new Promise((_, rej) => setTimeout(() => rej(new Error('evaluate timed out after {t}ms')), {t}))])");
    if r.is_some() {
        let el = element(b, target, r, None)?;
        return call_on(b, target, &el, &format!("function(){{ const el = this; return {}; }}", race(&format!("({f})(el)"))), vec![]);
    }
    b.eval(target, &race(&format!("({f})(undefined)")))
}

fn glob_match(pat: &str, s: &str) -> bool {
    if !pat.contains('*') {
        return s == pat || s.trim_end_matches('/') == pat.trim_end_matches('/');
    }
    let re = regex::escape(pat).replace(r"\*\*", ".*").replace(r"\*", "[^/]*");
    regex::Regex::new(&format!("^{re}$")).is_ok_and(|r| r.is_match(s))
}

pub struct Act<'a> {
    pub b: &'a Browser,
    pub target: String,
    pub evaluate_enabled: bool,
}

fn s<'v>(v: &'v Value, k: &str) -> Option<&'v str> {
    v[k].as_str().filter(|x| !x.is_empty())
}

fn act_timeout(v: &Value, default: u64, lo: u64, hi: u64) -> Duration {
    Duration::from_millis(v["timeoutMs"].as_u64().unwrap_or(default).clamp(lo, hi))
}

impl Act<'_> {
    /// One act request; returns the result object.
    pub fn run(&self, req: &Value, depth: usize) -> Result<Value, String> {
        let b = self.b;
        let t = self.target.as_str();
        let kind = s(req, "kind").ok_or("act requires kind")?;
        let rf = s(req, "ref");
        let sel = s(req, "selector");
        let need_el = || element(b, t, rf, sel).map_err(|e| if e == "requires ref or selector" { format!("{kind} requires ref or selector") } else { e });
        match kind {
            "click" => {
                let button = s(req, "button").unwrap_or("left");
                if !matches!(button, "left" | "right" | "middle") {
                    return Err("click button must be left|right|middle".into());
                }
                let mods = keys::mouse_modifiers(&strs(&req["modifiers"]))?;
                let delay = req["delayMs"].as_i64().unwrap_or(0);
                if delay < 0 {
                    return Err("click delayMs must be >= 0".into());
                }
                if delay as u64 > ACT_MAX_CLICK_DELAY_MS {
                    return Err("click delayMs exceeds maximum of 5000ms".into());
                }
                let el = need_el()?;
                click_el(b, t, &el, button, if req["doubleClick"] == true { 2 } else { 1 }, mods, Duration::from_millis(delay as u64))?;
                Ok(json!({"ok": true}))
            }
            "clickCoords" => {
                let (x, y) = (req["x"].as_f64().unwrap_or(-1.0), req["y"].as_f64().unwrap_or(-1.0));
                if x < 0.0 || y < 0.0 {
                    return Err("clickCoords requires non-negative x and y".into());
                }
                let button = s(req, "button").unwrap_or("left");
                let delay = req["delayMs"].as_u64().unwrap_or(0).min(ACT_MAX_CLICK_DELAY_MS);
                click_at(b, t, x, y, Click { button, count: if req["doubleClick"] == true { 2 } else { 1 }, modifiers: 0 }, Duration::from_millis(delay))?;
                Ok(json!({"ok": true, "x": x, "y": y}))
            }
            "type" => {
                let text = req["text"].as_str().ok_or("type requires text")?;
                let el = need_el()?;
                if req["slowly"] == true {
                    click_el(b, t, &el, "left", 1, 0, Duration::ZERO)?;
                    for ch in text.chars() {
                        let c = ch.to_string();
                        match keys::chord_events(if c == "+" { "+" } else { &c }) {
                            Ok(evs) if ch.is_ascii() && !ch.is_control() => {
                                for e in evs {
                                    b.page_call(t, "Input.dispatchKeyEvent", e)?;
                                }
                            }
                            _ => insert_text(b, t, &c)?,
                        }
                        std::thread::sleep(Duration::from_millis(75));
                    }
                } else {
                    fill_text(b, t, &el, text)?;
                }
                if req["submit"] == true {
                    press(b, t, "Enter")?;
                }
                Ok(json!({"ok": true}))
            }
            "press" => {
                let key = req["key"].as_str().filter(|k| !k.is_empty()).ok_or("press requires key")?;
                let key = if key == " " { "Space" } else { key };
                if let Some(d) = req["delayMs"].as_u64().filter(|d| *d > 0) {
                    std::thread::sleep(Duration::from_millis(d.min(ACT_MAX_CLICK_DELAY_MS)));
                }
                press(b, t, key)?;
                Ok(json!({"ok": true}))
            }
            "insertText" => {
                insert_text(b, t, req["text"].as_str().ok_or("insertText requires text")?)?;
                Ok(json!({"ok": true}))
            }
            "hover" => {
                let el = need_el()?;
                let (x, y) = center(b, t, &el)?;
                mouse(b, t, "mouseMoved", x, y, Click::MOVE)?;
                Ok(json!({"ok": true}))
            }
            "scrollIntoView" => {
                let el = need_el()?;
                b.session_call(t, &el.session, "DOM.scrollIntoViewIfNeeded", json!({"backendNodeId": el.backend}), act_timeout(req, 20_000, 500, 60_000))?;
                Ok(json!({"ok": true}))
            }
            "drag" => {
                let from = element(b, t, s(req, "startRef"), s(req, "startSelector")).map_err(|_| "drag requires startRef or startSelector".to_string())?;
                let to = element(b, t, s(req, "endRef"), s(req, "endSelector")).map_err(|_| "drag requires endRef or endSelector".to_string())?;
                let (x1, y1) = center(b, t, &from)?;
                let (x2, y2) = center(b, t, &to)?;
                mouse(b, t, "mouseMoved", x1, y1, Click::MOVE)?;
                mouse(b, t, "mousePressed", x1, y1, Click { button: "left", count: 1, modifiers: 0 })?;
                for i in 1..=10 {
                    let f = i as f64 / 10.0;
                    let mut p = json!({"type": "mouseMoved", "x": x1 + (x2 - x1) * f, "y": y1 + (y2 - y1) * f, "buttons": 1});
                    p["modifiers"] = 0.into();
                    b.page_call(t, "Input.dispatchMouseEvent", p)?;
                }
                mouse(b, t, "mouseReleased", x2, y2, Click { button: "left", count: 1, modifiers: 0 })?;
                Ok(json!({"ok": true}))
            }
            "select" => {
                let values = strs(&req["values"]);
                if req["values"].as_array().is_none() || (rf.is_none() && sel.is_none()) {
                    return Err("select requires ref/selector and values".into());
                }
                let el = need_el()?;
                let r = call_on(b, t, &el, "function(vals){ if (this.tagName !== 'SELECT') throw new Error('Element is not a <select> element'); vals = Array.isArray(vals) ? vals.map(String) : [String(vals)]; const opts = Array.from(this.options); const match = opts.filter(o => vals.includes(o.value) || vals.includes(o.label) || vals.includes(o.textContent.trim())); const pick = this.multiple ? match : match.slice(0, 1); for (const o of opts) o.selected = pick.includes(o); const hit = pick.map(o => o.value); if (vals.length && !hit.length) throw new Error('no option matches ' + JSON.stringify(vals)); this.dispatchEvent(new Event('input', {bubbles: true})); this.dispatchEvent(new Event('change', {bubbles: true})); return hit; }", vec![json!(values)])?;
                Ok(json!({"ok": true, "selected": r}))
            }
            "fill" => {
                let fields = req["fields"].as_array().filter(|f| !f.is_empty()).ok_or("fill requires fields")?;
                for (i, f) in fields.iter().enumerate() {
                    let obj = f.as_object().ok_or_else(|| format!("fields[{i}] must be an object"))?;
                    if let Some(k) = obj.keys().find(|k| !["ref", "type", "value"].contains(&k.as_str())) {
                        return Err(format!("fields[{i}] unsupported field key \"{k}\"; supported keys are ref, type, value"));
                    }
                    let r = f["ref"].as_str().filter(|r| !r.is_empty()).ok_or_else(|| format!("fields[{i}] must include ref"))?;
                    let ty = f["type"].as_str().unwrap_or("text");
                    let value = match &f["value"] {
                        Value::Null => String::new(),
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => return Err(format!("fields[{i}] value must be a string, number, boolean, or null")),
                    };
                    let el = element(b, t, Some(r), None)?;
                    if ty == "checkbox" || ty == "radio" {
                        let want = matches!(value.as_str(), "true" | "1");
                        let cur = call_on(b, t, &el, "function(){ return !!this.checked || this.getAttribute('aria-checked') === 'true'; }", vec![])?;
                        if cur.as_bool() != Some(want) {
                            click_el(b, t, &el, "left", 1, 0, Duration::ZERO)?;
                        }
                    } else {
                        fill_text(b, t, &el, &value)?;
                    }
                }
                Ok(json!({"ok": true, "filled": fields.len()}))
            }
            "resize" => {
                let (w, h) = (req["width"].as_u64().unwrap_or(0), req["height"].as_u64().unwrap_or(0));
                if w == 0 || h == 0 {
                    return Err("resize requires positive width and height".into());
                }
                if w > ACT_MAX_VIEWPORT_DIMENSION || h > ACT_MAX_VIEWPORT_DIMENSION {
                    return Err("resize width and height must not exceed 8192".into());
                }
                b.page_call(t, "Emulation.setDeviceMetricsOverride", json!({"width": w, "height": h, "deviceScaleFactor": 0, "mobile": false}))?;
                Ok(json!({"ok": true, "width": w, "height": h}))
            }
            "wait" => self.wait(req),
            "evaluate" => {
                if !self.evaluate_enabled {
                    return Err("act:evaluate is disabled by config (browser.evaluate_enabled=false)".into());
                }
                let f = s(req, "fn").ok_or("evaluate requires fn")?;
                let v = evaluate(b, t, f, rf, req["timeoutMs"].as_u64().unwrap_or(20_000))?;
                Ok(json!({"ok": true, "result": crate::policy::redact_json(&v)}))
            }
            "close" => {
                b.close_tab(t)?;
                Ok(json!({"ok": true, "closed": t}))
            }
            "batch" => self.batch(req, depth),
            other => Err(format!("unknown act kind `{other}` (batch, click, clickCoords, type, press, hover, scrollIntoView, drag, select, fill, resize, wait, evaluate, close)")),
        }
    }

    fn wait(&self, req: &Value) -> Result<Value, String> {
        let (b, t) = (self.b, self.target.as_str());
        let has = ["text", "textGone", "selector", "url", "loadState", "fn"].iter().any(|k| s(req, k).is_some());
        if req["timeMs"].is_null() && !has {
            return Err("wait requires at least one of: timeMs, text, textGone, selector, url, loadState, fn".into());
        }
        if s(req, "fn").is_some() && !self.evaluate_enabled {
            return Err("wait --fn is disabled by config (browser.evaluate_enabled=false)".into());
        }
        if let Some(ms) = req["timeMs"].as_u64() {
            if ms > ACT_MAX_WAIT_TIME_MS {
                return Err(format!("wait timeMs exceeds maximum of {ACT_MAX_WAIT_TIME_MS}ms"));
            }
            std::thread::sleep(Duration::from_millis(ms));
        }
        let timeout = act_timeout(req, 20_000, 500, 120_000);
        let poll = |what: &str, js: String| -> Result<(), String> {
            let until = Instant::now() + timeout;
            loop {
                if b.eval(t, &js).ok().and_then(|v| v.as_bool()) == Some(true) {
                    return Ok(());
                }
                if Instant::now() >= until {
                    return Err(format!("wait for {what} timed out after {}ms", timeout.as_millis()));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        let q = |x: &str| crate::util::json_str(x);
        if let Some(x) = s(req, "text") {
            poll(&format!("text {}", q(x)), format!("(document.body && document.body.innerText || '').includes({})", q(x)))?;
        }
        if let Some(x) = s(req, "textGone") {
            poll(&format!("text {} to disappear", q(x)), format!("!(document.body && document.body.innerText || '').includes({})", q(x)))?;
        }
        if let Some(x) = s(req, "selector") {
            poll(&format!("selector {}", q(x)), format!("(e => !!e && e.getClientRects().length > 0 && getComputedStyle(e).visibility !== 'hidden')(document.querySelector({}))", q(x)))?;
        }
        if let Some(u) = s(req, "url") {
            let until = Instant::now() + timeout;
            while !glob_match(u, &b.url_title(t).0) {
                if Instant::now() >= until {
                    return Err(format!("wait for url {u} timed out after {}ms", timeout.as_millis()));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        match s(req, "loadState") {
            None => {}
            Some("load") => poll("load", "document.readyState === 'complete'".into())?,
            Some("domcontentloaded") => poll("domcontentloaded", "document.readyState !== 'loading'".into())?,
            Some("networkidle") => {
                if !b.wait_network_idle(t, timeout) {
                    return Err(format!("wait for networkidle timed out after {}ms", timeout.as_millis()));
                }
            }
            Some(o) => return Err(format!("loadState must be load|domcontentloaded|networkidle, got {o}")),
        }
        if let Some(f) = s(req, "fn") {
            let src = normalize_fn(f);
            poll("fn", format!("Promise.resolve(({src})(document)).then(v => !!v)"))?;
        }
        Ok(json!({"ok": true}))
    }

    fn batch(&self, req: &Value, depth: usize) -> Result<Value, String> {
        let actions = req["actions"].as_array().filter(|a| !a.is_empty()).ok_or(if depth > 0 { "batch requires actions" } else { "actions are required" })?;
        if depth + 1 > ACT_MAX_BATCH_DEPTH {
            return Err(format!("batch nesting exceeds maximum depth of {ACT_MAX_BATCH_DEPTH}"));
        }
        if count_actions(actions) > ACT_MAX_BATCH_ACTIONS {
            return Err(format!("batch exceeds maximum of {ACT_MAX_BATCH_ACTIONS} actions"));
        }
        let stop = req["stopOnError"] != false;
        let mut results = vec![];
        let mut aborted = None;
        for (i, a) in actions.iter().enumerate() {
            if let Some(tid) = s(a, "targetId") {
                if tid != self.target {
                    return Err("batched action targetId must match request targetId".into());
                }
            }
            let nav0 = self.b.page(&self.target, |p| p.nav_seq);
            let r = self.run(a, depth + 1);
            std::thread::sleep(NAV_GRACE);
            let (nav1, closed) = self.b.page(&self.target, |p| (p.nav_seq, p.closed));
            let mut entry = match r {
                Ok(_) => json!({"ok": true}),
                Err(e) if e == crate::engine::BLOCKED_BY_DIALOG => return Err(e),
                Err(e) => json!({"ok": false, "error": e}),
            };
            let failed = entry["ok"] == false;
            let navigated = nav1 > nav0;
            if navigated {
                entry["navigated"] = true.into();
                entry["url"] = self.b.page(&self.target, |p| p.url.clone()).into();
            }
            results.push(entry);
            let skipped = actions.len() - i - 1;
            if (navigated || closed || a["kind"] == "close") && skipped > 0 {
                aborted = Some(json!({"reason": if navigated { "navigation" } else { "closed" }, "afterAction": i + 1, "url": self.b.page(&self.target, |p| p.url.clone()), "skipped": skipped}));
                break;
            }
            if failed && stop {
                break;
            }
        }
        let mut out = json!({"ok": results.iter().all(|r| r["ok"] == true), "results": results});
        if let Some(a) = aborted {
            out["aborted"] = a;
        }
        Ok(out)
    }
}

fn count_actions(a: &[Value]) -> usize {
    a.iter().map(|x| 1 + x["actions"].as_array().map(|n| count_actions(n)).unwrap_or(0)).sum()
}

pub fn strs(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().filter_map(|x| x.as_str().map(str::to_string)).collect()
}

// ---- screenshots, pdf ----

pub struct Shot {
    pub data: Vec<u8>,
    pub format: String,
    pub labels: usize,
    pub skipped: usize,
    pub annotations: Vec<Value>,
}

const LABEL_JS: &str = r#"(boxes) => { const root = document.createElement('div'); root.id = '__seagent-annotations__'; root.setAttribute('data-seagent-labels', '1'); root.style.cssText = 'position:fixed;inset:0;pointer-events:none;z-index:2147483647'; for (const b of boxes) { const d = document.createElement('div'); d.style.cssText = `position:fixed;left:${b.x}px;top:${b.y}px;width:${b.w}px;height:${b.h}px;border:2px solid #ffb020;box-sizing:border-box`; const tag = document.createElement('div'); tag.textContent = b.ref; tag.style.cssText = 'position:absolute;left:-2px;top:-16px;background:#ffb020;color:#1a1a1a;font:bold 11px/14px monospace;padding:0 3px'; d.appendChild(tag); root.appendChild(d); } document.documentElement.appendChild(root); return boxes.length; }"#;

pub fn screenshot(b: &Browser, target: &str, full_page: bool, el_ref: Option<&str>, el_sel: Option<&str>, jpeg: bool, labels: bool) -> Result<Shot, String> {
    if full_page && (el_ref.is_some() || el_sel.is_some()) {
        return Err("fullPage is not supported for element screenshots".into());
    }
    b.attach(target)?;
    let lm = b.page_call(target, "Page.getLayoutMetrics", json!({}))?;
    let vw = lm["cssLayoutViewport"]["clientWidth"].as_f64().unwrap_or(1280.0);
    let vh = lm["cssLayoutViewport"]["clientHeight"].as_f64().unwrap_or(800.0);
    let mut clip: Option<(f64, f64, f64, f64)> = None;
    if full_page {
        let cs = &lm["cssContentSize"];
        clip = Some((0.0, 0.0, cs["width"].as_f64().unwrap_or(vw), cs["height"].as_f64().unwrap_or(vh)));
    } else if el_ref.is_some() || el_sel.is_some() {
        let el = element(b, target, el_ref, el_sel)?;
        let _ = b.session_call(target, &el.session, "DOM.scrollIntoViewIfNeeded", json!({"backendNodeId": el.backend}), b.timeout);
        let bm = b.session_call(target, &el.session, "DOM.getBoxModel", json!({"backendNodeId": el.backend}), b.timeout)?;
        let v: Vec<f64> = bm["model"]["border"].as_array().into_iter().flatten().filter_map(|x| x.as_f64()).collect();
        if v.len() < 8 {
            return Err("element has no box".into());
        }
        let (xs, ys) = ([v[0], v[2], v[4], v[6]], [v[1], v[3], v[5], v[7]]);
        let (x0, y0) = (xs.iter().cloned().fold(f64::MAX, f64::min), ys.iter().cloned().fold(f64::MAX, f64::min));
        let (x1, y1) = (xs.iter().cloned().fold(f64::MIN, f64::max), ys.iter().cloned().fold(f64::MIN, f64::max));
        let sx = lm["cssVisualViewport"]["pageX"].as_f64().unwrap_or(0.0);
        let sy = lm["cssVisualViewport"]["pageY"].as_f64().unwrap_or(0.0);
        clip = Some((x0 + sx, y0 + sy, (x1 - x0).max(1.0), (y1 - y0).max(1.0)));
    }
    let (mut count, mut skipped, mut annotations) = (0, 0, vec![]);
    if labels {
        let refs: Vec<(String, Ref)> = b.page(target, |p| {
            let mut v: Vec<(String, Ref)> = p.refs.iter().map(|(k, r)| (k.clone(), r.clone())).collect();
            v.sort_by_key(|(k, _)| k[1..].parse::<u64>().unwrap_or(0));
            v
        });
        let mut boxes = vec![];
        for (id, r) in refs.iter().filter(|(_, r)| r.session.is_none()) {
            if boxes.len() >= MAX_LABELS {
                skipped += 1;
                continue;
            }
            let q = b.page_call(target, "DOM.getContentQuads", json!({"backendNodeId": r.backend})).ok();
            let Some(v) = q.and_then(|q| q["quads"][0].as_array().map(|a| a.iter().filter_map(|x| x.as_f64()).collect::<Vec<_>>())).filter(|v| v.len() == 8) else {
                skipped += 1;
                continue;
            };
            let (x, y) = (v[0].min(v[6]), v[1].min(v[3]));
            let (w, h) = ((v[2] - v[0]).abs().max(1.0), (v[5] - v[3]).abs().max(1.0));
            if x + w < 0.0 || y + h < 0.0 || x > vw || y > vh {
                skipped += 1;
                continue;
            }
            boxes.push(json!({"ref": id, "x": x, "y": y, "w": w, "h": h}));
            annotations.push(json!({"ref": id, "role": r.role, "name": r.name, "box": {"x": x, "y": y, "width": w, "height": h}}));
        }
        count = boxes.len();
        b.eval(target, &format!("({LABEL_JS})({})", Value::Array(boxes)))?;
    }
    let capture = |fmt: &str, quality: Option<u64>, scale: f64| -> Result<Vec<u8>, String> {
        let mut p = json!({"format": fmt, "captureBeyondViewport": full_page});
        if let Some(q) = quality {
            p["quality"] = q.into();
        }
        let (x, y, w, h) = clip.unwrap_or((lm["cssVisualViewport"]["pageX"].as_f64().unwrap_or(0.0), lm["cssVisualViewport"]["pageY"].as_f64().unwrap_or(0.0), vw, vh));
        if clip.is_some() || scale < 1.0 {
            p["clip"] = json!({"x": x, "y": y, "width": w, "height": h, "scale": scale});
        }
        let r = b.session_call(target, &b.attach(target)?, "Page.captureScreenshot", p, Duration::from_secs(20).max(b.timeout))?;
        seagent_net::crypto::b64_decode(r["data"].as_str().ok_or("Page.captureScreenshot returned no data")?).ok_or_else(|| "bad screenshot data".into())
    };
    let (w, h) = clip.map(|c| (c.2, c.3)).unwrap_or((vw, vh));
    let dpr = lm["visualViewport"]["clientWidth"].as_f64().map(|px| px / vw).filter(|d| *d > 0.0).unwrap_or(1.0);
    let scale = (SCREENSHOT_MAX_SIDE / (w.max(h) * dpr)).min(1.0);
    let mut fmt = if jpeg { "jpeg" } else { "png" }.to_string();
    let result = (|| {
        let mut data = capture(&fmt, jpeg.then_some(85), scale)?;
        for q in [85, 70, 55, 40] {
            if data.len() <= SCREENSHOT_MAX_BYTES {
                break;
            }
            fmt = "jpeg".into();
            data = capture("jpeg", Some(q), scale)?;
        }
        Ok::<_, String>(data)
    })();
    if labels {
        let _ = b.eval(target, "document.getElementById('__seagent-annotations__')?.remove()");
    }
    Ok(Shot { data: result?, format: fmt, labels: count, skipped, annotations })
}

pub fn pdf(b: &Browser, target: &str) -> Result<Vec<u8>, String> {
    let sid = b.attach(target)?;
    let r = b.session_call(target, &sid, "Page.printToPDF", json!({"printBackground": true, "preferCSSPageSize": true}), Duration::from_secs(60))?;
    seagent_net::crypto::b64_decode(r["data"].as_str().ok_or("Page.printToPDF returned no data")?).ok_or_else(|| "bad PDF data".into())
}

// ---- text, images, logs ----

pub fn page_text(b: &Browser, target: &str, selector: Option<&str>, max: usize) -> Result<(String, bool), String> {
    let sel = crate::util::json_str(selector.unwrap_or(""));
    let js = format!("(() => {{ const s = {sel}; const el = (s && document.querySelector(s)) || document.querySelector('article') || document.querySelector('main') || document.body; if (s && !document.querySelector(s)) throw new Error('no element matches selector ' + s); return el ? el.innerText : ''; }})()");
    let v = b.eval(target, &js)?;
    let t = v.as_str().unwrap_or("").to_string();
    Ok(if t.len() > max { (crate::util::cut(&t, max).to_string(), true) } else { (t, false) })
}

pub const GET_IMAGES_JS: &str = "[...document.images].map(img => ({src: img.src, alt: img.alt || '', width: img.naturalWidth, height: img.naturalHeight})).filter(img => img.src && !img.src.startsWith('data:'))";

fn level_rank(l: &str) -> u8 {
    match l {
        "error" => 3,
        "warn" | "warning" => 2,
        "debug" | "verbose" => 0,
        _ => 1,
    }
}

pub fn console(b: &Browser, target: &str, level: Option<&str>, clear: bool) -> Vec<Value> {
    b.page(target, |p| {
        let min = level.map(level_rank).unwrap_or(0);
        let v: Vec<Value> = p.console.iter().filter(|m| level_rank(m["type"].as_str().unwrap_or("log")) >= min).map(crate::policy::redact_json).collect();
        if clear {
            p.console.clear();
        }
        v
    })
}

/// requests / errors with limit + "drop oldest until it fits".
pub fn debug_log(b: &Browser, target: &str, kind: &str, filter: Option<&str>, limit: usize, clear: bool) -> Value {
    b.page(target, |p| {
        let src = if kind == "requests" { &mut p.requests } else { &mut p.errors };
        let f = filter.map(|f| f.to_ascii_lowercase());
        let mut all: Vec<Value> = src.iter().filter(|r| f.as_ref().is_none_or(|f| r["url"].as_str().unwrap_or("").to_ascii_lowercase().contains(f) || r["resourceType"].as_str().unwrap_or("").to_ascii_lowercase().contains(f))).cloned().collect();
        let total = all.len();
        if all.len() > limit {
            all.drain(..all.len() - limit);
        }
        let mut truncated = total > all.len();
        while serde_json::to_string(&all).map(|s| s.len()).unwrap_or(0) > 12_000 && all.len() > 1 {
            all.remove(0);
            truncated = true;
        }
        for r in all.iter_mut() {
            if let Some(o) = r.as_object_mut() {
                o.remove("requestId");
            }
        }
        if clear {
            src.clear();
        }
        json!({"total": total, "returned": all.len(), "truncated": truncated, kind: crate::policy::redact_json(&Value::Array(all))})
    })
}

// ---- emulation ----

/// A handful of common device descriptors (viewport, DPR, mobile, touch, UA).
pub fn device(name: &str) -> Option<(u64, u64, f64, bool, &'static str)> {
    const IOS: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
    const IPAD: &str = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1";
    const ANDROID: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36";
    const DESKTOP: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
    Some(match name.to_ascii_lowercase().as_str() {
        "iphone se" => (375, 667, 2.0, true, IOS),
        "iphone 12" | "iphone 13" | "iphone 14" => (390, 844, 3.0, true, IOS),
        "iphone 15" | "iphone 15 pro" => (393, 852, 3.0, true, IOS),
        "iphone 15 pro max" | "iphone 14 pro max" => (430, 932, 3.0, true, IOS),
        "ipad" | "ipad (gen 7)" => (810, 1080, 2.0, true, IPAD),
        "ipad pro 11" => (834, 1194, 2.0, true, IPAD),
        "ipad mini" => (768, 1024, 2.0, true, IPAD),
        "pixel 5" => (393, 851, 2.75, true, ANDROID),
        "pixel 7" => (412, 915, 2.625, true, ANDROID),
        "galaxy s9+" => (320, 658, 4.5, true, ANDROID),
        "galaxy s8" => (360, 740, 3.0, true, ANDROID),
        "desktop chrome" => (1280, 720, 1.0, false, DESKTOP),
        "desktop chrome hidpi" => (1280, 720, 2.0, false, DESKTOP),
        "desktop 1080p" => (1920, 1080, 1.0, false, DESKTOP),
        _ => return None,
    })
}

pub fn emulate(b: &Browser, target: &str, field: &str, value: &str) -> Result<(), String> {
    match field {
        "device" => {
            let (w, h, dpr, mobile, ua) = device(value).ok_or_else(|| format!("Unknown device \"{value}\"."))?;
            b.page_call(target, "Emulation.setDeviceMetricsOverride", json!({"width": w, "height": h, "deviceScaleFactor": dpr, "mobile": mobile}))?;
            b.page_call(target, "Emulation.setTouchEmulationEnabled", json!({"enabled": mobile, "maxTouchPoints": if mobile { 5 } else { 0 }}))?;
            b.page_call(target, "Emulation.setUserAgentOverride", json!({"userAgent": ua}))?;
        }
        "colorScheme" => {
            if !["dark", "light", "no-preference", "none"].contains(&value) {
                return Err("colorScheme must be dark|light|no-preference|none.".into());
            }
            let v = if value == "none" { "" } else { value };
            b.page_call(target, "Emulation.setEmulatedMedia", json!({"features": [{"name": "prefers-color-scheme", "value": v}]}))?;
        }
        "timezoneId" => {
            b.page_call(target, "Emulation.setTimezoneOverride", json!({"timezoneId": value}))?;
        }
        "locale" => {
            b.page_call(target, "Emulation.setLocaleOverride", json!({"locale": value}))?;
        }
        _ => return Err(format!("unknown emulation setting {field}")),
    }
    Ok(())
}

// ---- upload / download ----

pub fn upload(b: &Browser, target: &str, paths: &[PathBuf], rf: Option<&str>, input_ref: Option<&str>, selector: Option<&str>, timeout: Duration) -> Result<Value, String> {
    if paths.is_empty() {
        return Err("paths are required".into());
    }
    if rf.is_some() && (input_ref.is_some() || selector.is_some()) {
        return Err("ref cannot be combined with inputRef/element".into());
    }
    for p in paths {
        if !p.is_file() {
            return Err(format!("upload file not found: {}", p.display()));
        }
    }
    let files: Vec<String> = paths.iter().map(|p| p.canonicalize().unwrap_or(p.clone()).display().to_string()).collect();
    if input_ref.is_some() || selector.is_some() {
        let el = element(b, target, input_ref, selector)?;
        b.session_call(target, &el.session, "DOM.setFileInputFiles", json!({"files": files, "backendNodeId": el.backend}), b.timeout)?;
        return Ok(json!({"ok": true, "files": files.len(), "mode": "input"}));
    }
    let Some(r) = rf else {
        b.page(target, |p| {
            if p.armed_upload.is_some() {
                // OpenClaw: the last arm wins.
            }
            p.armed_upload = Some(files.clone());
        });
        return Ok(json!({"ok": true, "armed": true, "files": files.len(), "note": "The next file chooser on this tab receives these files."}));
    };
    let el = element(b, target, Some(r), None)?;
    let tag = call_on(b, target, &el, "function(){ return this.tagName === 'INPUT' && this.type === 'file'; }", vec![])?;
    if tag == true {
        b.session_call(target, &el.session, "DOM.setFileInputFiles", json!({"files": files, "backendNodeId": el.backend}), b.timeout)?;
        return Ok(json!({"ok": true, "files": files.len(), "mode": "input"}));
    }
    b.page(target, |p| p.armed_upload = Some(files.clone()));
    click_el(b, target, &el, "left", 1, 0, Duration::ZERO)?;
    let until = Instant::now() + timeout;
    while Instant::now() < until {
        if b.page(target, |p| p.armed_upload.is_none()) {
            return Ok(json!({"ok": true, "files": files.len(), "mode": "chooser"}));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    b.page(target, |p| p.armed_upload = None);
    Err(format!("no file chooser opened within {}ms after clicking {r}", timeout.as_millis()))
}

/// Wait for a download that began after `since_ms` to finish; move it to `dest`.
pub fn wait_download(b: &Browser, since_ms: u64, dest: Option<&Path>, timeout: Duration) -> Result<Value, String> {
    let until = Instant::now() + timeout;
    loop {
        let found = {
            let s = b.state.lock().unwrap();
            let mut v: Vec<_> = s.downloads.values().filter(|d| d.begun >= since_ms).cloned().collect();
            v.sort_by_key(|d| d.begun);
            v.into_iter().next()
        };
        if let Some(d) = found {
            match d.state.as_str() {
                "completed" => {
                    let src = b.dir.join("downloads").join(&d.guid);
                    let name = if d.suggested.is_empty() { d.guid.clone() } else { d.suggested.replace(['/', '\\'], "_") };
                    let to = match dest {
                        Some(p) if p.is_dir() => p.join(&name),
                        Some(p) => p.to_path_buf(),
                        None => b.dir.join("downloads").join(&name),
                    };
                    if let Some(parent) = to.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                    }
                    std::fs::rename(&src, &to).or_else(|_| std::fs::copy(&src, &to).map(|_| ())).map_err(|e| format!("saving download: {e}"))?;
                    b.state.lock().unwrap().downloads.remove(&d.guid);
                    return Ok(json!({"url": d.url, "suggestedFilename": d.suggested, "path": to.display().to_string()}));
                }
                "canceled" => return Err(format!("download of {} was canceled", d.url)),
                _ => {}
            }
        }
        if Instant::now() >= until {
            return Err(format!("no download completed within {}ms", timeout.as_millis()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_source_normalization() {
        assert_eq!(normalize_fn("() => document.title"), "() => document.title");
        assert_eq!(normalize_fn("async function f(){ return 1 }"), "async function f(){ return 1 }");
        assert_eq!(normalize_fn("el => el.value"), "el => el.value");
        assert_eq!(normalize_fn("document.title"), "(el) => { const r = (document.title); return typeof r === \"function\" ? r(el) : r; }");
        assert!(normalize_fn("const a = 1; return a + 1").starts_with("async (el) => {\n"));
        assert!(glob_match("https://x.example/**", "https://x.example/a/b"));
        assert!(glob_match("https://x.example/*", "https://x.example/a") && !glob_match("https://x.example/*", "https://x.example/a/b"));
        assert!(glob_match("https://x.example/", "https://x.example"));
        assert_eq!(count_actions(&[json!({"kind": "batch", "actions": [{"kind": "click"}, {"kind": "press"}]})]), 3);
        assert!(device("iPhone 13").is_some() && device("Nokia 3310").is_none());
        assert_eq!(level_rank("warning"), 2);
    }
}
