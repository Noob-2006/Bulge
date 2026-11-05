//! Session dashboards and agent-authored widgets: `show_widget` and `dashboard`
//! (OpenClaw src/canvas/widget-tool.ts, src/agents/tools/dashboard-tool.ts, src/boards, MIT).
//!
//! A board per session (`<surfaces>/boards/<session>.json`): tabs, and widgets placed on
//! them. Widget content is agent HTML (rendered in a sandboxed frame), or a plugin kind:
//! `session:report` (data-only report), `session:progress` (live progress card),
//! `session:website` (an HTTPS site in a frame) and `session:github` (GitHub Actions runs
//! for one repository, read by the daemon after the operator approves the
//! `github.actions.runs:<owner>/<repo>` capability). The web UI reads boards over ARP
//! (`surfaces.board`) and polls `surfaces.poll` for focus/presentation commands.

use super::{canvas, cards, esc_html, now_ms, read_json, safe_key, write_json, Env};
use ark_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

/// `[surfaces.widgets]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WidgetsConfig {
    /// Inline widgets in chat (hosted documents rendered by the web UI). Default true;
    /// false makes `show_widget` pinned-only.
    pub inline: bool,
    /// GitHub REST base for `session:github` widgets. Default `https://api.github.com`;
    /// plain http is accepted only for a loopback test server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_api: Option<String>,
    /// GitHub credential for `session:github` widgets, usually `{{secret:GITHUB_TOKEN}}`.
    /// Unset falls back to `[web.providers.github] api_key`, then `GITHUB_TOKEN` / `GH_TOKEN`
    /// (environment or vault). Anonymous reads work at GitHub's lower rate limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_token: Option<String>,
}

impl Default for WidgetsConfig {
    fn default() -> Self {
        WidgetsConfig { inline: true, github_api: None, github_token: None }
    }
}

pub const WIDGET_HTML_MAX_BYTES: usize = 10 * 1024 * 1024;
pub const PROPS_MAX_BYTES: usize = 8 * 1024;
const MAX_WIDGETS: usize = 48;
pub const WIDGET_MAX_PER_SCOPE: usize = 32;
pub const CDN_ORIGINS: &[&str] = &["https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://esm.sh", "https://unpkg.com", "https://fonts.googleapis.com", "https://fonts.gstatic.com"];
const SIZES: &[(&str, u32, u32)] = &[("sm", 3, 3), ("md", 6, 4), ("lg", 8, 6), ("xl", 12, 8), ("full", 12, 8)];
const PLUGIN_KINDS: &[&str] = &["session:report", "session:progress", "session:website", "session:github"];
pub const REPORT_GUIDANCE: &str = "Report data: {blocks:[...]}. Blocks: text {text,title?}; metrics {items:[{label,value,detail?}]}; table {columns,rows,title?}; chart {points:[{label,value}],style?:\"bar\"|\"line\",title?}; links {items:[{label,url,detail?}],title?}. Every block needs its type. Metric values and table cells are strings; chart values are numbers. Maximum 8KB JSON, 24 blocks, 8 metrics or columns, 40 rows or chart points, 20 links per block. Links must be HTTP(S). No HTML, scripts, styles, network reads, or executable actions.";
const WEBSITE_GUIDANCE: &str = "Website props: {url:\"https://...\"}. Opens the live website in an isolated frame without ark tools or credentials. Use a public HTTPS URL without embedded credentials; the website must allow embedding. Use size:\"full\", then action:\"set_presentation\" with presentation:\"expanded\" for a full-task website.";
pub const GITHUB_ACTIONS_GUIDANCE: &str = "GitHub Actions props: {repository:\"owner/repo\", workflow?:12|\"ci.yml\", branch?, status?, created?:\"YYYY-MM-DD\"|\">=YYYY-MM-DD\"|\"YYYY-MM-DD..YYYY-MM-DD\", perPage?:1..30, excludePullRequests?:bool}. Declares the capability github.actions.runs:<owner>/<repo>; the board reads GET https://api.github.com/repos/<owner>/<repo>/actions/runs only after the operator approves that capability, then shows workflow, branch, status/conclusion, time and links from cached server reads. GitHub token: [surfaces.widgets] github_token, [web.providers.github] api_key, or GITHUB_TOKEN/GH_TOKEN; without one the read is anonymous and rate limited. Use show_widget HTML for anything else.";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tab {
    pub tab_id: String,
    pub title: String,
    pub position: usize,
    pub chat_dock: String,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Widget {
    pub name: String,
    pub tab_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// html | plugin
    pub content_kind: String,
    pub content_owner: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub props: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height_mode: Option<String>,
    pub size_w: u32,
    pub size_h: u32,
    pub position: usize,
    /// none | pending | granted | rejected
    pub grant_state: String,
    pub revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<Declared>,
    /// sha256 of the HTML a grant was approved for (grants are frozen to approved bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub granted_sha256: Option<String>,
    /// Set when show_widget generated the name from the title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Declared {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub net_origins: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Board {
    pub session_key: String,
    pub revision: u64,
    pub tabs: Vec<Tab>,
    pub widgets: Vec<Widget>,
    /// split | expanded (saved default; read reports split when unset).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_presentation: Option<String>,
    #[serde(default)]
    pub updated_ms: u64,
}

fn board_path(env: &Env, session: &str) -> Result<std::path::PathBuf, String> {
    Ok(env.dir.join("boards").join(format!("{}.json", safe_key(session)?)))
}

static LOCK: Mutex<()> = Mutex::new(());

pub fn load(env: &Env, session: &str) -> Result<Board, String> {
    let p = board_path(env, session)?;
    Ok(read_json(&p).unwrap_or_else(|| Board { session_key: session.to_string(), ..Default::default() }))
}

/// Read-modify-write one board under the process lock; bumps the revision when `f` succeeds.
fn mutate(env: &Env, session: &str, f: impl FnOnce(&mut Board) -> Result<(), String>) -> Result<Board, String> {
    let _g = LOCK.lock().unwrap();
    let mut b = load(env, session)?;
    let mut next = b.clone();
    f(&mut next)?;
    normalize(&mut next);
    if next != b {
        next.revision = b.revision + 1;
        next.updated_ms = now_ms();
        write_json(&board_path(env, session)?, &next)?;
        b = next;
    }
    Ok(b)
}

fn normalize(b: &mut Board) {
    b.tabs.sort_by_key(|t| t.position);
    for (i, t) in b.tabs.iter_mut().enumerate() {
        t.position = i;
    }
    let pos: HashMap<String, usize> = b.tabs.iter().map(|t| (t.tab_id.clone(), t.position)).collect();
    b.widgets.sort_by_key(|w| (pos.get(&w.tab_id).copied().unwrap_or(usize::MAX), w.position));
    let mut next: HashMap<String, usize> = HashMap::new();
    for w in &mut b.widgets {
        let n = next.entry(w.tab_id.clone()).or_insert(0);
        w.position = *n;
        *n += 1;
    }
}

fn valid_tab_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

pub fn valid_widget_name(s: &str) -> bool {
    let mut c = s.chars();
    matches!(c.next(), Some(f) if f.is_ascii_lowercase() || f.is_ascii_digit()) && s.len() <= 64 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
}

fn require_tab<'a>(b: &'a mut Board, id: &str) -> Result<&'a mut Tab, String> {
    b.tabs.iter_mut().find(|t| t.tab_id == id).ok_or_else(|| format!("board tab not found: {id}"))
}

fn move_widget(b: &mut Board, name: &str, tab: &str, position: Option<usize>, after: Option<&str>) -> Result<(), String> {
    if !b.tabs.iter().any(|t| t.tab_id == tab) {
        return Err(format!("board tab not found: {tab}"));
    }
    if position.is_some() && after.is_some() {
        return Err("widget_move accepts either position or after, not both".into());
    }
    let idx = b.widgets.iter().position(|w| w.name == name).ok_or_else(|| format!("board widget not found: {name}"))?;
    let mut w = b.widgets.remove(idx);
    let mut target: Vec<Widget> = Vec::new();
    let mut others = Vec::new();
    for x in b.widgets.drain(..) {
        if x.tab_id == tab { target.push(x) } else { others.push(x) }
    }
    target.sort_by_key(|x| x.position);
    let at = if let Some(a) = after {
        if a == name {
            b.widgets = others.into_iter().chain(target).chain(std::iter::once(w)).collect();
            return Err("widget cannot be placed after itself".into());
        }
        match target.iter().position(|x| x.name == a) {
            Some(i) => i + 1,
            None => {
                b.widgets = others.into_iter().chain(target).chain(std::iter::once(w)).collect();
                return Err(format!("board widget anchor not found on tab {tab}: {a}"));
            }
        }
    } else {
        position.map(|p| p.min(target.len())).unwrap_or(target.len())
    };
    w.tab_id = tab.to_string();
    target.insert(at, w);
    for (i, x) in target.iter_mut().enumerate() {
        x.position = i;
    }
    b.widgets = others.into_iter().chain(target).collect();
    Ok(())
}

/// One layout op (OpenClaw BoardOp).
pub fn apply_op(b: &mut Board, op: &Value) -> Result<(), String> {
    let s = |k: &str| op[k].as_str();
    match s("kind").unwrap_or("") {
        "tab_create" => {
            let id = s("tabId").filter(|t| valid_tab_id(t)).ok_or("tabId must be a lowercase slug up to 40 characters")?;
            let title = s("title").map(str::trim).filter(|t| !t.is_empty() && t.chars().count() <= 80).ok_or("title must be 1-80 characters")?;
            if b.tabs.iter().any(|t| t.tab_id == id) {
                return Err(format!("board tab already exists: {id}"));
            }
            let n = b.tabs.len();
            b.tabs.push(Tab { tab_id: id.into(), title: title.into(), position: n, chat_dock: s("chatDock").unwrap_or("right").into() });
        }
        "tab_update" => {
            let id = s("tabId").unwrap_or("").to_string();
            let (title, pos) = (s("title").map(str::to_string), op["position"].as_u64());
            if title.is_none() && pos.is_none() && op["chatDock"].is_null() {
                return Err("tab_update has no changes".into());
            }
            let t = require_tab(b, &id)?;
            if let Some(t2) = title {
                if t2.trim().is_empty() || t2.chars().count() > 80 {
                    return Err("title must be 1-80 characters".into());
                }
                t.title = t2;
            }
            if let Some(d) = s("chatDock") {
                t.chat_dock = d.into();
            }
            if let Some(p) = pos {
                let i = b.tabs.iter().position(|t| t.tab_id == id).unwrap();
                let tab = b.tabs.remove(i);
                b.tabs.sort_by_key(|t| t.position);
                b.tabs.insert((p as usize).min(b.tabs.len()), tab);
                for (i, t) in b.tabs.iter_mut().enumerate() {
                    t.position = i;
                }
            }
        }
        "tab_delete" => {
            let id = s("tabId").unwrap_or("");
            require_tab(b, id)?;
            let rest: Vec<Tab> = b.tabs.iter().filter(|t| t.tab_id != id).cloned().collect();
            let has = b.widgets.iter().any(|w| w.tab_id == id);
            if rest.is_empty() && has {
                return Err("cannot delete the last board tab while it contains widgets".into());
            }
            if has {
                let fallback = rest.iter().min_by_key(|t| t.position).unwrap().tab_id.clone();
                for w in b.widgets.iter_mut().filter(|w| w.tab_id == id) {
                    w.tab_id = fallback.clone();
                    w.position += usize::MAX / 2;
                }
            }
            b.tabs = rest;
        }
        "tabs_reorder" => {
            let ids: Vec<String> = op["tabIds"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
            let uniq: std::collections::HashSet<&String> = ids.iter().collect();
            if ids.len() != b.tabs.len() || uniq.len() != ids.len() || ids.iter().any(|i| !b.tabs.iter().any(|t| &t.tab_id == i)) {
                return Err("tabs_reorder must contain every tab exactly once".into());
            }
            for t in &mut b.tabs {
                t.position = ids.iter().position(|i| i == &t.tab_id).unwrap();
            }
        }
        "widget_move" => {
            let name = s("name").unwrap_or("");
            let cur = b.widgets.iter().find(|w| w.name == name).ok_or_else(|| format!("board widget not found: {name}"))?.tab_id.clone();
            let tab = s("tabId").map(str::to_string).unwrap_or(cur);
            move_widget(b, name, &tab, op["position"].as_u64().map(|p| p as usize), s("after"))?;
        }
        "widget_resize" => {
            let name = s("name").unwrap_or("");
            let w = b.widgets.iter_mut().find(|w| w.name == name).ok_or_else(|| format!("board widget not found: {name}"))?;
            let (sw, sh) = (op["sizeW"].as_i64().ok_or("sizeW required")?, op["sizeH"].as_i64().ok_or("sizeH required")?);
            w.size_w = sw.clamp(1, 12) as u32;
            w.size_h = sh.clamp(1, 20) as u32;
            w.height_mode = Some(s("heightMode").unwrap_or("fixed").into());
        }
        "widget_remove" => {
            let name = s("name").unwrap_or("");
            if !b.widgets.iter().any(|w| w.name == name) {
                return Err(format!("board widget not found: {name}"));
            }
            b.widgets.retain(|w| w.name != name);
        }
        k => return Err(format!("Unknown dashboard action: {k}")),
    }
    Ok(())
}

/// What a widget_put places: content plus optional placement.
pub struct Put {
    pub name: String,
    pub title: Option<String>,
    pub html: Option<String>,
    pub plugin_kind: Option<String>,
    pub props: Option<Value>,
    pub presentation: Option<String>,
    pub declared: Option<Declared>,
    pub tab: Option<String>,
    pub size: Option<String>,
    pub after: Option<String>,
    pub generated_key: Option<String>,
}

pub fn put(env: &Env, session: &str, p: Put) -> Result<(Board, String), String> {
    let mut resolved = p.name.clone();
    let b = mutate(env, session, |b| {
        if b.tabs.is_empty() {
            b.tabs.push(Tab { tab_id: "main".into(), title: "Main".into(), position: 0, chat_dock: "right".into() });
        }
        // A generated name that collides with another widget gets the hash-suffixed fallback.
        if let Some(key) = &p.generated_key {
            if let Some(w) = b.widgets.iter().find(|w| w.name == resolved) {
                if w.generated_key.as_deref() != Some(key) {
                    let fallback = format!("{}-{}", resolved.chars().take(55).collect::<String>().trim_end_matches('-'), &key[..8]);
                    resolved = fallback;
                }
            }
        }
        let owner = if p.html.is_some() { "html" } else { "plugin" };
        let existing = b.widgets.iter().find(|w| w.name == resolved).cloned();
        if let Some(e) = &existing {
            if e.content_owner != owner || (owner == "plugin" && e.plugin_kind != p.plugin_kind) {
                let incoming = p.plugin_kind.clone().unwrap_or_else(|| owner.to_string());
                return Err(format!("board widget {} contains {} content; update it with the same content kind or remove it before replacing it with {incoming} content", resolved, e.plugin_kind.clone().unwrap_or_else(|| e.content_owner.clone())));
            }
        }
        if existing.is_none() && b.widgets.len() >= MAX_WIDGETS {
            return Err(format!("board cannot contain more than {MAX_WIDGETS} widgets"));
        }
        let tab = p.tab.clone().or_else(|| existing.as_ref().map(|e| e.tab_id.clone())).unwrap_or_else(|| b.tabs[0].tab_id.clone());
        if !b.tabs.iter().any(|t| t.tab_id == tab) {
            return Err(format!("board tab not found: {tab}"));
        }
        let (sw, sh) = SIZES.iter().find(|s| Some(s.0) == p.size.as_deref().or(Some("md"))).map(|s| (s.1, s.2)).ok_or("size must be sm, md, lg, xl, or full")?;
        let (sw, sh) = match (&existing, &p.size) {
            (Some(e), None) => (e.size_w, e.size_h),
            _ => (sw, sh),
        };
        let sha = p.html.as_deref().map(|h| ark_net::crypto::hex(&ark_net::crypto::sha256(h.as_bytes())));
        // Grants are frozen to approved bytes and may narrow but never widen.
        let grant = match (&p.declared, &existing) {
            (None, _) => "none".to_string(),
            (Some(d), Some(e)) if e.grant_state == "granted" && e.granted_sha256 == sha && e.declared.as_ref().is_some_and(|ed| narrower(d, ed)) => "granted".into(),
            (Some(_), _) => "pending".into(),
        };
        let w = Widget {
            name: resolved.clone(),
            tab_id: tab.clone(),
            title: p.title.clone(),
            content_kind: owner.into(),
            content_owner: owner.into(),
            plugin_kind: p.plugin_kind.clone(),
            props: p.props.clone(),
            html: p.html.clone(),
            presentation: p.presentation.clone(),
            height_mode: existing.as_ref().and_then(|e| e.height_mode.clone()),
            size_w: sw,
            size_h: sh,
            position: existing.as_ref().map(|e| e.position).unwrap_or(usize::MAX / 2),
            granted_sha256: if grant == "granted" { sha.clone() } else { None },
            grant_state: grant,
            revision: existing.as_ref().map(|e| e.revision).unwrap_or(0) + 1,
            declared: p.declared.clone(),
            generated_key: p.generated_key.clone(),
        };
        match b.widgets.iter_mut().find(|x| x.name == resolved) {
            Some(x) => *x = w,
            None => b.widgets.push(w),
        }
        if existing.is_none() || p.after.is_some() || p.tab.as_deref().is_some_and(|t| existing.as_ref().is_some_and(|e| e.tab_id != t)) {
            normalize(b);
            move_widget(b, &resolved, &tab, None, p.after.as_deref())?;
        }
        Ok(())
    })?;
    Ok((b, resolved))
}

fn narrower(new: &Declared, old: &Declared) -> bool {
    new.net_origins.iter().all(|o| old.net_origins.contains(o)) && new.tools.iter().all(|t| old.tools.contains(t))
}

/// Normalize declared capabilities: exact HTTPS origins and supported host tools.
pub fn parse_declared(v: &Value) -> Result<Option<Declared>, String> {
    if v.is_null() {
        return Ok(None);
    }
    let list = |k: &str| -> Vec<String> { v[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect()).unwrap_or_default() };
    let mut d = Declared { net_origins: list("netOrigins"), tools: list("tools") };
    for o in &d.net_origins {
        let ok = o.strip_prefix("https://").is_some_and(|h| !h.is_empty() && !h.contains(['/', '?', '#', '@', ' ', '*']));
        if !ok {
            return Err(format!("capabilities.netOrigins entries must be exact HTTPS origins, got `{o}`"));
        }
    }
    for t in &d.tools {
        let ok = t == "prompt" || t.strip_prefix("cron.trigger:").is_some_and(|j| !j.is_empty() && j.len() <= 256) || t.starts_with(GITHUB_ACTIONS_GRANT_PREFIX);
        if !ok {
            return Err(format!("capabilities.tools supports `prompt`, `cron.trigger:<jobId>` and `github.actions.runs:<owner>/<repo>`, got `{t}`"));
        }
        if t.starts_with(GITHUB_ACTIONS_GRANT_PREFIX) && normalize_github_actions_grant(t).is_none() {
            return Err(format!("GitHub Actions grant requires owner/repo, got `{t}`"));
        }
    }
    // Grants are compared byte for byte: the repository is normalized to lowercase.
    d.tools = d.tools.iter().map(|t| normalize_github_actions_grant(t).unwrap_or_else(|| t.clone())).collect();
    if d.net_origins.len() > 32 || d.tools.len() > 64 {
        return Err("too many declared capabilities".into());
    }
    d.net_origins.sort();
    d.net_origins.dedup();
    d.tools.sort();
    d.tools.dedup();
    Ok(if d.net_origins.is_empty() && d.tools.is_empty() { None } else { Some(d) })
}

// ───────────────────────── report / website props ─────────────────────────

pub fn validate_report(v: &Value) -> Result<(), String> {
    if v.to_string().len() > PROPS_MAX_BYTES {
        return Err("Report exceeds 8KB JSON budget".into());
    }
    let bad = |path: &str, m: &str| Err(format!("Invalid report at {path}: {m}"));
    let obj = v.as_object().ok_or("Invalid report at root: expected object")?;
    if obj.keys().any(|k| k != "blocks") {
        return bad("root", "unexpected field");
    }
    let blocks = v["blocks"].as_array().ok_or("Invalid report at blocks: expected array")?;
    if blocks.is_empty() || blocks.len() > 24 {
        return bad("blocks", "expected 1-24 blocks");
    }
    let str_in = |x: &Value, min: usize, max: usize| x.as_str().is_some_and(|s| (min..=max).contains(&s.chars().count()));
    let opt = |x: &Value, max: usize| x.is_null() || str_in(x, 1, max);
    for (i, b) in blocks.iter().enumerate() {
        let p = format!("blocks.{i}");
        let keys: Vec<&str> = b.as_object().map(|o| o.keys().map(String::as_str).collect()).unwrap_or_default();
        let allowed: &[&str] = match b["type"].as_str() {
            Some("text") => &["type", "title", "text"],
            Some("metrics") => &["type", "items"],
            Some("table") => &["type", "title", "columns", "rows"],
            Some("chart") => &["type", "title", "style", "points"],
            Some("links") => &["type", "title", "items"],
            _ => return bad(&format!("{p}.type"), "unknown block type"),
        };
        if keys.iter().any(|k| !allowed.contains(k)) {
            return bad(&p, "unexpected field");
        }
        if !opt(&b["title"], 120) {
            return bad(&format!("{p}.title"), "1-120 characters");
        }
        match b["type"].as_str().unwrap() {
            "text" if !str_in(&b["text"], 1, 4000) => return bad(&format!("{p}.text"), "1-4000 characters"),
            "metrics" => {
                let items = b["items"].as_array().filter(|a| (1..=8).contains(&a.len())).ok_or(format!("Invalid report at {p}.items: 1-8 items"))?;
                for (j, it) in items.iter().enumerate() {
                    if !str_in(&it["label"], 1, 160) || !str_in(&it["value"], 1, 80) || !(it["detail"].is_null() || str_in(&it["detail"], 0, 240)) || it.as_object().is_some_and(|o| o.keys().any(|k| !["label", "value", "detail"].contains(&k.as_str()))) {
                        return bad(&format!("{p}.items.{j}"), "label 1-160, value 1-80 (strings), detail ≤240");
                    }
                }
            }
            "table" => {
                let cols = b["columns"].as_array().filter(|a| (1..=8).contains(&a.len()) && a.iter().all(|c| str_in(c, 1, 160))).ok_or(format!("Invalid report at {p}.columns: 1-8 labels"))?;
                let rows = b["rows"].as_array().filter(|r| r.len() <= 40).ok_or(format!("Invalid report at {p}.rows: at most 40 rows"))?;
                for r in rows {
                    let r = r.as_array().ok_or(format!("Invalid report at {p}.rows: rows are arrays"))?;
                    if r.len() != cols.len() || r.iter().any(|c| !str_in(c, 0, 500)) {
                        return bad(&format!("{p}.rows"), "Every table row must match the columns");
                    }
                }
            }
            "chart" => {
                if !(b["style"].is_null() || matches!(b["style"].as_str(), Some("bar" | "line"))) {
                    return bad(&format!("{p}.style"), "bar or line");
                }
                let pts = b["points"].as_array().filter(|a| (1..=40).contains(&a.len())).ok_or(format!("Invalid report at {p}.points: 1-40 points"))?;
                if pts.iter().any(|x| !str_in(&x["label"], 1, 160) || !x["value"].as_f64().is_some_and(|f| f.is_finite() && f.abs() <= 9_007_199_254_740_991.0)) {
                    return bad(&format!("{p}.points"), "label string and numeric value");
                }
            }
            "links" => {
                let items = b["items"].as_array().filter(|a| (1..=20).contains(&a.len())).ok_or(format!("Invalid report at {p}.items: 1-20 links"))?;
                for it in items {
                    let url = it["url"].as_str().unwrap_or("");
                    if !str_in(&it["label"], 1, 160) || url.len() > 2048 || !(url.starts_with("https://") || url.starts_with("http://")) || url.contains(char::is_whitespace) || !(it["detail"].is_null() || str_in(&it["detail"], 0, 240)) {
                        return bad(&format!("{p}.items"), "label and HTTP(S) url");
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_props(kind: &str, props: &Value) -> Result<(), String> {
    if props.to_string().len() > PROPS_MAX_BYTES {
        return Err("props must be at most 8KB encoded".into());
    }
    match kind {
        "session:report" => validate_report(props),
        "session:website" => {
            let ok = props.as_object().is_some_and(|o| o.len() == 1)
                && props["url"].as_str().is_some_and(|u| u.len() <= 2048 && u.strip_prefix("https://").is_some_and(|r| !r.is_empty() && !r.contains(char::is_whitespace)));
            if !ok {
                return Err("Website props must contain only a valid HTTPS url of at most 2048 characters".into());
            }
            let host = props["url"].as_str().unwrap()[8..].split(['/', '?', '#']).next().unwrap_or("");
            if host.contains('@') {
                return Err("Website URLs must not contain embedded credentials".into());
            }
            Ok(())
        }
        "session:progress" => {
            if props.as_object().is_some_and(|o| o.keys().any(|k| k != "sessionKey")) || !(props["sessionKey"].is_null() || props["sessionKey"].is_string()) {
                return Err("session:progress props are {sessionKey?}".into());
            }
            Ok(())
        }
        "session:github" => validate_github_actions(props).map(|_| ()),
        k => Err(format!("widget kind {k:?} is unavailable; enable the plugin that provides it and retry")),
    }
}

// ───────────────────── GitHub Actions board (session:github) ─────────────────────
//
// OpenClaw src/boards/github-actions-capability.ts: one closed contract owns the props, the
// exact `github.actions.runs:<owner>/<repo>` grant and the URL. The board payload reads
// `GET /repos/<owner>/<repo>/actions/runs` synchronously (short timeout, 30s cache) only
// after the operator approved that grant, and renders runs through the report renderer, so
// the web UI needs no change. The token never reaches the document.

/// `session:github` plugin kind.
pub const GITHUB_ACTIONS_KIND: &str = "session:github";
const GITHUB_ACTIONS_BINDING_ID: &str = "github.actions.runs";
const GITHUB_ACTIONS_GRANT_PREFIX: &str = "github.actions.runs:";
const GITHUB_ACTIONS_API: &str = "https://api.github.com";
/// Short TTL: a dashboard render stays cheap and GitHub's anonymous limit intact.
const GITHUB_ACTIONS_TTL_MS: u64 = 30_000;
const GITHUB_ACTIONS_TIMEOUT_SECS: u64 = 5;
const GITHUB_ACTIONS_MAX_ROWS: usize = 40;
const GITHUB_ACTIONS_MAX_LINKS: usize = 20;
const GITHUB_ACTIONS_SAFE_INT: u64 = 9_007_199_254_740_991;
/// Upstream `paramsSchema.status` enum.
pub const GITHUB_ACTIONS_STATUSES: &[&str] = &["completed", "action_required", "cancelled", "failure", "neutral", "skipped", "stale", "success", "timed_out", "in_progress", "queued", "requested", "waiting", "pending"];
const GITHUB_ACTIONS_USAGE: &str = "use repository (owner/repo), workflow (id or \"ci.yml\"), perPage (1..30), branch, status, created, or excludePullRequests only";

/// A validated `session:github` request.
#[derive(Debug, Clone, PartialEq)]
pub struct GitHubActionsRequest {
    /// Normalized lowercase `owner/repo`.
    pub repository: String,
    pub workflow: Option<String>,
    pub branch: Option<String>,
    pub status: Option<String>,
    pub created: Option<String>,
    pub per_page: u32,
    pub exclude_pull_requests: bool,
}

impl GitHubActionsRequest {
    /// The one capability that must be granted before the board reads GitHub.
    pub fn grant(&self) -> String {
        format!("{GITHUB_ACTIONS_BINDING_ID}:{}", self.repository)
    }

    /// `/repos/<owner>/<repo>/actions[/workflows/<id>]/runs?…`
    pub fn path_and_query(&self) -> String {
        let repo = self.repository.split('/').map(ark_net::urlencode).collect::<Vec<_>>().join("/");
        let op = match &self.workflow {
            Some(w) => format!("workflows/{}/runs", ark_net::urlencode(w)),
            None => "runs".to_string(),
        };
        let mut q = format!("per_page={}&exclude_pull_requests={}", self.per_page, self.exclude_pull_requests);
        for (k, v) in [("branch", &self.branch), ("status", &self.status), ("created", &self.created)] {
            if let Some(v) = v {
                q.push('&');
                q.push_str(k);
                q.push('=');
                q.push_str(&ark_net::urlencode(v));
            }
        }
        format!("/repos/{repo}/actions/{op}?{q}")
    }
}

fn ascii_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

fn valid_day(s: &str) -> bool {
    let p: Vec<&str> = s.split('-').collect();
    if p.len() != 3 || p[0].len() != 4 || p[1].len() != 2 || p[2].len() != 2 || !p.iter().all(|x| ascii_digits(x)) {
        return false;
    }
    let (y, m, d) = (p[0].parse::<i64>().unwrap_or(0), p[1].parse::<u32>().unwrap_or(0), p[2].parse::<u32>().unwrap_or(0));
    (1..=12).contains(&m) && (1..=days_in_month(y, m)).contains(&d)
}

/// Upstream `createdSchema`: a day, one comparison (`<`, `<=`, `>`, `>=`), or a `..` range.
fn valid_created(s: &str) -> bool {
    let mut rest = s;
    let mut compared = false;
    if let Some(r) = rest.strip_prefix(['<', '>']) {
        compared = true;
        rest = r.strip_prefix('=').unwrap_or(r);
    }
    if compared {
        return valid_day(rest);
    }
    match rest.split_once("..") {
        Some((a, b)) => valid_day(a) && valid_day(b),
        None => valid_day(rest),
    }
}

/// Upstream `repositorySchema`: GitHub-safe owner/repo, lowercased.
pub fn normalize_repository(s: &str) -> Option<String> {
    let (owner, name) = s.split_once('/')?;
    let owner_ok = (1..=39).contains(&owner.len()) && owner.starts_with(|c: char| c.is_ascii_alphanumeric()) && owner.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    let name_ok = (1..=100).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')) && name != "." && name != "..";
    (owner_ok && name_ok).then(|| s.to_ascii_lowercase())
}

/// Upstream `workflow`: a positive integer id, or a `*.yml` / `*.yaml` file name.
fn normalize_workflow(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => n.as_u64().filter(|x| (1..=GITHUB_ACTIONS_SAFE_INT).contains(x)).map(|x| x.to_string()),
        Value::String(s) if s.chars().count() <= 255 => {
            if ascii_digits(s) {
                return (!s.starts_with('0')).then(|| s.parse::<u64>().ok()).flatten().filter(|x| (1..=GITHUB_ACTIONS_SAFE_INT).contains(x)).map(|x| x.to_string());
            }
            let lower = s.to_ascii_lowercase();
            let stem = lower.strip_suffix(".yaml").or_else(|| lower.strip_suffix(".yml"))?;
            (!stem.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))).then(|| s.clone())
        }
        _ => None,
    }
}

/// The closed `paramsSchema` of a `session:github` widget; errors name the correct usage.
pub fn validate_github_actions(v: &Value) -> Result<GitHubActionsRequest, String> {
    let bad = |m: String| format!("Invalid GitHub Actions parameters: {m}; {GITHUB_ACTIONS_USAGE}");
    let obj = v.as_object().ok_or_else(|| bad("props must be an object".into()))?;
    const KEYS: &[&str] = &["repository", "workflow", "branch", "status", "created", "perPage", "excludePullRequests"];
    if let Some(k) = obj.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(bad(format!("unexpected field `{k}`")));
    }
    let repository = obj.get("repository").and_then(|x| x.as_str()).and_then(normalize_repository).ok_or_else(|| bad("repository must be owner/repo with GitHub-safe characters, e.g. \"acme/app\"".into()))?;
    let workflow = match obj.get("workflow") {
        None | Some(Value::Null) => None,
        Some(w) => Some(normalize_workflow(w).ok_or_else(|| bad("workflow must be a positive workflow id or a workflow file such as \"ci.yml\"".into()))?),
    };
    let branch = match obj.get("branch") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if (1..=255).contains(&s.chars().count()) && !s.chars().any(|c| c.is_ascii_control()) => Some(s.clone()),
        Some(_) => return Err(bad("branch must be 1-255 characters without control characters".into())),
    };
    let status = match obj.get("status") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if GITHUB_ACTIONS_STATUSES.contains(&s.as_str()) => Some(s.clone()),
        Some(_) => return Err(bad(format!("status must be one of {}", GITHUB_ACTIONS_STATUSES.join(", ")))),
    };
    let created = match obj.get("created") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if valid_created(s) => Some(s.clone()),
        Some(_) => return Err(bad("created must be YYYY-MM-DD, >=YYYY-MM-DD (also <, <=, >) or YYYY-MM-DD..YYYY-MM-DD".into())),
    };
    let per_page = match obj.get("perPage") {
        None | Some(Value::Null) => 20,
        Some(v) => match v.as_i64().filter(|n| (1..=30).contains(n)) {
            Some(n) => n as u32,
            None => return Err(bad("perPage must be an integer from 1 to 30".into())),
        },
    };
    let exclude_pull_requests = match obj.get("excludePullRequests") {
        None | Some(Value::Null) => true,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(bad("excludePullRequests must be true or false".into())),
    };
    Ok(GitHubActionsRequest { repository, workflow, branch, status, created, per_page, exclude_pull_requests })
}

/// `github.actions.runs:<owner>/<repo>` with a normalized repository (upstream
/// `normalizeGitHubActionsGrant`); `None` when the tool is not an Actions grant.
pub fn normalize_github_actions_grant(tool: &str) -> Option<String> {
    let rest = tool.strip_prefix(GITHUB_ACTIONS_GRANT_PREFIX)?;
    normalize_repository(rest).map(|r| format!("{GITHUB_ACTIONS_GRANT_PREFIX}{r}"))
}

/// Where a widget may read: `https://api.github.com`, or a loopback test server.
fn github_api_base(env: &Env) -> Result<String, String> {
    let raw = env.cfg.widgets.github_api.as_deref().map(str::trim).unwrap_or("");
    if raw.is_empty() {
        return Ok(GITHUB_ACTIONS_API.to_string());
    }
    let b = raw.trim_end_matches('/');
    let official = b.strip_prefix("https://").is_some_and(|r| r == "api.github.com");
    let loopback = b.strip_prefix("http://").is_some_and(|r| (r == "localhost" || r == "127.0.0.1" || r.starts_with("localhost:") || r.starts_with("127.0.0.1:")) && !r.contains(['/', '?', '#', '@']));
    if official || loopback {
        Ok(b.to_string())
    } else {
        Err("[surfaces.widgets] github_api must be https://api.github.com (plain http is accepted only for a 127.0.0.1 test server)".into())
    }
}

/// `[web.providers.github] api_key` — ark's existing web GitHub setting.
fn web_github_api_key(env: &Env) -> Option<String> {
    let text = std::fs::read_to_string(&env.user_config).ok()?;
    let t: toml::Table = text.parse().ok()?;
    t.get("web")?.as_table()?.get("providers")?.as_table()?.get("github")?.as_table()?.get("api_key")?.as_str().map(str::to_string)
}

/// The GitHub credential ark already uses: `[surfaces.widgets] github_token`, then
/// `[web.providers.github] api_key`, then `GITHUB_TOKEN` / `GH_TOKEN` (environment or vault).
fn github_token(env: &Env) -> Option<String> {
    let sub = |s: &str| env.kernel().map(|k| k.vault.substitute(s)).unwrap_or_else(|_| s.to_string());
    let usable = |s: String| {
        let t = s.trim().to_string();
        (!t.is_empty() && !t.contains("{{secret:")).then_some(t)
    };
    if let Some(t) = env.cfg.widgets.github_token.as_deref().and_then(|t| usable(sub(t))) {
        return Some(t);
    }
    if let Some(t) = web_github_api_key(env).and_then(|t| usable(sub(&t))) {
        return Some(t);
    }
    for name in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Some(t) = std::env::var(name).ok().and_then(usable) {
            return Some(t);
        }
        let ph = format!("{{{{secret:{name}}}}}");
        let v = sub(&ph);
        if v != ph {
            if let Some(t) = usable(v) {
                return Some(t);
            }
        }
    }
    None
}

struct GitHubCacheEntry {
    url: String,
    auth: bool,
    at: u64,
    body: Result<Value, String>,
}

fn github_actions_cache() -> &'static Mutex<Vec<GitHubCacheEntry>> {
    static C: OnceLock<Mutex<Vec<GitHubCacheEntry>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(Vec::new()))
}

/// GET the Actions runs API with a short timeout; returns `(body, authenticated)`.
fn github_actions_json(env: &Env, req: &GitHubActionsRequest) -> Result<(Value, bool), String> {
    let url = format!("{}{}", github_api_base(env)?, req.path_and_query());
    let token = github_token(env);
    let auth = token.is_some();
    let now = now_ms();
    if let Some(e) = github_actions_cache().lock().unwrap().iter().find(|e| e.url == url && e.auth == auth && now.saturating_sub(e.at) < GITHUB_ACTIONS_TTL_MS) {
        return e.body.clone().map(|v| (v, auth));
    }
    let body = github_http_get(&url, token.as_deref());
    let mut c = github_actions_cache().lock().unwrap();
    c.retain(|e| e.url != url || e.auth != auth);
    c.push(GitHubCacheEntry { url, auth, at: now, body: body.clone() });
    if c.len() > 64 {
        c.remove(0);
    }
    body.map(|v| (v, auth))
}

#[cfg(test)]
fn clear_github_actions_cache() {
    github_actions_cache().lock().unwrap().clear();
}

fn github_http_get(url: &str, token: Option<&str>) -> Result<Value, String> {
    let redact = |s: &str| match token {
        Some(t) if !t.is_empty() => s.replace(t, "[redacted]"),
        _ => s.to_string(),
    };
    let agent: ureq::Agent = ark_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(GITHUB_ACTIONS_TIMEOUT_SECS))).build().into();
    let mut r = agent.get(url).header("accept", "application/vnd.github+json").header("x-github-api-version", "2022-11-28").header("user-agent", "ark-surfaces-widgets");
    if let Some(t) = token {
        r = r.header("authorization", format!("Bearer {t}"));
    }
    let mut resp = r.call().map_err(|e| format!("GitHub request failed; check connectivity and retry ({})", redact(&e.to_string())))?;
    let status = resp.status().as_u16();
    let body = resp.body_mut().read_to_string().unwrap_or_default();
    match status {
        200..=299 => serde_json::from_str(&body).map_err(|_| "GitHub returned invalid JSON; retry".to_string()),
        401 => Err("GitHub rejected the credential (HTTP 401): update [surfaces.widgets] github_token, [web.providers.github] api_key, or GITHUB_TOKEN, then retry".into()),
        403 | 429 => Err(format!("GitHub denied the read (HTTP {status}): rate limit or missing permissions. Wait and retry, or set a token in [web.providers.github] api_key")),
        404 => Err("GitHub returned HTTP 404: the repository is missing, or this credential cannot see it. Check repository owner/repo and token access".into()),
        s if s >= 500 => Err(format!("GitHub is unavailable (HTTP {s}); retry shortly")),
        s => Err(format!("GitHub returned HTTP {s}; check repository, workflow and token access")),
    }
}

fn github_actions_text(text: String) -> Value {
    json!({"blocks": [{"type": "text", "text": text}]})
}

fn github_run_state(r: &Value) -> String {
    match (r["status"].as_str(), r["conclusion"].as_str()) {
        (Some("completed"), Some(c)) => format!("completed · {c}"),
        (Some(s), _) => s.to_string(),
        (None, Some(c)) => c.to_string(),
        _ => "unknown".into(),
    }
}

fn github_run_when(r: &Value) -> String {
    let s = r["created_at"].as_str().or(r["updated_at"].as_str()).unwrap_or("");
    s.get(..16).unwrap_or(s).replace('T', " ")
}

/// Workflow runs → report blocks (text summary, metrics, table, links).
fn github_actions_report(req: &GitHubActionsRequest, v: &Value, authenticated: bool) -> Value {
    let runs: Vec<&Value> = v["workflow_runs"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let total = v["total_count"].as_u64().unwrap_or(runs.len() as u64);
    let clip = |s: &str, max: usize| s.chars().take(max).collect::<String>();
    let mut summary = format!("{} · {total} run(s)", req.repository);
    if let Some(w) = &req.workflow {
        summary.push_str(&format!(" · workflow {w}"));
    }
    if let Some(b) = &req.branch {
        summary.push_str(&format!(" · branch {b}"));
    }
    if let Some(s) = &req.status {
        summary.push_str(&format!(" · status {s}"));
    }
    if !authenticated {
        summary.push_str(". Anonymous GitHub read (rate limited); set [web.providers.github] api_key or GITHUB_TOKEN for private repositories");
    }
    let mut blocks = vec![json!({"type": "text", "text": summary})];
    if runs.is_empty() {
        blocks.push(json!({"type": "text", "text": "No workflow runs match this filter yet."}));
        return json!({"blocks": blocks});
    }
    let count = |pred: fn(&Value) -> bool| runs.iter().filter(|r| pred(r)).count();
    blocks.push(json!({"type": "metrics", "items": [
        {"label": "Runs", "value": runs.len().to_string()},
        {"label": "Succeeded", "value": count(|r| r["conclusion"] == "success").to_string()},
        {"label": "Failed", "value": count(|r| r["conclusion"] == "failure").to_string()},
        {"label": "Running", "value": count(|r| matches!(r["status"].as_str(), Some("in_progress" | "queued" | "requested" | "waiting" | "pending"))).to_string()},
    ]}));
    let rows: Vec<Value> = runs
        .iter()
        .take(GITHUB_ACTIONS_MAX_ROWS)
        .map(|r| json!([clip(r["name"].as_str().or(r["display_title"].as_str()).unwrap_or("(unnamed)"), 80), clip(r["head_branch"].as_str().unwrap_or("—"), 80), clip(&github_run_state(r), 80), clip(&github_run_when(r), 40)]))
        .collect();
    blocks.push(json!({"type": "table", "title": "Recent runs", "columns": ["Workflow", "Branch", "Status", "Created"], "rows": rows}));
    let links: Vec<Value> = runs
        .iter()
        .filter_map(|r| {
            let url = r["html_url"].as_str().filter(|u| u.starts_with("https://") && u.len() <= 2048 && !u.contains(char::is_whitespace))?;
            let n = r["run_number"].as_u64().map(|n| format!("#{n} ")).unwrap_or_default();
            let name = clip(r["name"].as_str().unwrap_or("workflow"), 120);
            Some(json!({"label": clip(&format!("{n}{name}"), 160), "url": url, "detail": r["head_branch"].as_str().map(|b| clip(b, 80))}))
        })
        .take(GITHUB_ACTIONS_MAX_LINKS)
        .collect();
    if !links.is_empty() {
        blocks.push(json!({"type": "links", "title": "Open on GitHub", "items": links}));
    }
    json!({"blocks": blocks})
}

/// Report HTML for a `session:github` widget: runs, an approval prompt (no request), or an
/// actionable error. The credential never appears here.
fn github_actions_body(env: &Env, w: &Widget) -> String {
    let req = match w.props.as_ref().map(validate_github_actions) {
        Some(Ok(r)) => r,
        Some(Err(e)) => return render_report(&github_actions_text(e)),
        None => return render_report(&github_actions_text("GitHub Actions props are missing: set repository (owner/repo) with dashboard widget_put.".into())),
    };
    let grant = req.grant();
    let declared = w.declared.as_ref().is_some_and(|d| d.tools.iter().any(|t| t.eq_ignore_ascii_case(&grant)));
    if !declared || w.grant_state != "granted" {
        let state = if w.grant_state == "rejected" { "was rejected" } else { "is waiting for approval" };
        return render_report(&github_actions_text(format!(
            "GitHub Actions reads are disabled: the `{grant}` capability {state}. Approve it in the dashboard permission card (op grant) to load runs; until then this widget makes no network request."
        )));
    }
    match github_actions_json(env, &req) {
        Ok((v, auth)) => render_report(&github_actions_report(&req, &v, auth)),
        Err(e) => render_report(&github_actions_text(format!("GitHub Actions read failed: {e}"))),
    }
}

/// Data-only report → HTML (every value escaped; no scripts).
pub fn render_report(v: &Value) -> String {
    let mut h = String::new();
    for b in v["blocks"].as_array().into_iter().flatten() {
        if let Some(t) = b["title"].as_str() {
            h.push_str(&format!("<h3>{}</h3>", esc_html(t)));
        }
        match b["type"].as_str().unwrap_or("") {
            "text" => h.push_str(&format!("<p>{}</p>", esc_html(b["text"].as_str().unwrap_or("")).replace('\n', "<br>"))),
            "metrics" => {
                h.push_str("<div class=\"row\">");
                for it in b["items"].as_array().into_iter().flatten() {
                    h.push_str(&format!("<div class=\"card\"><div class=\"muted\">{}</div><div class=\"metric\">{}</div>{}</div>", esc_html(it["label"].as_str().unwrap_or("")), esc_html(it["value"].as_str().unwrap_or("")), it["detail"].as_str().map(|d| format!("<div class=\"muted\">{}</div>", esc_html(d))).unwrap_or_default()));
                }
                h.push_str("</div>");
            }
            "table" => {
                h.push_str("<table><tr>");
                for c in b["columns"].as_array().into_iter().flatten() {
                    h.push_str(&format!("<th>{}</th>", esc_html(c.as_str().unwrap_or(""))));
                }
                h.push_str("</tr>");
                for r in b["rows"].as_array().into_iter().flatten() {
                    h.push_str("<tr>");
                    for c in r.as_array().into_iter().flatten() {
                        h.push_str(&format!("<td>{}</td>", esc_html(c.as_str().unwrap_or(""))));
                    }
                    h.push_str("</tr>");
                }
                h.push_str("</table>");
            }
            "chart" => h.push_str(&chart_svg(b)),
            "links" => {
                h.push_str("<ul>");
                for it in b["items"].as_array().into_iter().flatten() {
                    h.push_str(&format!("<li><a href=\"{}\" target=\"_blank\" rel=\"noopener noreferrer\">{}</a>{}</li>", esc_html(it["url"].as_str().unwrap_or("")), esc_html(it["label"].as_str().unwrap_or("")), it["detail"].as_str().map(|d| format!(" <span class=\"muted\">{}</span>", esc_html(d))).unwrap_or_default()));
                }
                h.push_str("</ul>");
            }
            _ => {}
        }
    }
    h
}

fn chart_svg(b: &Value) -> String {
    let pts: Vec<(String, f64)> = b["points"].as_array().into_iter().flatten().map(|p| (p["label"].as_str().unwrap_or("").to_string(), p["value"].as_f64().unwrap_or(0.0))).collect();
    if pts.is_empty() {
        return String::new();
    }
    let (w, h, pad) = (600.0, 220.0, 24.0);
    let max = pts.iter().map(|p| p.1).fold(f64::MIN, f64::max).max(0.0);
    let min = pts.iter().map(|p| p.1).fold(f64::MAX, f64::min).min(0.0);
    let span = if (max - min).abs() < f64::EPSILON { 1.0 } else { max - min };
    let step = (w - 2.0 * pad) / pts.len() as f64;
    let y = |v: f64| pad + (max - v) / span * (h - 2.0 * pad);
    let mut s = format!("<svg viewBox=\"0 0 {w} {h}\" width=\"100%\" role=\"img\"><line x1=\"{pad}\" x2=\"{}\" y1=\"{}\" y2=\"{}\" stroke=\"currentColor\" opacity=\".3\"/>", w - pad, y(0.0), y(0.0));
    if b["style"] == "line" {
        let path: Vec<String> = pts.iter().enumerate().map(|(i, p)| format!("{:.1},{:.1}", pad + step * (i as f64 + 0.5), y(p.1))).collect();
        s.push_str(&format!("<polyline fill=\"none\" stroke=\"var(--accent)\" stroke-width=\"2\" points=\"{}\"/>", path.join(" ")));
    } else {
        for (i, p) in pts.iter().enumerate() {
            let (top, bot) = (y(p.1.max(0.0)), y(p.1.min(0.0)));
            s.push_str(&format!("<rect x=\"{:.1}\" y=\"{top:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"var(--accent)\"><title>{}: {}</title></rect>", pad + step * i as f64 + step * 0.15, step * 0.7, (bot - top).max(1.0), esc_html(&p.0), p.1));
        }
    }
    for (i, p) in pts.iter().enumerate() {
        s.push_str(&format!("<text x=\"{:.1}\" y=\"{}\" font-size=\"10\" text-anchor=\"middle\" fill=\"currentColor\">{}</text>", pad + step * (i as f64 + 0.5), h - 6.0, esc_html(&p.0.chars().take(12).collect::<String>())));
    }
    s.push_str("</svg>");
    s
}

// ───────────────────────── widget documents ─────────────────────────

const BASE_STYLES: &str = ":root{color-scheme:light dark;--surface:#faf9f7;--card:#fff;--elevated:#fff;--text:#403c35;--text-strong:#211e1a;--muted:#6e6960;--border:#e8e4dc;--border-strong:#d6d0c5;--accent:#bd4531;--accent-fill:#bd4531;--accent-fg:#fff;--ok:#15803d;--warn:#b45309;--danger:#dc2626;--info:#2563eb;--radius:10px;--font-body:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,sans-serif;--font-mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--accent-subtle:color-mix(in srgb,var(--accent) 10%,transparent);--ok-subtle:color-mix(in srgb,var(--ok) 10%,transparent);--warn-subtle:color-mix(in srgb,var(--warn) 12%,transparent);--danger-subtle:color-mix(in srgb,var(--danger) 10%,transparent);--info-subtle:color-mix(in srgb,var(--info) 10%,transparent)}\n@media (prefers-color-scheme:dark){:root{--surface:#0e1015;--card:#161920;--elevated:#191c24;--text:#d4d4d8;--text-strong:#f4f4f5;--muted:#8b8b94;--border:#1e2028;--border-strong:#2e3040;--accent:#ff5c5c;--accent-fill:#d13c3c;--ok:#22c55e;--warn:#f59e0b;--danger:#ef4444;--info:#3b82f6}}\n*{box-sizing:border-box}html,body{margin:0}body{display:flow-root;font:14px/1.5 var(--font-body);color:var(--text)}h1,h2,h3{margin:0 0 8px;color:var(--text-strong);font-weight:600}h1{font-size:18px}h2{font-size:16px}h3{font-size:14px}p{margin:0 0 8px}a{color:var(--accent)}button{font:13px var(--font-body);color:var(--text);background:var(--card);border:1px solid var(--border-strong);border-radius:var(--radius);padding:6px 14px;cursor:pointer}button.primary{background:var(--accent-fill);color:var(--accent-fg);border-color:transparent}input,select,textarea{font:13px var(--font-body);color:var(--text);background:var(--elevated);border:1px solid var(--border-strong);border-radius:var(--radius);padding:6px 10px}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;font-weight:500;color:var(--muted);font-size:12px;padding:4px 8px}td{padding:6px 8px;border-top:1px solid var(--border)}code,pre{font-family:var(--font-mono);font-size:12px;background:var(--card);border-radius:4px}code{padding:1px 5px}pre{padding:10px;overflow-x:auto}.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:14px}.badge{display:inline-block;font-size:12px;padding:2px 10px;border-radius:999px;background:var(--accent-subtle);color:var(--accent)}.badge.ok{background:var(--ok-subtle);color:var(--ok)}.badge.warn{background:var(--warn-subtle);color:var(--warn)}.badge.danger{background:var(--danger-subtle);color:var(--danger)}.badge.info{background:var(--info-subtle);color:var(--info)}.metric{font-size:24px;font-weight:600;color:var(--text-strong)}.muted{color:var(--muted)}.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.svg-widget{display:grid;place-items:center}.svg-widget>svg{max-width:100%}";

/// Size reporting and `sendPrompt(text)` (a user click asks the host to submit a prompt).
const BRIDGE: &str = "<script>(()=>{if(!window.parent||window.parent===window)return;const post=window.parent.postMessage.bind(window.parent);let last=0;const report=()=>{const b=document.body;if(!b)return;const h=Math.ceil(Math.max(b.scrollHeight,b.offsetHeight));if(h&&h!==last){last=h;post({type:'ark:widget-size',height:h},'*');}};addEventListener('load',report);new ResizeObserver(report).observe(document.documentElement);setTimeout(report,50);let act=null;try{const ua=navigator.userActivation;if(ua)act=()=>ua.isActive;}catch{}const send=(text)=>{if(act&&!act())return false;post({type:'ark:widget-prompt',prompt:String(text)},'*');return true;};Object.defineProperty(window,'sendPrompt',{value:send,writable:false,configurable:false});Object.defineProperty(window,'ark',{value:Object.freeze({prompt:Object.freeze({send})}),writable:false,configurable:false});addEventListener('error',(e)=>post({type:'ark:widget-runtime-error',message:String(e.message||e.error||'error').slice(0,500),line:e.lineno,column:e.colno},'*'));})();</script>";

/// The CSP a widget document runs under: CDN scripts/styles, data images, no fetches
/// unless `connect` origins were declared and granted.
pub fn widget_csp(connect: &[String]) -> String {
    let cdn = CDN_ORIGINS.join(" ");
    let con = if connect.is_empty() { "'none'".to_string() } else { connect.join(" ") };
    format!("default-src 'none'; style-src 'unsafe-inline' {cdn}; script-src 'unsafe-inline' {cdn}; font-src data: {cdn}; img-src data:; media-src data: https: blob:; connect-src {con}; frame-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'")
}

/// Wrap agent markup in the isolated widget document shell.
pub fn build_document(title: &str, code: &str, connect: &[String]) -> String {
    let svg = code.trim_start().to_ascii_lowercase().starts_with("<svg");
    format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"referrer\" content=\"no-referrer\"><meta http-equiv=\"Content-Security-Policy\" content=\"{}\"><title>{}</title><style>{BASE_STYLES}</style></head><body{}>{BRIDGE}{code}</body></html>",
        widget_csp(connect),
        esc_html(title),
        if svg { " class=\"svg-widget\"" } else { "" }
    )
}

/// First structural error in an inline script: unbalanced brackets, an unterminated
/// string, template or comment. Returns (script index, line, column, message, offending line).
pub fn script_syntax_error(code: &str) -> Option<(usize, usize, usize, String, String)> {
    let lower = code.to_ascii_lowercase();
    let mut idx = 0;
    let mut from = 0;
    while let Some(open) = lower[from..].find("<script").map(|i| i + from) {
        idx += 1;
        let tag_end = lower[open..].find('>').map(|i| i + open)?;
        let attrs = &lower[open + 7..tag_end];
        let close = lower[tag_end..].find("</script").map(|i| i + tag_end).unwrap_or(code.len());
        from = close;
        let ty = attrs.split("type=").nth(1).map(|t| t.trim_start_matches(['"', '\'']).split(['"', '\'', ' ']).next().unwrap_or("").to_string());
        let js = ty.as_deref().is_none_or(|t| t.is_empty() || t == "module" || t.contains("javascript") || t.contains("ecmascript"));
        if attrs.contains("src=") || !js {
            continue;
        }
        let body = &code[tag_end + 1..close];
        if let Some((off, msg)) = scan_js(body) {
            let abs = tag_end + 1 + off;
            let line = code[..abs].matches('\n').count() + 1;
            let col = abs - code[..abs].rfind('\n').map(|i| i + 1).unwrap_or(0);
            let snippet = code.lines().nth(line - 1).unwrap_or("").trim().chars().take(160).collect();
            return Some((idx, line, col, msg, snippet));
        }
    }
    None
}

fn scan_js(s: &str) -> Option<(usize, String)> {
    let b = s.as_bytes();
    let mut stack: Vec<(u8, usize)> = Vec::new();
    let mut i = 0;
    // Whether a `/` here would start a regex literal (after an operator or opener).
    let mut regex_ok = true;
    while i < b.len() {
        let c = b[i];
        match c {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            b'/' if b.get(i + 1) == Some(&b'*') => match s[i + 2..].find("*/") {
                Some(e) => i += e + 4,
                None => return Some((i, "Unterminated comment".into())),
            },
            b'\'' | b'"' => {
                let start = i;
                i += 1;
                while i < b.len() && b[i] != c {
                    if b[i] == b'\\' {
                        i += 1;
                    } else if b[i] == b'\n' {
                        return Some((start, "Unterminated string constant".into()));
                    }
                    i += 1;
                }
                if i >= b.len() {
                    return Some((start, "Unterminated string constant".into()));
                }
                i += 1;
                regex_ok = false;
            }
            b'`' => {
                let start = i;
                i += 1;
                let mut depth = 0;
                loop {
                    if i >= b.len() {
                        return Some((start, "Unterminated template".into()));
                    }
                    match b[i] {
                        b'\\' => i += 1,
                        b'`' if depth == 0 => break,
                        b'$' if b.get(i + 1) == Some(&b'{') => {
                            depth += 1;
                            i += 1;
                        }
                        b'}' if depth > 0 => depth -= 1,
                        _ => {}
                    }
                    i += 1;
                }
                i += 1;
                regex_ok = false;
            }
            b'/' if regex_ok => {
                let start = i;
                i += 1;
                let mut class = false;
                while i < b.len() && (b[i] != b'/' || class) {
                    match b[i] {
                        b'\\' => i += 1,
                        b'[' => class = true,
                        b']' => class = false,
                        b'\n' => return Some((start, "Unterminated regular expression".into())),
                        _ => {}
                    }
                    i += 1;
                }
                if i >= b.len() {
                    return Some((start, "Unterminated regular expression".into()));
                }
                i += 1;
                regex_ok = false;
            }
            b'(' | b'[' | b'{' => {
                stack.push((c, i));
                i += 1;
                regex_ok = true;
            }
            b')' | b']' | b'}' => {
                let want = match c {
                    b')' => b'(',
                    b']' => b'[',
                    _ => b'{',
                };
                match stack.pop() {
                    Some((o, _)) if o == want => {}
                    _ => return Some((i, format!("Unexpected token '{}'", c as char))),
                }
                i += 1;
                regex_ok = c == b'}';
            }
            c if c.is_ascii_whitespace() => i += 1,
            c if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' => {
                let st = i;
                while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'$') {
                    i += 1;
                }
                regex_ok = matches!(&s[st..i], "return" | "typeof" | "case" | "do" | "else" | "in" | "of" | "new" | "delete" | "void" | "throw" | "yield" | "await");
            }
            _ => {
                i += 1;
                regex_ok = true;
            }
        }
    }
    stack.pop().map(|(o, at)| (at, format!("Unexpected end of input (unclosed '{}')", o as char)))
}

// ───────────────────────── viewer commands (focus_tab, presentation) ─────────────────────────

struct Viewers {
    /// session → (viewer id → last poll ms, pending commands)
    by_session: HashMap<String, (HashMap<String, u64>, Vec<Value>)>,
}

fn viewers() -> &'static Mutex<Viewers> {
    static V: OnceLock<Mutex<Viewers>> = OnceLock::new();
    V.get_or_init(|| Mutex::new(Viewers { by_session: HashMap::new() }))
}

const VIEWER_TTL_MS: u64 = 20_000;

/// Queue a command for the web UIs showing this session's dashboard; returns how many.
pub fn emit_command(session: &str, cmd: Value) -> usize {
    let mut v = viewers().lock().unwrap();
    let e = v.by_session.entry(session.to_string()).or_insert_with(|| (HashMap::new(), vec![]));
    let now = now_ms();
    e.0.retain(|_, t| now.saturating_sub(*t) < VIEWER_TTL_MS);
    if e.0.is_empty() {
        return 0;
    }
    e.1.push(json!({"seq": now, "command": cmd}));
    if e.1.len() > 20 {
        e.1.remove(0);
    }
    e.0.len()
}

/// A UI viewing `session`'s dashboard checks in; gets commands newer than its last poll.
pub fn poll(env: &Env, session: &str) -> Value {
    let _ = env;
    let mut v = viewers().lock().unwrap();
    let e = v.by_session.entry(session.to_string()).or_insert_with(|| (HashMap::new(), vec![]));
    let now = now_ms();
    let viewer = "web".to_string();
    let last = e.0.insert(viewer, now).unwrap_or(now);
    let cmds: Vec<Value> = e.1.iter().filter(|c| c["seq"].as_u64().unwrap_or(0) >= last).map(|c| c["command"].clone()).collect();
    e.1.retain(|c| c["seq"].as_u64().unwrap_or(0) >= now.saturating_sub(VIEWER_TTL_MS));
    json!({"commands": cmds, "revision": load(env, session).map(|b| b.revision).unwrap_or(0)})
}

// ───────────────────────── ARP for the web UI ─────────────────────────

pub fn list_boards(env: &Env) -> Value {
    let mut out = vec![];
    for e in std::fs::read_dir(env.dir.join("boards")).into_iter().flatten().flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "json") {
            if let Some(b) = read_json::<Board>(&p) {
                if !b.widgets.is_empty() {
                    out.push(json!({"session": b.session_key, "revision": b.revision, "tabs": b.tabs.len(), "widgets": b.widgets.len(), "titles": b.widgets.iter().filter_map(|w| w.title.clone()).take(6).collect::<Vec<_>>(), "updatedMs": b.updated_ms}));
                }
            }
        }
    }
    out.sort_by(|a, b| b["updatedMs"].as_u64().cmp(&a["updatedMs"].as_u64()));
    json!(out)
}

/// A board with each widget's renderable document (HTML wrapped, reports rendered).
pub fn board_json(env: &Env, session: &str) -> Result<Value, String> {
    let b = load(env, session)?;
    let card = cards::get(&env.dir, session);
    let widgets: Vec<Value> = b
        .widgets
        .iter()
        .map(|w| {
            let mut v = json!({"name": w.name, "tabId": w.tab_id, "title": w.title, "sizeW": w.size_w, "sizeH": w.size_h, "position": w.position, "presentation": w.presentation, "grantState": w.grant_state, "declared": w.declared, "pluginKind": w.plugin_kind, "revision": w.revision});
            let title = w.title.clone().unwrap_or_else(|| w.name.clone());
            match (w.html.as_deref(), w.plugin_kind.as_deref()) {
                (Some(h), _) => {
                    let connect = if w.grant_state == "granted" { w.declared.as_ref().map(|d| d.net_origins.clone()).unwrap_or_default() } else { vec![] };
                    v["document"] = build_document(&title, h, &connect).into();
                    v["csp"] = widget_csp(&connect).into();
                }
                (_, Some("session:report")) => v["document"] = build_document(&title, &render_report(w.props.as_ref().unwrap_or(&Value::Null)), &[]).into(),
                (_, Some("session:progress")) => {
                    let s = w.props.as_ref().and_then(|p| p["sessionKey"].as_str()).unwrap_or(session);
                    let c = if s == session { card.clone() } else { cards::get(&env.dir, s) };
                    v["document"] = build_document(&title, &cards::render_html(c.as_ref()), &[]).into();
                }
                (_, Some("session:website")) => v["url"] = w.props.as_ref().map(|p| p["url"].clone()).unwrap_or(Value::Null),
                (_, Some("session:github")) => v["document"] = build_document(&title, &github_actions_body(env, w), &[]).into(),
                _ => {}
            }
            v
        })
        .collect();
    Ok(json!({"sessionKey": b.session_key, "revision": b.revision, "tabs": b.tabs, "widgets": widgets, "defaultPresentation": b.default_presentation.clone().unwrap_or_else(|| "split".into()), "progressCard": card}))
}

/// Operator actions from the UI: layout ops, and approving / rejecting declared capabilities.
pub fn ui_update(env: &Env, p: &Value) -> Result<Value, String> {
    let session = p["session"].as_str().unwrap_or("");
    match p["op"]["kind"].as_str() {
        Some("grant") | Some("reject") => {
            let name = p["op"]["name"].as_str().unwrap_or("").to_string();
            let grant = p["op"]["kind"] == "grant";
            mutate(env, session, |b| {
                let w = b.widgets.iter_mut().find(|w| w.name == name).ok_or_else(|| format!("board widget not found: {name}"))?;
                if w.declared.is_none() {
                    return Err("widget declares no capabilities".into());
                }
                w.grant_state = if grant { "granted" } else { "rejected" }.into();
                w.granted_sha256 = if grant { w.html.as_deref().map(|h| ark_net::crypto::hex(&ark_net::crypto::sha256(h.as_bytes()))) } else { None };
                Ok(())
            })?;
        }
        Some("cron.trigger") => {
            let (name, job) = (p["op"]["name"].as_str().unwrap_or(""), p["op"]["jobId"].as_str().unwrap_or(""));
            let b = load(env, session)?;
            let w = b.widgets.iter().find(|w| w.name == name).ok_or_else(|| format!("board widget not found: {name}"))?;
            let want = format!("cron.trigger:{job}");
            if w.grant_state != "granted" || !w.declared.as_ref().is_some_and(|d| d.tools.contains(&want)) {
                return Err(format!("widget {name} has no granted `{want}` capability"));
            }
            let k = env.kernel()?.clone();
            use ark_kernel::automation::{jobs_path, read_list, run_job, Job};
            let job = read_list::<Job>(&jobs_path(&k.paths.data))?.into_iter().find(|j| j.id == job).ok_or_else(|| format!("no cron job `{job}`"))?;
            std::thread::spawn(move || run_job(&k, &job));
            return Ok(json!({"ok": true, "triggered": want}));
        }
        _ => {
            let op = p["op"].clone();
            mutate(env, session, |b| apply_op(b, &op))?;
        }
    }
    board_json(env, session)
}

// ───────────────────────── show_widget ─────────────────────────

pub struct ShowWidget(pub Arc<Env>);

fn slug(title: &str) -> String {
    let mut s = String::new();
    for c in title.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c);
        } else if !s.ends_with('-') {
            s.push('-');
        }
    }
    let s = s.trim_matches('-').to_string();
    if !s.is_empty() && s.len() <= 64 {
        return s;
    }
    let suffix = &ark_net::crypto::hex(&ark_net::crypto::sha256(title.as_bytes()))[..8];
    let prefix: String = if s.is_empty() { "widget".into() } else { s.chars().take(55).collect::<String>().trim_end_matches('-').to_string() };
    format!("{prefix}-{suffix}")
}

impl ShowWidget {
    fn run(&self, ctx: &ToolCtx, p: &Value) -> Result<(String, Option<Value>), String> {
        let env = &self.0;
        let inline = env.cfg.widgets.inline;
        let title = p["title"].as_str().map(str::trim).filter(|t| !t.is_empty()).ok_or("title required")?.to_string();
        let raw = p["widget_code"].as_str().unwrap_or("");
        let kind = p["kind"].as_str().unwrap_or("html");
        let report = p.get("report").filter(|r| !r.is_null() && !(r.as_object().is_some_and(|o| o.is_empty()) && !raw.trim().is_empty()));
        let pin = p["pin"] == true;
        let target = p["presentation"]["target"].as_str();
        if report.is_some() {
            if !pin || !raw.is_empty() || p.get("kind").is_some_and(|k| !k.is_null()) || p.get("capabilities").is_some_and(|c| !c.is_null()) || target.is_some() {
                return Err("Reports require pin=true; omit widget_code, kind, capabilities, and presentation.target. Use HTML for an inline or executable widget".into());
            }
        } else {
            if raw.trim().is_empty() {
                return Err("widget_code required".into());
            }
            if kind != "html" {
                return Err(format!("widget kind {kind:?} is unavailable; enable the plugin that provides it and retry"));
            }
            if raw.len() > WIDGET_HTML_MAX_BYTES {
                return Err(format!("widget_code exceeds {WIDGET_HTML_MAX_BYTES} bytes"));
            }
            if let Some((i, line, col, msg, snip)) = script_syntax_error(raw) {
                return Err(format!("widget_code has a JavaScript syntax error in inline script {i} at line {line}, column {col}: {msg}. Offending line: {snip}. Fix the script and call show_widget again."));
            }
        }
        if !inline && !pin && target != Some("node_panel") {
            return Err("inline widget hosting is disabled; set pin=true to place the widget on the session dashboard".into());
        }
        let declared = parse_declared(p.get("capabilities").unwrap_or(&Value::Null))?;
        if declared.is_some() && !pin {
            return Err("capabilities require pin=true".into());
        }
        if let Some(t) = target.filter(|t| !matches!(*t, "assistant_message" | "node_panel")) {
            return Err(format!("presentation.target must be assistant_message or node_panel, got {t}"));
        }
        let code = raw.trim();
        let mut pinned_text = String::new();
        let mut pinned_name = None;
        let mut grant = None;
        if pin {
            let explicit = p["name"].as_str();
            if let Some(n) = explicit.filter(|n| !valid_widget_name(n)) {
                return Err(format!("name must match ^[a-z0-9][a-z0-9._-]{{0,63}}$, got {n}"));
            }
            if let Some(t) = p["tab"].as_str().filter(|t| !valid_tab_id(t)) {
                return Err(format!("tab must be a lowercase slug up to 40 characters, got {t}"));
            }
            let name = explicit.map(str::to_string).unwrap_or_else(|| slug(&title));
            let short: String = title.chars().take(80).collect();
            if report.is_none() {
                let doc = build_document(&short, code, declared.as_ref().map(|d| d.net_origins.as_slice()).unwrap_or(&[]));
                if doc.len() > WIDGET_HTML_MAX_BYTES {
                    return Err(format!("pin exceeds effective dashboard budget ({WIDGET_HTML_MAX_BYTES} UTF-8 bytes after wrapping)"));
                }
            }
            if let Some(r) = report {
                validate_report(r)?;
            }
            let gen = explicit.is_none().then(|| ark_net::crypto::hex(&ark_net::crypto::sha256(title.trim().as_bytes())));
            let (board, resolved) = put(
                env,
                &ctx.session_id,
                Put {
                    name,
                    title: Some(short),
                    html: report.is_none().then(|| code.to_string()),
                    plugin_kind: report.is_some().then(|| "session:report".to_string()),
                    props: report.cloned(),
                    presentation: p["presentation"]["frame"].as_str().map(str::to_string),
                    declared: declared.clone(),
                    tab: p["tab"].as_str().map(str::to_string),
                    size: p["size"].as_str().map(str::to_string),
                    after: p["after"].as_str().map(str::to_string),
                    generated_key: gen,
                },
            )?;
            let w = board.widgets.iter().find(|w| w.name == resolved).ok_or("Dashboard did not return the pinned widget; read the board and retry.")?;
            pinned_text = format!("pinned to dashboard tab {} as {resolved}{}", w.tab_id, p["size"].as_str().map(|s| format!(" ({s})")).unwrap_or_default());
            match w.grant_state.as_str() {
                "pending" => pinned_text.push_str("; capabilities pending: ask the operator to review and approve the dashboard permission card"),
                "rejected" => pinned_text.push_str("; capabilities rejected: review the requested access and session permission policy with the operator before retrying"),
                "granted" => pinned_text.push_str("; capabilities granted"),
                _ => {}
            }
            grant = Some(w.grant_state.clone()).filter(|g| g != "none");
            pinned_name = Some(resolved);
        }
        let routed = report.is_none() && (inline || target == Some("node_panel"));
        if !routed {
            let status = match grant.as_deref() {
                Some(g @ ("pending" | "rejected")) => g.to_string(),
                _ => "pinned".into(),
            };
            let d = json!({"status": status, "boardWidgetName": pinned_name, "capabilityState": grant, "text": format!("Widget {pinned_text}. Open this dashboard in the web UI to view it.")});
            return Ok((d.to_string(), None));
        }
        let wrapped = build_document(&title, code, &[]);
        if wrapped.len() > WIDGET_HTML_MAX_BYTES {
            return Err(format!("widget document after wrapping exceeds {WIDGET_HTML_MAX_BYTES} bytes"));
        }
        let doc = canvas::create_document(&env.dir, &title, &wrapped, Some(&format!("session:{}", ctx.session_id)), WIDGET_MAX_PER_SCOPE)?;
        let url = format!("{}{}", env.base_url, doc.entry_url);
        let mut presented = None;
        let mut failure = None;
        if target == Some("node_panel") {
            match canvas::present_on_node(env, None, &url) {
                Ok(n) => presented = Some(n),
                Err(e) => failure = Some(e),
            }
            if let (Some(e), false) = (&failure, inline) {
                let msg = if e.ends_with('.') { e.clone() } else { format!("{e}.") };
                if let Some(n) = &pinned_name {
                    let d = json!({"status": "partial", "boardWidgetName": n, "capabilityState": grant, "presentation": {"target": "node_panel", "status": "failed", "error": e}, "text": format!("Widget {pinned_text}, but presentation failed: {msg}")});
                    return Ok((d.to_string(), None));
                }
                return Err(format!("Widget presentation failed: {msg}"));
            }
        }
        let presentation_text = match (&presented, &failure) {
            (Some((id, name)), _) => format!("; presented on {name} ({id})"),
            (_, Some(e)) => format!("; {}{} The widget is available inline here. Pair a canvas-capable device, then retry.", e, if e.ends_with('.') { "" } else { "." }),
            _ => String::new(),
        };
        let d = json!({
            "kind": "canvas",
            "capabilityState": grant,
            "presentation": {"target": if presented.is_some() { "node_panel" } else { "assistant_message" }, "title": title, "sandbox": "scripts", "node": presented.as_ref().map(|(id, n)| json!({"id": id, "name": n}))},
            "view": {"id": doc.id, "url": url, "boardWidgetName": pinned_name},
            "text": format!("Widget hosted at {url}{}{presentation_text}", if pinned_text.is_empty() { String::new() } else { format!("; {pinned_text}") }),
        });
        let ui = json!({"server": "ark", "tool": "show_widget", "title": title, "html": wrapped, "csp": {"resourceDomains": CDN_ORIGINS}, "url": url});
        Ok((d.to_string(), Some(ui)))
    }
}

impl Tool for ShowWidget {
    fn spec(&self) -> ToolSpec {
        let usage = if self.0.cfg.widgets.inline { "Keep one-off visualizations inline; pin for explicit dashboard requests or multiple non-code visualizations." } else { "Inline previews are unavailable; set pin=true to save to the session dashboard." };
        ToolSpec {
            name: "show_widget".into(),
            description: format!("Visual helps? Make widget. Do not wait for ask. {usage} Update pinned HTML by name. Use for code architecture, execution traces, performance comparisons, interactive explanations, UI mockups, and dashboards. Text clearer? Skip. Send an HTML/SVG fragment (optional style/script tags, not a full document) in widget_code. Scripts, stylesheets, and fonts may load from {}; pin library versions. Images must be data URLs. Inline widgets cannot fetch APIs; pinned widgets may fetch declared capabilities.netOrigins after the operator approves. A user click may call sendPrompt(text) to ask the agent a follow-up. `title` is host metadata: do not repeat it inside the widget. Use host theme variables such as --text, --muted, --card, --border, --accent, --font-body, --font-mono. Inline script syntax errors return line and column; fix and retry. presentation.target=node_panel also shows it on a paired device's canvas. For data reports prefer `report` with pin=true (renders natively): {REPORT_GUIDANCE}", CDN_ORIGINS.join(", ")),
            input_schema: json!({"type": "object", "properties": {
                "title": {"type": "string", "description": "Short host title; do not repeat it inside the widget"},
                "widget_code": {"type": "string", "description": "HTML or SVG fragment. Use fluid widths; wrap or stack narrow layouts."},
                "report": {"type": "object", "description": "Native dashboard data; requires pin=true. Omit widget_code, kind, capabilities, and presentation.target."},
                "kind": {"type": "string", "enum": ["html"], "description": "Widget source kind (html)"},
                "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$", "description": "Stable dashboard widget name; reuse it with pin=true to update"},
                "pin": {"type": "boolean", "description": "Pin only for an explicit dashboard request or multiple non-code visualizations"},
                "tab": {"type": "string", "pattern": "^[a-z0-9-]{1,40}$", "description": "Dashboard tab slug"},
                "size": {"type": "string", "enum": ["sm", "md", "lg", "xl", "full"]},
                "presentation": {"type": "object", "properties": {"target": {"type": "string", "enum": ["assistant_message", "node_panel"]}, "frame": {"type": "string", "enum": ["card", "full-bleed", "frameless"]}}},
                "after": {"type": "string", "description": "Place after this dashboard widget name"},
                "capabilities": {"type": "object", "properties": {"netOrigins": {"type": "array", "items": {"type": "string"}, "description": "Exact HTTPS origins the pinned widget may fetch after approval"}, "tools": {"type": "array", "items": {"type": "string"}, "description": "prompt or cron.trigger:<jobId>"}}}
            }, "required": ["title"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        if input["presentation"]["target"] == "node_panel" {
            return vec![Effect::Net { dest: "node:canvas".into(), payload: input["title"].as_str().unwrap_or("").to_string() }];
        }
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok((text, ui)) => {
                let mut o = ToolOutput::ok(text);
                o.ui_resource = ui;
                o
            }
            Err(e) => ToolOutput::err(e),
        }
    }
}

// ───────────────────────── dashboard ─────────────────────────

pub struct DashboardTool(pub Arc<Env>);

fn snapshot_text(b: &Board) -> String {
    let mut owners = serde_json::Map::new();
    for w in &b.widgets {
        let how = if w.content_owner == "html" { "Use show_widget (pin=true) with the same name." } else { "Use widget_put with the same name and pluginKind." };
        owners.insert(w.content_owner.clone(), how.into());
    }
    let widgets: Vec<Value> = b.widgets.iter().map(|w| json!({"name": w.name, "tabId": w.tab_id, "title": w.title, "contentKind": w.content_kind, "contentOwner": w.content_owner, "pluginKind": w.plugin_kind, "sizeW": w.size_w, "sizeH": w.size_h, "position": w.position, "grantState": w.grant_state, "revision": w.revision})).collect();
    let mut d = json!({"sessionKey": b.session_key, "revision": b.revision, "tabs": b.tabs.iter().map(|t| json!({"tabId": t.tab_id, "title": t.title, "position": t.position})).collect::<Vec<_>>(), "widgets": widgets, "defaultPresentation": b.default_presentation.clone().unwrap_or_else(|| "split".into())});
    if !b.widgets.is_empty() {
        d["contentUpdatePaths"] = Value::Object(owners);
    }
    format!("Dashboard revision {}: {} tabs, {} widgets\n{d}", b.revision, b.tabs.len(), b.widgets.len())
}

impl DashboardTool {
    fn run(&self, ctx: &ToolCtx, p: &Value) -> Result<String, String> {
        let env = &self.0;
        let session = &ctx.session_id;
        let action = p["action"].as_str().ok_or("action required")?;
        let tab_id = || -> Result<String, String> { p["tabId"].as_str().filter(|t| valid_tab_id(t)).map(str::to_string).ok_or_else(|| "tabId must be a lowercase slug up to 40 characters".to_string()) };
        let presentation = || -> Result<&str, String> { p["presentation"].as_str().filter(|x| matches!(*x, "split" | "expanded")).ok_or_else(|| "presentation must be split or expanded".to_string()) };
        let name = || -> Result<String, String> { p["name"].as_str().filter(|n| valid_widget_name(n)).map(str::to_string).ok_or_else(|| "name required (^[a-z0-9][a-z0-9._-]{0,63}$)".to_string()) };
        match action {
            "read" => Ok(snapshot_text(&load(env, session)?)),
            "set_default_presentation" => {
                let pr = presentation()?.to_string();
                mutate(env, session, |b| {
                    b.default_presentation = Some(pr.clone());
                    Ok(())
                })?;
                Ok(format!("Dashboard default presentation saved: {pr}. Applies on subsequent opens; personal viewer overrides take precedence.\n{}", json!({"ok": true, "sessionKey": session, "defaultPresentation": pr})))
            }
            "focus_tab" | "set_presentation" => {
                let cmd = if action == "focus_tab" { json!({"kind": "focus_tab", "tabId": tab_id()?}) } else { json!({"kind": "set_chat_dock", "dock": if presentation()? == "expanded" { "hidden" } else { "right" }}) };
                let n = emit_command(session, cmd);
                Ok(if n == 0 { format!("Dashboard unavailable. Connect the web UI and retry.\n{}", json!({"status": "unavailable", "code": "UNAVAILABLE", "message": "Connect the web UI and retry."})) } else { format!("Dashboard command sent to {n} client(s)\n{}", json!({"ok": true, "delivered": n})) })
            }
            "widget_put" => {
                let kind = p["pluginKind"].as_str().ok_or("pluginKind required")?;
                let ok_kind = kind.split_once(':').is_some_and(|(a, b)| !a.is_empty() && !b.is_empty() && a.len() <= 64 && b.len() <= 64 && a.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') && valid_widget_name(b));
                if !ok_kind {
                    return Err("pluginKind must use the <pluginId>:<name> format".into());
                }
                if !PLUGIN_KINDS.contains(&kind) {
                    return Err(format!("widget kind {kind:?} is unavailable; enable the plugin that provides it and retry"));
                }
                if let Some(t) = p["tabId"].as_str().filter(|t| !valid_tab_id(t)) {
                    return Err(format!("tabId must be a lowercase slug up to 40 characters, got {t}"));
                }
                let props = match p.get("props") {
                    None | Some(Value::Null) => json!({}),
                    Some(v) if v.is_object() => v.clone(),
                    _ => return Err("props must be an object".into()),
                };
                validate_props(kind, &props)?;
                // A session:github widget owns the exact repository grant; the board reads
                // GitHub only after the operator approves it (no silent network access).
                let declared = if kind == GITHUB_ACTIONS_KIND {
                    let req = validate_github_actions(&props)?;
                    let mut d = parse_declared(p.get("capabilities").unwrap_or(&Value::Null))?.unwrap_or_default();
                    if !d.tools.iter().any(|t| t.eq_ignore_ascii_case(&req.grant())) {
                        d.tools.push(req.grant());
                        d.tools.sort();
                        d.tools.dedup();
                    }
                    Some(d)
                } else {
                    None
                };
                let (b, _) = put(env, session, Put { name: name()?, title: p["title"].as_str().map(str::to_string), html: None, plugin_kind: Some(kind.into()), props: Some(props), presentation: None, declared, tab: p["tabId"].as_str().map(str::to_string), size: p["size"].as_str().map(str::to_string), after: p["after"].as_str().map(str::to_string), generated_key: None })?;
                Ok(snapshot_text(&b))
            }
            "tab_create" | "tab_update" | "tab_delete" | "tabs_reorder" | "widget_move" | "widget_resize" | "widget_remove" => {
                let mut op = p.clone();
                op["kind"] = action.into();
                if action == "widget_move" && !p["position"].is_null() && !p["after"].is_null() {
                    return Err("widget_move accepts either position or after, not both".into());
                }
                if action == "tab_update" && p["title"].is_null() && p["position"].is_null() {
                    return Err("tab_update requires title or position".into());
                }
                if action.starts_with("widget_") {
                    name()?;
                }
                if action == "widget_resize" && (!p["sizeW"].is_i64() || !p["sizeH"].is_i64()) {
                    return Err("sizeW and sizeH required".into());
                }
                let b = mutate(env, session, |b| apply_op(b, &op))?;
                Ok(snapshot_text(&b))
            }
            other => Err(format!("Unknown dashboard action: {other}")),
        }
    }
}

impl Tool for DashboardTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "dashboard".into(),
            description: format!("Read and arrange this session's dashboard (shown in the web UI); widget_put updates plugin widgets only. Actions: read snapshot; tab_create/tab_update/tab_delete/tabs_reorder; widget_put/widget_move/widget_resize/widget_remove; focus_tab opens a tab in connected web UIs; set_presentation shows the dashboard alongside chat (split) or across the task area (expanded); both need a connected web UI and do not save a default. set_default_presentation saves split or expanded. Widgets use stable names; update HTML widgets through show_widget. Prefer session:report for data reports ({REPORT_GUIDANCE}). Use session:progress props {{sessionKey?}} for live session progress. Use session:website props {{url}} for a live HTTPS website ({WEBSITE_GUIDANCE}). {GITHUB_ACTIONS_GUIDANCE} Sizes: sm=3x3, md=6x4, lg=8x6, xl=12x8, full=12x8."),
            input_schema: json!({"type": "object", "properties": {
                "action": {"type": "string", "enum": ["read", "tab_create", "tab_update", "tab_delete", "tabs_reorder", "widget_put", "widget_move", "widget_resize", "widget_remove", "focus_tab", "set_presentation", "set_default_presentation"]},
                "tabId": {"type": "string", "pattern": "^[a-z0-9-]{1,40}$"},
                "title": {"type": "string", "minLength": 1, "maxLength": 80},
                "presentation": {"type": "string", "enum": ["split", "expanded"]},
                "position": {"type": "integer", "minimum": 0},
                "tabIds": {"type": "array", "items": {"type": "string"}},
                "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$"},
                "after": {"type": "string"},
                "sizeW": {"type": "integer", "minimum": 1, "maximum": 12},
                "sizeH": {"type": "integer", "minimum": 1, "maximum": 20},
                "size": {"type": "string", "enum": ["sm", "md", "lg", "xl", "full"]},
                "pluginKind": {"type": "string", "enum": PLUGIN_KINDS, "description": "session:report, session:progress, session:website or session:github"},
                "props": {"type": "object", "description": "Widget JSON props (maximum 8KB encoded)"}
            }, "required": ["action"], "additionalProperties": false}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, _input: &Value) -> Vec<Effect> {
        vec![]
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok(t) => ToolOutput::ok(t),
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;

    // ───────────────────── session:github (GitHub Actions board) ─────────────────────

    #[test]
    fn github_actions_props_match_upstream_contract() {
        let ok = validate_github_actions(&json!({"repository": "Acme/App", "perPage": 5, "status": "failure", "branch": "release/1.0", "created": ">=2026-11-01", "workflow": "ci.yml"})).unwrap();
        assert_eq!(ok.repository, "acme/app");
        assert_eq!(ok.grant(), "github.actions.runs:acme/app");
        assert_eq!((ok.per_page, ok.exclude_pull_requests), (5, true));
        assert_eq!(ok.path_and_query(), "/repos/acme/app/actions/workflows/ci.yml/runs?per_page=5&exclude_pull_requests=true&branch=release%2F1.0&status=failure&created=%3E%3D2026-11-01");
        // Defaults and a numeric workflow id.
        let d = validate_github_actions(&json!({"repository": "acme/app", "workflow": 42, "excludePullRequests": false})).unwrap();
        assert_eq!(d.path_and_query(), "/repos/acme/app/actions/workflows/42/runs?per_page=20&exclude_pull_requests=false");
        // Upstream's closed contract: every rejection names the correct usage.
        for bad in [
            json!({}),
            json!({"repository": "acme"}),
            json!({"repository": "acme/"}),
            json!({"repository": "acme/.."}),
            json!({"repository": "-acme/app"}),
            json!({"repository": "acme/app/x"}),
            json!({"repository": "acme/app", "workflow": 0}),
            json!({"repository": "acme/app", "workflow": "007"}),
            json!({"repository": "acme/app", "workflow": ".yml"}),
            json!({"repository": "acme/app", "workflow": true}),
            json!({"repository": "acme/app", "perPage": 0}),
            json!({"repository": "acme/app", "perPage": 31}),
            json!({"repository": "acme/app", "perPage": 2.5}),
            json!({"repository": "acme/app", "status": "bogus"}),
            json!({"repository": "acme/app", "created": "2026-02-30"}),
            json!({"repository": "acme/app", "created": "2026-1-1"}),
            json!({"repository": "acme/app", "branch": "a\u{1}b"}),
            json!({"repository": "acme/app", "excludePullRequests": "yes"}),
            json!({"repository": "acme/app", "owner": "x"}),
        ] {
            let e = validate_github_actions(&bad).unwrap_err();
            assert!(e.starts_with("Invalid GitHub Actions parameters:"), "{bad} → {e}");
            assert!(e.contains("repository (owner/repo)"), "{bad} → {e}");
        }
        // `created` accepts a day, one comparison, or a range (leap years included).
        for good in ["2026-11-01", "<2026-11-01", "<=2026-11-01", ">2026-11-01", "2026-11-01..2026-11-30", "2024-02-29"] {
            assert!(validate_github_actions(&json!({"repository": "acme/app", "created": good})).is_ok(), "{good}");
        }
        assert!(validate_github_actions(&json!({"repository": "acme/app", "created": ">=2026-11-01..2026-11-30"})).is_err());
        // The grant normalizes to lowercase and rejects malformed repositories.
        assert_eq!(normalize_github_actions_grant("github.actions.runs:Acme/App").as_deref(), Some("github.actions.runs:acme/app"));
        assert!(normalize_github_actions_grant("github.actions.runs:acme").is_none());
        let d = parse_declared(&json!({"tools": ["github.actions.runs:Acme/App", "prompt"]})).unwrap().unwrap();
        assert_eq!(d.tools, vec!["github.actions.runs:acme/app".to_string(), "prompt".to_string()]);
        assert!(parse_declared(&json!({"tools": ["github.actions.runs:acme"]})).unwrap_err().contains("GitHub Actions grant requires owner/repo"));
        assert!(parse_declared(&json!({"tools": ["nope"]})).unwrap_err().contains("github.actions.runs:<owner>/<repo>"));
        // Only api.github.com (or a loopback test server) may be read.
        let (env, _) = testkit::env("gh-base", &[], "");
        assert_eq!(github_api_base(&env).unwrap(), "https://api.github.com");
        for bad in ["https://evil.example", "https://api.github.com.evil.example", "http://10.0.0.1:1", "https://api.github.com/?x=1"] {
            let mut e = (*env).clone();
            e.cfg.widgets.github_api = Some(bad.into());
            assert!(github_api_base(&e).is_err(), "{bad} must be refused");
        }
        let mut e = (*env).clone();
        e.cfg.widgets.github_api = Some("http://127.0.0.1:9/".into());
        assert_eq!(github_api_base(&e).unwrap(), "http://127.0.0.1:9");
    }

    /// A board widget reads GitHub only after approval, then renders runs as report blocks.
    #[test]
    fn github_actions_widget_renders_runs_after_approval() {
        let (url, seen) = testkit::server(Box::new(|r| {
            let body = if r.path.starts_with("/repos/acme/app/actions/runs") {
                json!({"total_count": 2, "workflow_runs": [
                    {"name": "CI", "head_branch": "main", "status": "completed", "conclusion": "success", "created_at": "2026-11-03T09:41:12Z", "run_number": 12, "html_url": "https://github.com/acme/app/actions/runs/12"},
                    {"name": "<Deploy>", "head_branch": "release/1.0", "status": "in_progress", "created_at": "2026-11-03T10:02:00Z", "run_number": 13, "html_url": "https://github.com/acme/app/actions/runs/13"},
                ]})
            } else {
                return (404, vec![], "{}".into());
            };
            (200, vec![], body.to_string())
        }));
        let (env, _) = testkit::env("gh-runs", &[], &format!("[widgets]\ngithub_api = \"{url}\"\ngithub_token = \"ghs_widget\"\n"));
        let ws = testkit::temp("gh-ws");
        let ctx = testkit::ctx(&env, &ws);
        let dash = DashboardTool(env.clone());
        let o = dash.call(&ctx, json!({"action": "widget_put", "name": "actions", "title": "CI", "pluginKind": "session:github", "props": {"repository": "Acme/App", "perPage": 5, "status": "failure"}}));
        assert!(!o.is_error, "{}", o.content);
        assert!(o.content.contains("\"grantState\":\"pending\""), "{}", o.content);
        // Disabled until the operator approves: no request, and the document says how to approve.
        let b = board_json(&env, "s1").unwrap();
        let doc = b["widgets"].as_array().unwrap().iter().find(|w| w["name"] == "actions").unwrap()["document"].as_str().unwrap().to_string();
        assert!(doc.contains("GitHub Actions reads are disabled") && doc.contains("github.actions.runs:acme/app"), "{doc}");
        assert!(seen.lock().unwrap().is_empty(), "no network before approval");
        clear_github_actions_cache();
        let b = ui_update(&env, &json!({"session": "s1", "op": {"kind": "grant", "name": "actions"}})).unwrap();
        let doc = b["widgets"].as_array().unwrap().iter().find(|w| w["name"] == "actions").unwrap()["document"].as_str().unwrap().to_string();
        assert!(doc.contains("<th>Workflow</th>") && doc.contains("CI") && doc.contains("release/1.0"), "{doc}");
        assert!(doc.contains("completed · success") && doc.contains("<div class=\"metric\">2</div>"), "{doc}");
        assert!(doc.contains("https://github.com/acme/app/actions/runs/12"), "{doc}");
        assert!(doc.contains("&lt;Deploy&gt;"), "API text is escaped: {doc}");
        assert!(!doc.contains("ghs_widget"), "the token never reaches the document");
        // perPage/status/branch really are in the query, and the token authenticates the read.
        let reqs = seen.lock().unwrap().clone();
        let q = reqs.iter().find(|r| r.path.starts_with("/repos/acme/app/actions/runs")).expect("one read");
        assert!(q.path.contains("per_page=5") && q.path.contains("status=failure") && q.path.contains("exclude_pull_requests=true"), "{}", q.path);
        assert!(q.headers.iter().any(|(k, v)| k == "authorization" && v == "Bearer ghs_widget"), "{:?}", q.headers);
        assert!(q.headers.iter().any(|(k, v)| k == "accept" && v == "application/vnd.github+json"));
        // Re-putting the same repository keeps the grant; a new repository needs approval again.
        let o = dash.call(&ctx, json!({"action": "widget_put", "name": "actions", "pluginKind": "session:github", "props": {"repository": "acme/app"}}));
        assert!(o.content.contains("\"grantState\":\"granted\""), "{}", o.content);
        let o = dash.call(&ctx, json!({"action": "widget_put", "name": "actions", "pluginKind": "session:github", "props": {"repository": "acme/other"}}));
        assert!(o.content.contains("\"grantState\":\"pending\""), "{}", o.content);
        // widget_put keeps the closed contract.
        assert!(dash.call(&ctx, json!({"action": "widget_put", "name": "bad", "pluginKind": "session:github", "props": {"repository": "acme/app", "perPage": 99}})).content.contains("perPage must be an integer from 1 to 30"));
        assert!(dash.call(&ctx, json!({"action": "widget_put", "name": "bad", "pluginKind": "session:github", "props": {"repository": "acme/app", "deep": 1}})).content.contains("unexpected field"));
    }

    /// 404/401 reads and anonymous reads are actionable, never silent, and stay in the document.
    #[test]
    fn github_actions_reads_report_http_errors_and_anonymous_access() {
        let (url, seen) = testkit::server(Box::new(|r| {
            if r.path.starts_with("/repos/acme/missing") {
                return (404, vec![], "{\"message\":\"Not Found\"}".into());
            }
            if r.path.starts_with("/repos/acme/private") {
                return (401, vec![], "{\"message\":\"Bad credentials\"}".into());
            }
            (200, vec![], json!({"total_count": 1, "workflow_runs": [{"name": "CI", "head_branch": "main", "status": "completed", "conclusion": "success", "created_at": "2026-11-03T09:41:12Z", "run_number": 1, "html_url": "https://github.com/acme/open/actions/runs/1"}]}).to_string())
        }));
        let (env, _) = testkit::env("gh-err", &[], &format!("[widgets]\ngithub_api = \"{url}\"\ngithub_token = \"ghs_widget\"\n"));
        let ws = testkit::temp("gh-err-ws");
        let ctx = testkit::ctx(&env, &ws);
        let dash = DashboardTool(env.clone());
        for (name, repo) in [("missing", "acme/missing"), ("private", "acme/private"), ("open", "acme/open")] {
            let o = dash.call(&ctx, json!({"action": "widget_put", "name": name, "pluginKind": "session:github", "props": {"repository": repo}}));
            assert!(!o.is_error, "{}", o.content);
            ui_update(&env, &json!({"session": "s1", "op": {"kind": "grant", "name": name}})).unwrap();
        }
        let b = board_json(&env, "s1").unwrap();
        let doc = |n: &str| b["widgets"].as_array().unwrap().iter().find(|w| w["name"] == n).unwrap()["document"].as_str().unwrap().to_string();
        let missing = doc("missing");
        assert!(missing.contains("HTTP 404") && missing.contains("Check repository owner/repo"), "{missing}");
        assert!(missing.contains("GitHub Actions read failed"), "{missing}");
        let private = doc("private");
        assert!(private.contains("HTTP 401") && private.contains("github_token") && private.contains("GITHUB_TOKEN"), "{private}");
        assert!(doc("open").contains("CI"), "the healthy widget still renders");
        // Rejected grants are disabled, not an error.
        let b = ui_update(&env, &json!({"session": "s1", "op": {"kind": "reject", "name": "open"}})).unwrap();
        let open = b["widgets"].as_array().unwrap().iter().find(|w| w["name"] == "open").unwrap()["document"].as_str().unwrap().to_string();
        assert!(open.contains("was rejected") && open.contains("github.actions.runs:acme/open"), "{open}");

        // Anonymous: no credential configured anywhere → no Authorization header, an explicit note.
        clear_github_actions_cache();
        let (anon_env, _) = testkit::env("gh-anon", &[], &format!("[widgets]\ngithub_api = \"{url}\"\n"));
        let before = seen.lock().unwrap().len();
        let dash = DashboardTool(anon_env.clone());
        assert!(!dash.call(&ctx, json!({"action": "widget_put", "name": "open", "pluginKind": "session:github", "props": {"repository": "acme/open"}})).is_error);
        ui_update(&anon_env, &json!({"session": "s1", "op": {"kind": "grant", "name": "open"}})).unwrap();
        let doc = board_json(&anon_env, "s1").unwrap()["widgets"].as_array().unwrap().iter().find(|w| w["name"] == "open").unwrap()["document"].as_str().unwrap().to_string();
        let configured = github_token(&anon_env).is_some();
        let q = seen.lock().unwrap()[before..].to_vec();
        let q = q.iter().find(|r| r.path.starts_with("/repos/acme/open/actions/runs")).expect("anonymous read");
        // No credential configured: no Authorization header and an explicit note. On a machine
        // that exports GITHUB_TOKEN the same widget authenticates instead.
        assert_eq!(q.headers.iter().any(|(k, _)| k == "authorization"), configured, "{:?}", q.headers);
        assert_eq!(doc.contains("Anonymous GitHub read (rate limited)"), !configured, "{doc}");
        assert!(doc.contains("CI"), "{doc}");

        // A broken API base is refused before any request.
        let mut bad = (*anon_env).clone();
        bad.cfg.widgets.github_api = Some("https://evil.example".into());
        assert!(github_actions_json(&bad, &validate_github_actions(&json!({"repository": "acme/open"})).unwrap()).unwrap_err().contains("api.github.com"));
    }

    #[test]
    fn script_errors_report_line_and_column() {
        assert!(script_syntax_error("<div></div><script>const a = [1, 2];\nfunction f() { return a.map(x => x * 2); }</script>").is_none());
        assert!(script_syntax_error("<script src=\"https://cdn.jsdelivr.net/x.js\"></script><script type=\"application/json\">{</script>").is_none());
        let (i, line, col, msg, snip) = script_syntax_error("<p>hi</p>\n<script>\nconst x = {a: 1;\nconsole.log(x)\n</script>").unwrap();
        assert_eq!((i, line), (1, 3));
        assert!(msg.contains("Unexpected end") || msg.contains("Unexpected token"), "{msg} {col}");
        assert!(snip.contains("const x"));
        let (_, line, _, msg, _) = script_syntax_error("<script>let s = 'oops\n</script>").unwrap();
        assert_eq!(line, 1);
        assert!(msg.contains("Unterminated string"));
        assert!(script_syntax_error("<script>const r = /[)]/g; const t = `a ${'}'} b`;</script>").is_none());
    }

    #[test]
    fn inline_widget_is_hosted_and_rendered_by_the_ui() {
        let (env, _) = testkit::env("widget", &[], "");
        let ws = testkit::temp("w-ws");
        let ctx = testkit::ctx(&env, &ws);
        let t = ShowWidget(env.clone());
        let out = t.call(&ctx, json!({"title": "Latency", "widget_code": "<div class=card>p50 <b>12ms</b></div>"}));
        assert!(!out.is_error, "{}", out.content);
        let v: Value = serde_json::from_str(&out.content).unwrap();
        assert_eq!(v["kind"], "canvas");
        let url = v["view"]["url"].as_str().unwrap();
        assert!(url.starts_with("http://127.0.0.1:8640/surfaces/canvas/documents/cv_"), "{url}");
        let ui = out.ui_resource.unwrap();
        assert!(ui["html"].as_str().unwrap().contains("p50 <b>12ms</b>") && ui["html"].as_str().unwrap().contains("connect-src 'none'"));
        // The hosted document is served with the sandbox CSP.
        let rest = url.split("/surfaces/canvas/documents/").nth(1).unwrap();
        let r = canvas::serve_document(&env.dir, rest);
        assert_eq!(r.status, 200);
        assert!(r.headers.iter().any(|(k, v)| k == "content-security-policy" && v.contains("sandbox allow-scripts")));
        // Errors.
        assert!(t.call(&ctx, json!({"title": "x"})).content.contains("widget_code required"));
        assert!(t.call(&ctx, json!({"title": "x", "widget_code": "<p>", "capabilities": {"netOrigins": ["https://api.example.com"]}})).content.contains("capabilities require pin=true"));
        assert!(t.call(&ctx, json!({"title": "x", "widget_code": "<script>if (</script>"})).content.contains("syntax error in inline script 1"));
        assert!(t.call(&ctx, json!({"title": "x", "report": {"blocks": []}})).content.contains("Reports require pin=true"));
    }

    #[test]
    fn pinned_widgets_reports_and_dashboard_layout() {
        let (env, _) = testkit::env("board", &[], "[widgets]\ninline = false\n");
        let ws = testkit::temp("b-ws");
        let ctx = testkit::ctx(&env, &ws);
        let sw = ShowWidget(env.clone());
        let dash = DashboardTool(env.clone());
        assert!(sw.call(&ctx, json!({"title": "x", "widget_code": "<p>1</p>"})).content.contains("inline widget hosting is disabled"));
        let o = sw.call(&ctx, json!({"title": "Build Status!", "widget_code": "<p>green</p>", "pin": true, "capabilities": {"netOrigins": ["https://ci.example.com"]}}));
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!((v["status"].as_str(), v["boardWidgetName"].as_str()), (Some("pending"), Some("build-status")));
        let o = sw.call(&ctx, json!({"title": "Weekly", "pin": true, "size": "lg", "report": {"blocks": [{"type": "metrics", "items": [{"label": "PRs", "value": "12"}]}, {"type": "chart", "points": [{"label": "Mon", "value": 3}]}]}}));
        assert!(o.content.contains("pinned to dashboard tab main as weekly (lg)"), "{}", o.content);
        assert!(sw.call(&ctx, json!({"title": "Bad", "pin": true, "report": {"blocks": [{"type": "table", "columns": ["a"], "rows": [["1", "2"]]}]}})).content.contains("Every table row must match the columns"));
        // Dashboard ops.
        assert!(dash.call(&ctx, json!({"action": "tab_create", "tabId": "ops", "title": "Ops"})).content.contains("2 tabs, 2 widgets"));
        assert!(dash.call(&ctx, json!({"action": "tab_create", "tabId": "ops", "title": "Ops"})).content.contains("already exists"));
        assert!(!dash.call(&ctx, json!({"action": "widget_move", "name": "weekly", "tabId": "ops"})).is_error);
        assert!(dash.call(&ctx, json!({"action": "widget_move", "name": "weekly", "position": 0, "after": "x"})).content.contains("either position or after"));
        let o = dash.call(&ctx, json!({"action": "widget_put", "name": "site", "pluginKind": "session:website", "props": {"url": "https://example.com/"}, "size": "full"}));
        assert!(!o.is_error, "{}", o.content);
        assert!(dash.call(&ctx, json!({"action": "widget_put", "name": "site2", "pluginKind": "session:website", "props": {"url": "http://example.com/"}})).content.contains("valid HTTPS url"));
        assert!(dash.call(&ctx, json!({"action": "widget_put", "name": "x", "pluginKind": "nope"})).content.contains("<pluginId>:<name>"));
        assert!(dash.call(&ctx, json!({"action": "widget_put", "name": "build-status", "pluginKind": "session:progress"})).content.contains("contains html content"));
        let o = dash.call(&ctx, json!({"action": "widget_resize", "name": "site", "sizeW": 40, "sizeH": 2}));
        assert!(o.content.contains("\"sizeW\":12"), "{}", o.content);
        assert!(dash.call(&ctx, json!({"action": "tabs_reorder", "tabIds": ["ops"]})).content.contains("every tab exactly once"));
        assert!(!dash.call(&ctx, json!({"action": "tabs_reorder", "tabIds": ["ops", "main"]})).is_error);
        assert!(!dash.call(&ctx, json!({"action": "tab_delete", "tabId": "ops"})).is_error);
        let r = dash.call(&ctx, json!({"action": "read"}));
        assert!(r.content.contains("1 tabs, 3 widgets") && r.content.contains("\"defaultPresentation\":\"split\""), "{}", r.content);
        // No web UI → unavailable; a polling viewer receives the command.
        assert!(dash.call(&ctx, json!({"action": "focus_tab", "tabId": "main"})).content.starts_with("Dashboard unavailable"));
        poll(&env, "s1");
        assert!(dash.call(&ctx, json!({"action": "focus_tab", "tabId": "main"})).content.contains("sent to 1 client"));
        assert_eq!(poll(&env, "s1")["commands"][0]["kind"], "focus_tab");
        assert!(dash.call(&ctx, json!({"action": "set_default_presentation", "presentation": "expanded"})).content.contains("saved: expanded"));
        // The UI view renders documents; granting the capability opens connect-src.
        let b = board_json(&env, "s1").unwrap();
        let w = b["widgets"].as_array().unwrap().iter().find(|w| w["name"] == "build-status").unwrap().clone();
        assert!(w["document"].as_str().unwrap().contains("connect-src 'none'"));
        let b = ui_update(&env, &json!({"session": "s1", "op": {"kind": "grant", "name": "build-status"}})).unwrap();
        let w = b["widgets"].as_array().unwrap().iter().find(|w| w["name"] == "build-status").unwrap().clone();
        assert_eq!(w["grantState"], "granted");
        assert!(w["document"].as_str().unwrap().contains("connect-src https://ci.example.com"));
        let rep = b["widgets"].as_array().unwrap().iter().find(|w| w["name"] == "weekly").unwrap();
        assert!(rep["document"].as_str().unwrap().contains("<div class=\"metric\">12</div>"));
        // Same bytes and narrower declaration keep the grant; new bytes need approval again.
        let o = sw.call(&ctx, json!({"title": "Build Status!", "name": "build-status", "widget_code": "<p>green</p>", "pin": true, "capabilities": {"netOrigins": ["https://ci.example.com"]}}));
        assert!(o.content.contains("capabilities granted"), "{}", o.content);
        let o = sw.call(&ctx, json!({"title": "Build Status!", "name": "build-status", "widget_code": "<p>red</p>", "pin": true, "capabilities": {"netOrigins": ["https://ci.example.com"]}}));
        assert!(o.content.contains("capabilities pending"), "{}", o.content);
        assert_eq!(list_boards(&env)[0]["widgets"], 3);
    }
}
