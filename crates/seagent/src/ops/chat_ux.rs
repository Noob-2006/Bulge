//! Conversation management for the web console's chat rail (`ui.chat.*`): the "⋯" menu on
//! every conversation (pin, mark unread, rename, fork, nest / fold sub-agent sessions, move to
//! a section, archive, delete with restore, export) and the settings a conversation carries on
//! its own (model, reasoning effort, fast mode, exec route, approval mode, tools, persona).
//!
//! Where each piece lives, so the CLI and the UI never disagree:
//! - pin / archive / section are the session's own `Meta` events (`seagent session pin`,
//!   `archive`, `group` write the same ones); `session.list` reports them.
//! - unread markers, the section list (order, collapsed) and folded parents are console state
//!   in `<data>/ui/chats.json` — they describe the rail, not the conversation.
//! - delete is soft: the session directory moves to `<data>/trash/sessions/<id>` and comes back
//!   with `ui.chat.restore`; `ui.chat.purge` (and 30 days in the trash) removes it for good.
//! - model / reasoning / fast / title / tools / persona are session events (`Model`, `Thinking`,
//!   `Fast`, `Title`, `Tools`, `System`); exec route and approval mode are the per-session
//!   security state (`seagent_security::approvals::SessionState`, what `/exec host=`, `/yolo`
//!   and `/elevated` change).
//!
//! No upstream counterpart: the menu follows the conversation list of the Claude desktop app
//! (pin, unread, rename, fork, sections, archive, delete).

use crate::export::{render_json, render_markdown, safe_filename, SessionData};
use seagent_core::SystemSegment;
use seagent_kernel::daemon::MethodExt;
use seagent_kernel::event::{now_ms, EventKind};
use seagent_kernel::kernel::{Kernel, KernelError, PERSONA_SEGMENT};
use seagent_kernel::projection::{project, View};
use seagent_security::approvals::{self as ap, Elevated};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Method names for the app server's `initialize` list (`daemon_cli`).
pub const METHODS: &[&str] = &[
    "ui.chat.list", "ui.chat.meta.set", "ui.chat.read", "ui.chat.section",
    "ui.chat.fork", "ui.chat.delete", "ui.chat.restore", "ui.chat.purge",
    "ui.chat.settings.get", "ui.chat.settings.set", "ui.chat.export", "ui.chat.models.prefs",
];

/// Most "recently used" models the model picker keeps at its top.
const RECENT_MODELS: usize = 8;
/// Most pinned (favourite) models.
const PINNED_MODELS: usize = 100;

/// Trashed conversations older than this are removed for good the next time the rail loads.
const TRASH_DAYS: u64 = 30;
/// First line of the persona segment; the rest is what the person typed.
const PERSONA_HEADER: &str = "# Persona and instructions for this conversation";

type Res = Result<Value, (i32, String)>;

fn bad(e: impl Into<String>) -> (i32, String) {
    (-32602, e.into())
}
fn fail(e: impl Into<String>) -> (i32, String) {
    (-32000, e.into())
}
fn kerr(e: KernelError) -> (i32, String) {
    match e {
        KernelError::Invalid(m) => bad(m),
        e => fail(e.to_string()),
    }
}

pub struct ChatCtx {
    pub k: Kernel,
}

pub fn methods(k: Kernel) -> MethodExt {
    let c = Arc::new(ChatCtx { k });
    Arc::new(move |m: &str, p: &Value| call(&c, m, p))
}

pub fn call(c: &ChatCtx, m: &str, p: &Value) -> Option<Res> {
    if !m.starts_with("ui.chat.") {
        return None;
    }
    RAIL.with(|r| *r.borrow_mut() = p["_rail"].as_str().map(str::to_string));
    let id = || session_id(c, p);
    Some(match m {
        "ui.chat.list" => list(c),
        "ui.chat.meta.set" => id().and_then(|id| meta_set(c, &id, p)),
        "ui.chat.read" => id().and_then(|id| mark_read(c, &id)),
        "ui.chat.section" => section(c, p),
        "ui.chat.fork" => id().and_then(|id| fork(c, &id)),
        "ui.chat.delete" => id().and_then(|id| delete(c, &id, p)),
        "ui.chat.restore" => restore(c, p["id"].as_str().unwrap_or("")),
        "ui.chat.purge" => purge(c, p["id"].as_str().unwrap_or(""), p),
        "ui.chat.settings.get" => id().and_then(|id| settings_get(c, &id, read_only(p))),
        "ui.chat.settings.set" => id().and_then(|id| settings_set(c, &id, p)),
        "ui.chat.export" => id().and_then(|id| export(c, &id, p)),
        "ui.chat.models.prefs" => model_prefs(c, p),
        _ => return None,
    })
}

fn session_id(c: &ChatCtx, p: &Value) -> Result<String, (i32, String)> {
    let id = p["id"].as_str().unwrap_or("").trim();
    if id.is_empty() {
        return Err(bad("missing param `id`"));
    }
    if !c.k.store.exists(id) {
        return Err(bad(format!("no such conversation `{id}`")));
    }
    Ok(id.to_string())
}

fn read_only(p: &Value) -> bool {
    matches!(p["_scope"].as_str(), Some("scope:read") | Some("auditor"))
}

fn actor(p: &Value) -> seagent_security::audit::Actor {
    match p["_by"].as_str() {
        Some(b) => seagent_security::audit::Actor::parse_label(b).with_role(p["_by_role"].as_str().unwrap_or("")),
        None => seagent_security::audit::Actor::local(),
    }
}

fn view(c: &ChatCtx, id: &str) -> Result<View, (i32, String)> {
    Ok(project(&c.k.store.read(id).map_err(|e| fail(e.to_string()))?))
}

/// A section name / title as one trimmed line of at most `max` characters.
fn one_line(s: &str, max: usize) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(max).collect()
}

/// Session ids are `[A-Za-z0-9_-]{1,64}` (the store refuses anything else); trash paths are
/// built from them, so the same rule guards restore / purge.
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ───────────────────────── rail state (`<data>/ui/chats.json`) ─────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Section {
    name: String,
    collapsed: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct RailState {
    /// User-made sections in display order (a session's `Meta.group` names its section).
    sections: Vec<Section>,
    /// When the person last looked at each conversation (unix ms).
    read_ms: BTreeMap<String, u64>,
    /// Conversations explicitly marked unread.
    unread: BTreeSet<String>,
    /// Parents whose nested (sub-agent / child) sessions are hidden.
    folded: BTreeSet<String>,
    /// The model picker's pinned (favourite) `provider/model` refs, in pin order.
    pinned_models: Vec<String>,
    /// The models last chosen in the picker, newest first (at most [`RECENT_MODELS`]).
    recent_models: Vec<String>,
}

static STATE_LOCK: Mutex<()> = Mutex::new(());

/// The rail state of one scope. The app server sets `_rail` from the authenticated principal
/// (a tenant-bound or non-admin caller gets its own sections / unread markers); the owner of
/// the installation (no `_rail`) uses `chats.json`.
fn state_path(c: &ChatCtx) -> PathBuf {
    let ui = c.k.paths.data.join("ui");
    RAIL.with(|r| match r.borrow().as_deref() {
        Some(k) if !k.is_empty() => ui.join("chats").join(format!("{}.json", rail_file(k))),
        _ => ui.join("chats.json"),
    })
}

/// A scope key as a file name: hex of its bytes (no path characters can survive).
fn rail_file(k: &str) -> String {
    k.bytes().take(96).map(|b| format!("{b:02x}")).collect()
}

thread_local! {
    /// The `_rail` scope of the call being served (one ARP call runs on one thread).
    static RAIL: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

fn load_state(path: &Path) -> RailState {
    std::fs::read_to_string(path).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default()
}

/// Read-modify-write the rail state (temp file + rename, so a crash never leaves half a file).
fn update_state<T>(c: &ChatCtx, f: impl FnOnce(&mut RailState) -> Result<T, String>) -> Result<T, (i32, String)> {
    let _g = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = state_path(c);
    let mut st = load_state(&path);
    let out = f(&mut st).map_err(bad)?;
    let dir = path.parent().expect("chats.json has a parent");
    std::fs::create_dir_all(dir).map_err(|e| fail(format!("{}: {e}", dir.display())))?;
    let tmp = path.with_extension(format!("json.tmp{}", std::process::id()));
    std::fs::write(&tmp, serde_json::to_vec_pretty(&st).unwrap_or_default()).map_err(|e| fail(format!("{}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, &path).map_err(|e| fail(format!("{}: {e}", path.display())))?;
    Ok(out)
}

fn list(c: &ChatCtx) -> Res {
    purge_expired(c);
    let st = load_state(&state_path(c));
    Ok(json!({
        "sections": st.sections,
        "read_ms": st.read_ms,
        "unread": st.unread,
        "folded": st.folded,
        "pinned_models": st.pinned_models,
        "recent_models": st.recent_models,
        "trash": trash_list(c),
    }))
}

/// A `provider/model` ref as the picker sends it: one token, at most 200 characters.
fn model_ref(v: &Value) -> Option<String> {
    let r = v.as_str()?.trim();
    (!r.is_empty() && r.len() <= 200 && r.contains('/') && !r.chars().any(|c| c.is_whitespace() || c.is_control())).then(|| r.to_string())
}

/// `ui.chat.models.prefs {pin?, pinned?, used?}`: the model picker's favourites and recently
/// used list (console state of this rail scope, next to the sections). `pin` + `pinned: bool`
/// adds / removes a favourite; `used` moves a ref to the top of the recent list. Answers both.
fn model_prefs(c: &ChatCtx, p: &Value) -> Res {
    let pin = p.get("pin").map(|v| model_ref(v).ok_or_else(|| bad("`pin` must be a provider/model ref"))).transpose()?;
    let used = p.get("used").map(|v| model_ref(v).ok_or_else(|| bad("`used` must be a provider/model ref"))).transpose()?;
    let st = if pin.is_none() && used.is_none() {
        load_state(&state_path(c))
    } else {
        let on = p.get("pinned").and_then(Value::as_bool).unwrap_or(true);
        update_state(c, |st| {
            if let Some(r) = pin {
                st.pinned_models.retain(|x| *x != r);
                if on {
                    st.pinned_models.push(r);
                    st.pinned_models.truncate(PINNED_MODELS);
                }
            }
            if let Some(r) = used {
                st.recent_models.retain(|x| *x != r);
                st.recent_models.insert(0, r);
                st.recent_models.truncate(RECENT_MODELS);
            }
            Ok(st.clone())
        })?
    };
    Ok(json!({"pinned": st.pinned_models, "recent": st.recent_models}))
}

fn meta_set(c: &ChatCtx, id: &str, p: &Value) -> Res {
    let pinned = p.get("pinned").and_then(Value::as_bool);
    let archived = p.get("archived").and_then(Value::as_bool);
    let group = p.get("group").and_then(Value::as_str).map(|g| one_line(g, 60));
    let unread = p.get("unread").and_then(Value::as_bool);
    let folded = p.get("folded").and_then(Value::as_bool);
    if pinned.is_none() && archived.is_none() && group.is_none() && unread.is_none() && folded.is_none() {
        return Err(bad("give pinned, archived, group, unread or folded"));
    }
    if pinned.is_some() || archived.is_some() || group.is_some() {
        c.k.record(id, EventKind::Meta { pinned, archived, group: group.clone(), status: None }).map_err(kerr)?;
    }
    let new_section = group.filter(|g| !g.is_empty());
    if unread.is_some() || folded.is_some() || new_section.is_some() {
        update_state(c, |st| {
            match unread {
                Some(true) => {
                    st.unread.insert(id.to_string());
                }
                Some(false) => {
                    st.unread.remove(id);
                    st.read_ms.insert(id.to_string(), now_ms());
                }
                None => {}
            }
            match folded {
                Some(true) => {
                    st.folded.insert(id.to_string());
                }
                Some(false) => {
                    st.folded.remove(id);
                }
                None => {}
            }
            // Moving a conversation into a section that does not exist yet creates it.
            if let Some(g) = new_section {
                if !st.sections.iter().any(|s| s.name == g) {
                    st.sections.push(Section { name: g, collapsed: false });
                }
            }
            Ok(())
        })?;
    }
    Ok(json!({"ok": true}))
}

fn mark_read(c: &ChatCtx, id: &str) -> Res {
    let at = now_ms();
    update_state(c, |st| {
        st.unread.remove(id);
        st.read_ms.insert(id.to_string(), at);
        Ok(())
    })?;
    Ok(json!({"read_ms": at}))
}

/// Sessions whose `Meta.group` is `name`.
fn members(c: &ChatCtx, name: &str) -> Vec<String> {
    c.k.store.list().into_iter().filter(|s| s.group.as_deref() == Some(name)).map(|s| s.id).collect()
}

/// `op`: add | rename (`to`) | delete | collapse (`collapsed`) | move (`index`).
fn section(c: &ChatCtx, p: &Value) -> Res {
    let name = one_line(p["name"].as_str().unwrap_or(""), 60);
    if name.is_empty() {
        return Err(bad("missing section `name`"));
    }
    match p["op"].as_str().unwrap_or("") {
        "add" => update_state(c, |st| {
            if st.sections.iter().any(|s| s.name == name) {
                return Err(format!("section `{name}` already exists"));
            }
            st.sections.push(Section { name: name.clone(), collapsed: false });
            Ok(())
        })?,
        "collapse" => {
            let collapsed = p["collapsed"].as_bool().unwrap_or(true);
            update_state(c, |st| {
                match st.sections.iter_mut().find(|s| s.name == name) {
                    Some(s) => s.collapsed = collapsed,
                    None => st.sections.push(Section { name: name.clone(), collapsed }),
                }
                Ok(())
            })?
        }
        "move" => {
            let to = p["index"].as_u64().ok_or_else(|| bad("missing `index`"))? as usize;
            update_state(c, |st| {
                let at = st.sections.iter().position(|s| s.name == name).ok_or_else(|| format!("no section `{name}`"))?;
                let s = st.sections.remove(at);
                st.sections.insert(to.min(st.sections.len()), s);
                Ok(())
            })?
        }
        "rename" => {
            let to = one_line(p["to"].as_str().unwrap_or(""), 60);
            if to.is_empty() {
                return Err(bad("missing new name `to`"));
            }
            if to != name && load_state(&state_path(c)).sections.iter().any(|s| s.name == to) {
                return Err(bad(format!("section `{to}` already exists")));
            }
            for id in members(c, &name) {
                c.k.record(&id, EventKind::Meta { pinned: None, archived: None, group: Some(to.clone()), status: None }).map_err(kerr)?;
            }
            update_state(c, |st| {
                match st.sections.iter_mut().find(|s| s.name == name) {
                    Some(s) => s.name = to.clone(),
                    None => st.sections.push(Section { name: to.clone(), collapsed: false }),
                }
                Ok(())
            })?
        }
        "delete" => {
            // The conversations stay; they only leave the section.
            for id in members(c, &name) {
                c.k.record(&id, EventKind::Meta { pinned: None, archived: None, group: Some(String::new()), status: None }).map_err(kerr)?;
            }
            update_state(c, |st| {
                st.sections.retain(|s| s.name != name);
                Ok(())
            })?
        }
        other => return Err(bad(format!("unknown section op `{other}` (add, rename, delete, collapse, move)"))),
    }
    Ok(json!({"sections": load_state(&state_path(c)).sections}))
}

// ───────────────────────── fork ─────────────────────────

/// Fork = the kernel's `/branch` (history up to now, minus a half-finished exchange) plus the
/// settings this conversation carries, so the copy behaves like the original.
fn fork(c: &ChatCtx, id: &str) -> Res {
    let v = view(c, id)?;
    let new = c.k.branch(id, None).map_err(fail)?;
    if let Some(t) = &v.thinking {
        c.k.set_thinking(&new, t).map_err(kerr)?;
    }
    if let Some(f) = &v.fast {
        c.k.set_fast(&new, f).map_err(kerr)?;
    }
    if v.tool_allow.is_some() || !v.tool_deny.is_empty() {
        c.k.record(&new, EventKind::Tools { allow: v.tool_allow.clone(), deny: v.tool_deny.clone() }).map_err(kerr)?;
    }
    if let Some(seg) = v.system.iter().find(|s| s.id == PERSONA_SEGMENT) {
        let mut segs = view(c, &new)?.system;
        segs.retain(|s| s.id != PERSONA_SEGMENT);
        segs.push(seg.clone());
        c.k.record(&new, EventKind::System { segments: segs }).map_err(kerr)?;
    }
    if !v.skills_disabled.is_empty() {
        c.k.set_skills_disabled(&new, v.skills_disabled.clone()).map_err(kerr)?;
    }
    // The fork belongs to the same organization / team as the original (ent-050 stamps).
    let tenant = seagent_kernel::tenancy::session_tenant(&c.k.paths.data, id);
    if tenant != seagent_kernel::tenancy::Tenant::default() {
        seagent_kernel::tenancy::stamp(&c.k.paths.data, &new, &tenant);
    }
    let base = v.title.clone().filter(|t| !t.trim().is_empty()).unwrap_or_else(|| id.chars().take(8).collect());
    c.k.set_title(&new, &format!("{base} (fork)")).map_err(kerr)?;
    ap::transfer_session(&c.k.paths.data, id, &new).map_err(fail)?;
    Ok(json!({"id": new, "from": id}))
}

// ───────────────────────── delete / restore / purge ─────────────────────────

fn trash_root(c: &ChatCtx) -> PathBuf {
    c.k.paths.data.join("trash").join("sessions")
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Trashed {
    deleted_ms: u64,
    title: Option<String>,
    parent: Option<String>,
}

fn trash_list(c: &ChatCtx) -> Vec<Value> {
    let Ok(rd) = std::fs::read_dir(trash_root(c)) else { return vec![] };
    let mut out: Vec<(u64, Value)> = rd
        .flatten()
        .filter_map(|e| {
            let id = e.file_name().to_string_lossy().to_string();
            let t: Trashed = std::fs::read_to_string(e.path().join("trash.json")).ok().and_then(|s| serde_json::from_str(&s).ok())?;
            valid_id(&id).then(|| (t.deleted_ms, json!({"id": id, "title": t.title, "deleted_ms": t.deleted_ms, "parent": t.parent})))
        })
        .collect();
    out.sort_by_key(|(ms, _)| std::cmp::Reverse(*ms));
    out.into_iter().map(|(_, v)| v).collect()
}

fn purge_expired(c: &ChatCtx) {
    let cutoff = now_ms().saturating_sub(TRASH_DAYS * 86_400_000);
    for t in trash_list(c) {
        if t["deleted_ms"].as_u64().is_some_and(|ms| ms < cutoff) {
            let _ = std::fs::remove_dir_all(trash_root(c).join(t["id"].as_str().unwrap_or("-")));
        }
    }
}

fn delete(c: &ChatCtx, id: &str, p: &Value) -> Res {
    if c.k.is_running(id) {
        return Err(bad("this conversation is running: stop it before deleting it"));
    }
    let v = view(c, id)?;
    // Taking the write lock proves no other process (a worker, the CLI) is appending to it.
    drop(c.k.store.open(id).map_err(|e| fail(e.to_string()))?);
    let root = trash_root(c);
    std::fs::create_dir_all(&root).map_err(|e| fail(format!("{}: {e}", root.display())))?;
    let dest = root.join(id);
    if dest.exists() {
        std::fs::remove_dir_all(&dest).map_err(|e| fail(format!("{}: {e}", dest.display())))?;
    }
    std::fs::rename(c.k.store.dir(id), &dest).map_err(|e| fail(format!("move to trash: {e}")))?;
    let t = Trashed { deleted_ms: now_ms(), title: v.title.clone(), parent: v.parent.clone() };
    std::fs::write(dest.join("trash.json"), serde_json::to_vec(&t).unwrap_or_default()).map_err(|e| fail(e.to_string()))?;
    seagent_security::audit::record(&c.k.paths.data, seagent_security::audit::Event::new("session.delete", actor(p), id, "ok").session(id).detail(json!({"soft": true})));
    Ok(json!({"deleted": id, "restorable": true, "days": TRASH_DAYS}))
}

fn restore(c: &ChatCtx, id: &str) -> Res {
    if !valid_id(id) {
        return Err(bad("missing or invalid `id`"));
    }
    let from = trash_root(c).join(id);
    if !from.join("events.jsonl").is_file() {
        return Err(bad(format!("`{id}` is not in the trash")));
    }
    let to = c.k.store.dir(id);
    if to.exists() {
        return Err(bad(format!("a conversation `{id}` already exists")));
    }
    let _ = std::fs::remove_file(from.join("trash.json"));
    std::fs::rename(&from, &to).map_err(|e| fail(format!("restore: {e}")))?;
    Ok(json!({"restored": id}))
}

fn purge(c: &ChatCtx, id: &str, p: &Value) -> Res {
    if !valid_id(id) {
        return Err(bad("missing or invalid `id`"));
    }
    let dir = trash_root(c).join(id);
    if !dir.is_dir() {
        return Err(bad(format!("`{id}` is not in the trash (only deleted conversations can be purged)")));
    }
    std::fs::remove_dir_all(&dir).map_err(|e| fail(e.to_string()))?;
    let _ = update_state(c, |st| {
        st.read_ms.remove(id);
        st.unread.remove(id);
        st.folded.remove(id);
        Ok(())
    });
    ap::clear_session(&c.k.paths.data, id);
    seagent_security::audit::record(&c.k.paths.data, seagent_security::audit::Event::new("session.purge", actor(p), id, "ok").session(id));
    Ok(json!({"purged": id}))
}

// ───────────────────────── settings ─────────────────────────

fn persona_of(v: &View) -> String {
    v.system
        .iter()
        .find(|s| s.id == PERSONA_SEGMENT)
        .map(|s| s.text.strip_prefix(PERSONA_HEADER).unwrap_or(&s.text).trim().to_string())
        .unwrap_or_default()
}

fn tool_enabled(v: &View, name: &str) -> bool {
    !v.tool_deny.iter().any(|d| d == name) && v.tool_allow.as_ref().is_none_or(|a| a.iter().any(|x| x == name || x == "*"))
}

/// Reasoning levels the session's provider takes (its preset / config list), else the
/// kernel's common set.
fn efforts_for(c: &ChatCtx, model: &str) -> Vec<String> {
    let pid = model.split_once('/').map(|(p, _)| p).unwrap_or("");
    let from_provider = crate::providers::Providers::new(&c.k.cfg.providers, c.k.vault.clone()).ok().and_then(|ps| ps.config(pid).and_then(|pc| pc.reasoning_efforts.clone()));
    from_provider.filter(|e| !e.is_empty()).unwrap_or_else(|| ["off", "low", "medium", "high"].iter().map(|s| s.to_string()).collect())
}

fn approval_mode(c: &ChatCtx, st: &ap::SessionState) -> &'static str {
    if st.yolo {
        "yolo"
    } else if c.k.cfg.approvals.elevated.enabled && matches!(st.elevated, Some(Elevated::On) | Some(Elevated::Full)) {
        "elevated"
    } else {
        "ask"
    }
}

fn settings_get(c: &ChatCtx, id: &str, read_only: bool) -> Res {
    let v = view(c, id)?;
    let st = ap::session_state(&c.k.paths.data, id);
    let tools: Vec<Value> = c
        .k
        .specs()
        .into_iter()
        .map(|s| {
            let desc: String = s.description.lines().next().unwrap_or("").chars().take(140).collect();
            json!({"name": s.name, "description": desc, "enabled": tool_enabled(&v, &s.name)})
        })
        .collect();
    let mut out = json!({
        "id": id,
        "title": v.title,
        "model": v.model,
        "thinking": v.thinking.clone().unwrap_or_default(),
        "efforts": efforts_for(c, &v.model),
        "fast": v.fast.clone().unwrap_or_default(),
        "exec_host": st.exec.host.clone().unwrap_or_else(|| "auto".into()),
        "approval": approval_mode(c, &st),
        "elevated_enabled": c.k.cfg.approvals.elevated.enabled,
        "approvals_mode": format!("{:?}", c.k.cfg.approvals.mode).to_lowercase(),
        "process_yolo": ap::process_yolo(),
        "tools": tools,
        "tool_allow": v.tool_allow,
        "persona": persona_of(&v),
        "skills": c.k.skill_catalog(Path::new(&v.workspace)).into_iter().map(|(name, description)| {
            let enabled = !v.skills_disabled.contains(&name);
            json!({"name": name, "description": description.chars().take(160).collect::<String>(), "enabled": enabled})
        }).collect::<Vec<_>>(),
        "skills_disabled": v.skills_disabled,
        "parent": v.parent,
        "running": c.k.is_running(id),
    });
    if !read_only {
        out["workspace"] = json!(v.workspace);
    }
    Ok(out)
}

/// Change any subset of the settings. Everything is checked before anything is written, so a
/// bad value in one field never leaves the others half-applied.
fn settings_set(c: &ChatCtx, id: &str, p: &Value) -> Res {
    let s = |k: &str| p.get(k).and_then(Value::as_str).map(str::trim);
    let v = view(c, id)?;
    // ── validate ──
    let title = s("title").map(|t| one_line(t, 80));
    if title.as_deref() == Some("") {
        return Err(bad("the title cannot be empty"));
    }
    let model = s("model").filter(|m| !m.is_empty()).map(|m| c.k.cfg.resolve_model(m).to_string());
    if let Some(m) = &model {
        let pid = m.split_once('/').map(|(p, _)| p).ok_or_else(|| bad(format!("`{m}` is not provider/model")))?;
        let ps = crate::providers::Providers::new(&c.k.cfg.providers, c.k.vault.clone()).map_err(fail)?;
        if ps.canonical(pid).is_none() {
            return Err(bad(format!("unknown provider `{pid}`")));
        }
    }
    let host = match s("exec_host") {
        None => None,
        Some("auto") | Some("") => Some(None),
        Some(h @ ("sandbox" | "host" | "node")) => Some(Some(h.to_string())),
        Some(h) => return Err(bad(format!("exec_host `{h}`: use auto, sandbox, host or node"))),
    };
    let approval = s("approval");
    match approval {
        None | Some("ask") | Some("yolo") => {}
        Some("elevated") if c.k.cfg.approvals.elevated.enabled => {}
        Some("elevated") => return Err(bad("elevated mode is not enabled (approvals.elevated.enabled)")),
        Some(a) => return Err(bad(format!("approval `{a}`: use ask, yolo or elevated"))),
    }
    let deny = match p.get("tools_disabled") {
        None => None,
        Some(Value::Array(a)) => {
            let mut d: Vec<String> = a.iter().filter_map(Value::as_str).map(str::to_string).collect();
            d.sort();
            d.dedup();
            Some(d)
        }
        Some(_) => return Err(bad("tools_disabled must be an array of tool names")),
    };
    let skills_off = match p.get("skills_disabled") {
        None => None,
        Some(Value::Array(a)) => Some(a.iter().filter_map(Value::as_str).map(str::to_string).collect::<Vec<_>>()),
        Some(_) => return Err(bad("skills_disabled must be an array of skill names")),
    };
    let persona = p.get("persona").and_then(Value::as_str).map(str::trim);
    if persona.is_some_and(|t| t.chars().count() > 20_000) {
        return Err(bad("the persona is limited to 20,000 characters"));
    }
    // ── apply ──
    if let Some(t) = title {
        c.k.set_title(id, &t).map_err(kerr)?;
    }
    if let Some(m) = &model {
        c.k.set_model(id, m).map_err(kerr)?;
    }
    if let Some(t) = s("thinking") {
        c.k.set_thinking(id, if t == "default" { "" } else { t }).map_err(kerr)?;
    }
    if let Some(f) = s("fast") {
        c.k.set_fast(id, f).map_err(kerr)?;
    }
    if host.is_some() || approval.is_some() {
        ap::update_session(&c.k.paths.data, id, |st| {
            if let Some(h) = host {
                st.exec.host = h;
            }
            match approval {
                Some("ask") => {
                    st.yolo = false;
                    st.elevated = None;
                }
                Some("yolo") => {
                    st.yolo = true;
                    st.elevated = None;
                }
                Some("elevated") => {
                    st.yolo = false;
                    st.elevated = Some(Elevated::On);
                }
                _ => {}
            }
        })
        .map_err(fail)?;
    }
    if let Some(d) = deny.filter(|d| *d != v.tool_deny) {
        c.k.record(id, EventKind::Tools { allow: v.tool_allow.clone(), deny: d }).map_err(kerr)?;
    }
    if let Some(off) = skills_off {
        c.k.set_skills_disabled(id, off).map_err(kerr)?;
    }
    let v = if persona.is_some() { view(c, id)? } else { v };
    if let Some(text) = persona.filter(|t| *t != persona_of(&v)) {
        // Written as the system head (not a delta) so the persona is read back from the session
        // itself; it sits after the config's segments, so their cached prefix is unchanged.
        let mut segs: Vec<SystemSegment> = v.system.iter().filter(|s| s.id != PERSONA_SEGMENT).cloned().collect();
        if !text.is_empty() {
            segs.push(SystemSegment { id: PERSONA_SEGMENT.into(), text: format!("{PERSONA_HEADER}\n{text}"), cache: false });
        }
        c.k.record(id, EventKind::System { segments: segs }).map_err(kerr)?;
    }
    settings_get(c, id, read_only(p))
}

// ───────────────────────── export ─────────────────────────

/// The same renderers as `seagent session export`, with the same redaction (vault values) and
/// PII masking policy; the browser saves the text as a file.
fn export(c: &ChatCtx, id: &str, p: &Value) -> Res {
    let fmt = p["format"].as_str().unwrap_or("md");
    let mut s = SessionData::from_events(&c.k.store.read(id).map_err(|e| fail(e.to_string()))?);
    s.redact(&c.k.vault);
    let mask = c.k.cfg.compliance.pii.exports;
    if mask {
        s.mask_pii(&c.k.cfg.compliance.pii);
    }
    let (text, ext, mime) = match fmt {
        "md" => (render_markdown(&s, "md", false, now_ms()), "md", "text/markdown"),
        "json" => (serde_json::to_string_pretty(&render_json(&s)).unwrap_or_default(), "json", "application/json"),
        other => return Err(bad(format!("format `{other}`: use md or json"))),
    };
    seagent_security::audit::record(&c.k.paths.data, seagent_security::audit::Event::new("session.export", actor(p), id, "ok").session(id).detail(json!({"format": fmt, "pii_masked": mask, "secrets_redacted": true, "via": "web"})));
    Ok(json!({"name": safe_filename(&s, ext), "mime": mime, "text": text}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{kit, Kit};

    fn ctx(t: &Kit) -> ChatCtx {
        ChatCtx { k: t.k.clone() }
    }
    fn ok(c: &ChatCtx, m: &str, p: Value) -> Value {
        call(c, m, &p).unwrap_or_else(|| panic!("{m} not handled")).unwrap_or_else(|e| panic!("{m}: {e:?}"))
    }
    fn err(c: &ChatCtx, m: &str, p: Value) -> (i32, String) {
        call(c, m, &p).unwrap_or_else(|| panic!("{m} not handled")).unwrap_err()
    }
    fn info(t: &Kit, id: &str) -> seagent_kernel::store::SessionInfo {
        t.k.store.list().into_iter().find(|s| s.id == id).expect("listed")
    }

    #[test]
    fn model_picker_pins_and_recents_persist_per_rail() {
        let t = kit();
        let c = ctx(&t);
        ok(&c, "ui.chat.models.prefs", json!({"pin": "openrouter/anthropic/claude-x"}));
        ok(&c, "ui.chat.models.prefs", json!({"pin": "deepseek/deepseek-chat"}));
        for r in ["a/1", "b/2", "a/1", "c/3", "d/4", "e/5", "f/6", "g/7", "h/8", "i/9"] {
            ok(&c, "ui.chat.models.prefs", json!({"used": r}));
        }
        let v = ok(&c, "ui.chat.models.prefs", json!({"pin": "openrouter/anthropic/claude-x", "pinned": false}));
        assert_eq!(v["pinned"], json!(["deepseek/deepseek-chat"]));
        assert_eq!(v["recent"], json!(["i/9", "h/8", "g/7", "f/6", "e/5", "d/4", "c/3", "a/1"]), "newest first, deduplicated, capped");
        // Persisted with the rail state (survives a reload) and listed with it.
        let l = ok(&c, "ui.chat.list", json!({}));
        assert_eq!(l["pinned_models"], json!(["deepseek/deepseek-chat"]));
        assert_eq!(l["recent_models"][0], "i/9");
        let on_disk = std::fs::read_to_string(t.paths.data.join("ui/chats.json")).unwrap();
        assert!(on_disk.contains("deepseek/deepseek-chat"), "{on_disk}");
        // Another rail scope (a non-admin principal) has its own.
        let other = ok(&c, "ui.chat.models.prefs", json!({"_rail": "token:someone"}));
        assert_eq!(other["pinned"], json!([]));
        for bad in [json!({"pin": "no-slash"}), json!({"used": "two words/x"}), json!({"pin": 7})] {
            assert_eq!(err(&c, "ui.chat.models.prefs", bad).0, -32602);
        }
    }

    #[test]
    fn pin_archive_section_and_unread_round_trip() {
        let t = kit();
        let c = ctx(&t);
        let id = t.k.create_session(&t.ws, None, None, Some("first")).unwrap();
        ok(&c, "ui.chat.meta.set", json!({"id": id, "pinned": true}));
        assert!(info(&t, &id).pinned, "pin is the session's own Meta event");
        ok(&c, "ui.chat.meta.set", json!({"id": id, "group": "Work"}));
        assert_eq!(info(&t, &id).group.as_deref(), Some("Work"));
        let l = ok(&c, "ui.chat.list", json!({}));
        assert_eq!(l["sections"][0]["name"], "Work", "moving into a new section creates it");
        ok(&c, "ui.chat.meta.set", json!({"id": id, "unread": true, "folded": true}));
        let l = ok(&c, "ui.chat.list", json!({}));
        assert_eq!(l["unread"], json!([id]));
        assert_eq!(l["folded"], json!([id]));
        ok(&c, "ui.chat.read", json!({"id": id}));
        let l = ok(&c, "ui.chat.list", json!({}));
        assert_eq!(l["unread"], json!([]));
        assert!(l["read_ms"][&id].as_u64().unwrap() > 0);
        ok(&c, "ui.chat.meta.set", json!({"id": id, "archived": true, "pinned": false}));
        let i = info(&t, &id);
        assert!(i.archived && !i.pinned);
        assert!(err(&c, "ui.chat.meta.set", json!({"id": id})).1.contains("give"));
        assert!(err(&c, "ui.chat.meta.set", json!({"id": "nope", "pinned": true})).1.contains("no such"));
    }

    #[test]
    fn sections_rename_and_delete_move_their_conversations() {
        let t = kit();
        let c = ctx(&t);
        let a = t.k.create_session(&t.ws, None, None, Some("a")).unwrap();
        let b = t.k.create_session(&t.ws, None, None, Some("b")).unwrap();
        ok(&c, "ui.chat.section", json!({"op": "add", "name": "Later"}));
        assert!(err(&c, "ui.chat.section", json!({"op": "add", "name": "Later"})).1.contains("exists"));
        ok(&c, "ui.chat.meta.set", json!({"id": a, "group": "Ops"}));
        ok(&c, "ui.chat.meta.set", json!({"id": b, "group": "Ops"}));
        let r = ok(&c, "ui.chat.section", json!({"op": "rename", "name": "Ops", "to": "Operations"}));
        assert_eq!(r["sections"].as_array().unwrap().iter().map(|s| s["name"].as_str().unwrap()).collect::<Vec<_>>(), ["Later", "Operations"]);
        assert_eq!(info(&t, &a).group.as_deref(), Some("Operations"));
        assert_eq!(info(&t, &b).group.as_deref(), Some("Operations"));
        let r = ok(&c, "ui.chat.section", json!({"op": "move", "name": "Operations", "index": 0}));
        assert_eq!(r["sections"][0]["name"], "Operations");
        let r = ok(&c, "ui.chat.section", json!({"op": "collapse", "name": "Operations", "collapsed": true}));
        assert_eq!(r["sections"][0]["collapsed"], true);
        ok(&c, "ui.chat.section", json!({"op": "delete", "name": "Operations"}));
        assert_eq!(info(&t, &a).group, None, "deleting a section keeps its conversations");
        assert!(t.k.store.exists(&a));
        assert!(err(&c, "ui.chat.section", json!({"op": "explode", "name": "x"})).1.contains("unknown"));
    }

    #[test]
    fn fork_copies_history_and_settings() {
        let t = kit();
        let c = ctx(&t);
        let id = t.k.create_session(&t.ws, None, None, Some("plan")).unwrap();
        t.k.submit(&id, "hello there", "web").unwrap();
        t.k.run(&id, Default::default()).unwrap();
        ok(&c, "ui.chat.settings.set", json!({"id": id, "thinking": "high", "persona": "You are terse.", "tools_disabled": ["shell"], "approval": "yolo"}));
        let f = ok(&c, "ui.chat.fork", json!({"id": id}))["id"].as_str().unwrap().to_string();
        assert_ne!(f, id);
        let (a, b) = (view(&c, &id).unwrap(), view(&c, &f).unwrap());
        assert_eq!(a.messages, b.messages, "the fork has the history up to now");
        let s = ok(&c, "ui.chat.settings.get", json!({"id": f}));
        assert_eq!((s["thinking"].as_str(), s["persona"].as_str(), s["approval"].as_str()), (Some("high"), Some("You are terse."), Some("yolo")));
        assert!(s["tools"].as_array().unwrap().iter().any(|x| x["name"] == "shell" && x["enabled"] == false));
        assert_eq!(s["title"], "plan (fork)");
    }

    #[test]
    fn delete_is_soft_restorable_and_purgeable() {
        let t = kit();
        let c = ctx(&t);
        let id = t.k.create_session(&t.ws, None, None, Some("doomed")).unwrap();
        ok(&c, "ui.chat.delete", json!({"id": id}));
        assert!(!t.k.store.exists(&id), "gone from the store");
        let l = ok(&c, "ui.chat.list", json!({}));
        assert_eq!((l["trash"][0]["id"].as_str(), l["trash"][0]["title"].as_str()), (Some(id.as_str()), Some("doomed")));
        ok(&c, "ui.chat.restore", json!({"id": id}));
        assert!(t.k.store.exists(&id));
        assert_eq!(info(&t, &id).title.as_deref(), Some("doomed"));
        assert!(ok(&c, "ui.chat.list", json!({}))["trash"].as_array().unwrap().is_empty());
        ok(&c, "ui.chat.delete", json!({"id": id}));
        ok(&c, "ui.chat.purge", json!({"id": id}));
        assert!(!trash_root(&c).join(&id).exists(), "purged for good");
        assert!(err(&c, "ui.chat.restore", json!({"id": id})).1.contains("not in the trash"));
        assert!(err(&c, "ui.chat.purge", json!({"id": "../etc"})).1.contains("invalid"));
        // A live conversation cannot be purged without going through the trash.
        let live = t.k.create_session(&t.ws, None, None, None).unwrap();
        assert!(err(&c, "ui.chat.purge", json!({"id": live})).1.contains("not in the trash"));
        assert!(t.k.store.exists(&live));
    }

    #[test]
    fn expired_trash_is_purged_on_list() {
        let t = kit();
        let c = ctx(&t);
        let id = t.k.create_session(&t.ws, None, None, None).unwrap();
        ok(&c, "ui.chat.delete", json!({"id": id}));
        let meta = trash_root(&c).join(&id).join("trash.json");
        std::fs::write(&meta, serde_json::to_vec(&Trashed { deleted_ms: 1, title: None, parent: None }).unwrap()).unwrap();
        assert!(ok(&c, "ui.chat.list", json!({}))["trash"].as_array().unwrap().is_empty());
        assert!(!trash_root(&c).join(&id).exists());
    }

    #[test]
    fn settings_validate_before_writing_anything() {
        let t = kit();
        let c = ctx(&t);
        let id = t.k.create_session(&t.ws, None, None, Some("s")).unwrap();
        let before = t.k.store.read(&id).unwrap().len();
        for (p, want) in [
            (json!({"id": id, "title": "x", "exec_host": "moon"}), "exec_host"),
            (json!({"id": id, "title": "x", "approval": "elevated"}), "not enabled"),
            (json!({"id": id, "title": "x", "model": "nosuch/m"}), "unknown provider"),
            (json!({"id": id, "title": "x", "tools_disabled": "shell"}), "array"),
            (json!({"id": id, "title": "   "}), "empty"),
        ] {
            let (code, msg) = err(&c, "ui.chat.settings.set", p);
            assert!(code == -32602 && msg.contains(want), "{msg}");
        }
        assert_eq!(t.k.store.read(&id).unwrap().len(), before, "nothing was written");
        let s = ok(&c, "ui.chat.settings.set", json!({"id": id, "title": "Renamed", "model": "openai/gpt-test", "thinking": "low", "exec_host": "sandbox", "approval": "yolo"}));
        assert_eq!((s["title"].as_str(), s["model"].as_str(), s["thinking"].as_str(), s["exec_host"].as_str(), s["approval"].as_str()), (Some("Renamed"), Some("openai/gpt-test"), Some("low"), Some("sandbox"), Some("yolo")));
        assert_eq!(ap::session_state(&t.paths.data, &id).exec.host.as_deref(), Some("sandbox"), "the same state `/exec host=` writes");
        assert_eq!(info(&t, &id).current_model, "openai/gpt-test", "session.list shows the switched model");
        let s = ok(&c, "ui.chat.settings.set", json!({"id": id, "exec_host": "auto", "approval": "ask", "thinking": "default"}));
        assert_eq!((s["exec_host"].as_str(), s["approval"].as_str(), s["thinking"].as_str()), (Some("auto"), Some("ask"), Some("")));
        assert!(s["workspace"].is_string());
        assert!(ok(&c, "ui.chat.settings.get", json!({"id": id, "_scope": "scope:read"})).get("workspace").is_none(), "read-only callers do not see the host's paths");
    }

    #[test]
    fn persona_and_tools_reach_the_request() {
        let t = kit();
        let c = ctx(&t);
        let id = t.k.create_session(&t.ws, None, None, None).unwrap();
        ok(&c, "ui.chat.settings.set", json!({"id": id, "persona": "Answer like a pirate.", "tools_disabled": ["shell"]}));
        t.k.submit(&id, "hi", "web").unwrap();
        t.k.run(&id, Default::default()).unwrap();
        let seen = t.echo.seen.lock().unwrap().clone();
        let req = seen.last().expect("one request");
        assert!(req.system.iter().any(|s| s.id == PERSONA_SEGMENT && s.text.contains("Answer like a pirate.")), "persona in the system prompt");
        assert!(!req.tools.iter().any(|x| x.name == "shell"), "a disabled tool is not offered");
        // Clearing the persona removes the segment.
        ok(&c, "ui.chat.settings.set", json!({"id": id, "persona": ""}));
        assert!(!view(&c, &id).unwrap().system.iter().any(|s| s.id == PERSONA_SEGMENT));
    }

    #[test]
    fn skills_can_be_switched_off_per_conversation() {
        let t = kit();
        let c = ctx(&t);
        for n in ["alpha-skill", "beta-skill"] {
            let d = t.ws.join(".seagent/skills").join(n);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("SKILL.md"), format!("---
name: {n}
description: Does {n} things
---
body
")).unwrap();
        }
        let id = t.k.create_session(&t.ws, None, None, None).unwrap();
        let other = t.k.create_session(&t.ws, None, None, None).unwrap();
        let s = ok(&c, "ui.chat.settings.get", json!({"id": id}));
        let names: Vec<&str> = s["skills"].as_array().unwrap().iter().map(|x| x["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"alpha-skill") && names.contains(&"beta-skill"), "{names:?}");
        assert!(s["skills"].as_array().unwrap().iter().all(|x| x["enabled"] == true));
        let s = ok(&c, "ui.chat.settings.set", json!({"id": id, "skills_disabled": ["alpha-skill"]}));
        assert_eq!(s["skills_disabled"], json!(["alpha-skill"]));
        assert!(s["skills"].as_array().unwrap().iter().any(|x| x["name"] == "alpha-skill" && x["enabled"] == false));
        let skills_text = |sid: &str| view(&c, sid).unwrap().system.iter().find(|x| x.id == "skills").map(|x| x.text.clone()).unwrap_or_default();
        assert!(!skills_text(&id).contains("alpha-skill") && skills_text(&id).contains("beta-skill"), "{}", skills_text(&id));
        assert!(skills_text(&other).contains("alpha-skill"), "other conversations keep every skill");
        // The model cannot load it by name either.
        let v = view(&c, &id).unwrap();
        assert!(seagent_kernel::subagents::skill_refused(&v, "skill", &json!({"action": "view", "name": "alpha-skill"})).is_some());
        assert!(seagent_kernel::subagents::skill_refused(&v, "skill", &json!({"action": "view", "name": "beta-skill"})).is_none());
        assert!(seagent_kernel::subagents::skill_refused(&v, "skill", &json!({"action": "list"})).is_none());
        // A fork keeps the switch; turning it back on restores the index line.
        let f = ok(&c, "ui.chat.fork", json!({"id": id}))["id"].as_str().unwrap().to_string();
        assert_eq!(view(&c, &f).unwrap().skills_disabled, ["alpha-skill"]);
        ok(&c, "ui.chat.settings.set", json!({"id": id, "skills_disabled": []}));
        assert!(skills_text(&id).contains("alpha-skill"));
        assert!(err(&c, "ui.chat.settings.set", json!({"id": id, "skills_disabled": "alpha-skill"})).1.contains("array"));
    }

    #[test]
    fn rail_state_is_kept_per_scope() {
        let t = kit();
        let c = ctx(&t);
        let id = t.k.create_session(&t.ws, None, None, None).unwrap();
        ok(&c, "ui.chat.section", json!({"op": "add", "name": "Owner's"}));
        ok(&c, "ui.chat.section", json!({"op": "add", "name": "Device's", "_rail": "device:phone-1"}));
        ok(&c, "ui.chat.meta.set", json!({"id": id, "unread": true, "_rail": "device:phone-1"}));
        let owner = ok(&c, "ui.chat.list", json!({}));
        let dev = ok(&c, "ui.chat.list", json!({"_rail": "device:phone-1"}));
        assert_eq!(owner["sections"].as_array().unwrap().len(), 1);
        assert_eq!(owner["sections"][0]["name"], "Owner's");
        assert_eq!(dev["sections"][0]["name"], "Device's");
        assert_eq!((owner["unread"].as_array().unwrap().len(), dev["unread"].as_array().unwrap().len()), (0, 1));
        assert!(std::fs::read_dir(t.paths.data.join("ui/chats")).unwrap().all(|e| e.unwrap().file_name().to_string_lossy().chars().all(|ch| ch.is_ascii_hexdigit() || ch == '.' || ch.is_ascii_lowercase())));
    }

    #[test]
    fn export_redacts_vault_values() {
        let t = kit();
        let c = ctx(&t);
        t.k.vault.set("CHAT_EXPORT_TOKEN", "tok-very-secret-123").unwrap();
        let id = t.k.create_session(&t.ws, None, None, Some("exp")).unwrap();
        t.k.submit(&id, "my token is tok-very-secret-123", "web").unwrap();
        t.k.run(&id, Default::default()).unwrap();
        let md = ok(&c, "ui.chat.export", json!({"id": id, "format": "md"}));
        assert!(md["name"].as_str().unwrap().ends_with(".md"));
        let text = md["text"].as_str().unwrap();
        assert!(text.contains("my token is") && !text.contains("tok-very-secret-123"), "{text}");
        let js = ok(&c, "ui.chat.export", json!({"id": id, "format": "json"}));
        assert!(serde_json::from_str::<Value>(js["text"].as_str().unwrap()).is_ok());
        assert!(err(&c, "ui.chat.export", json!({"id": id, "format": "pdf"})).1.contains("format"));
    }

    #[test]
    fn chat_menu_js_calls_only_served_methods() {
        for (name, js) in [("chat_menu.js", include_str!("../../../../ui/web/chat_menu.js")), ("keys.js", include_str!("../../../../ui/web/keys.js"))] {
            let mut called: Vec<&str> = js.match_indices("'ui.").map(|(i, _)| &js[i + 1..]).map(|s| &s[..s.find('\'').unwrap_or(0)]).filter(|m| m.starts_with("ui.chat") || m.starts_with("ui.keys")).collect();
            called.sort();
            called.dedup();
            assert!(!called.is_empty(), "{name}: scanner found no ui.chat / ui.keys calls");
            for m in called {
                assert!(METHODS.contains(&m) || crate::ops::model_keys::METHODS.contains(&m), "{name} calls `{m}`, which no module serves");
            }
        }
    }
}
