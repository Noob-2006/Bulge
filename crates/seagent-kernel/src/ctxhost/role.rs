//! `/role` — the occupation this session works as (crate::roles), on every surface.
//!
//! - `/role` or `/role show`: the current role, its layers and their token cost.
//! - `/role list [words]`: the presets, or the packs matching the words.
//! - `/role <ISCO code | name | preset>` (or `/role use …`): switch this session now (its
//!   `role` segment is rewritten) and new sessions of this process; `seagent role use` saves it.
//! - `/role none`: back to the L0 core only.
//!
//! The choice is per process, like `/personality`: `[role] active` stays the saved default.

use super::Host;
use crate::kernel::Kernel;
use crate::lifecycle::Lifecycle;
use crate::roles::{self, Catalog, Found, Role};
use seagent_core::SystemSegment;
use std::sync::{Arc, RwLock};

/// `/role` selection for this process: `None` = follow `[role] active`, `Some("")` = none.
#[derive(Default)]
pub struct RoleChoice(RwLock<Option<String>>);

impl RoleChoice {
    pub fn get(&self) -> Option<String> {
        self.0.read().unwrap().clone()
    }
    pub fn set(&self, id: &str) {
        *self.0.write().unwrap() = Some(id.to_string());
    }
}

/// The role new sessions of this process start with.
fn current(host: &Host, cfg: &crate::config::Config) -> Option<Role> {
    match host.role.get() {
        Some(id) if id.is_empty() => None,
        Some(id) => roles::resolve(cfg, &Catalog::for_config(cfg), &id).ok(),
        None => roles::active(cfg),
    }
}

/// Lifecycle segment: the `/role` choice for new sessions (an empty segment drops the config's).
pub struct RoleSegment(pub Arc<Host>);

impl Lifecycle for RoleSegment {
    fn name(&self) -> String {
        "ctxhost:role".into()
    }
    fn system_segment(&self, _workspace: &str) -> Option<SystemSegment> {
        self.0.role.get()?;
        let cfg = self.0.cfg()?;
        Some(current(&self.0, &cfg).map(|r| r.segment()).unwrap_or(SystemSegment { id: roles::SEGMENT_ID.into(), text: String::new(), cache: false }))
    }
}

/// The role of a live session (its segment marker), else what a new session would get.
pub fn session_role(k: &Kernel, session: Option<&str>) -> Option<Role> {
    let cfg = k.cfg_now();
    if let Some(ev) = session.and_then(|s| k.store.read(s).ok()) {
        let v = crate::projection::project(&ev);
        let id = v.system.iter().find(|s| s.id == roles::SEGMENT_ID).and_then(|s| roles::segment_role_id(&s.text))?;
        return roles::resolve(&cfg, &Catalog::for_config(&cfg), &id).ok();
    }
    roles::active(&cfg)
}

/// One line for `/context`: what the professional rules cost in this prompt.
pub fn context_line(k: &Kernel, session: Option<&str>) -> String {
    let cfg = k.cfg_now();
    let core = if cfg.role.core { roles::core_pack(&Catalog::for_config(&cfg)).tokens() } else { 0 };
    match session_role(k, session) {
        Some(r) => {
            let (_, l1, l2) = r.tokens();
            format!("role: {} [{}] · L0 ~{core} + L1 ~{l1} + L2 ~{l2} = ~{} tokens{}\n", r.title, r.id, core + l1 + l2, if r.regulated() { " · regulated (reserved acts enforced)" } else { "" })
        }
        None => format!("role: core conduct only · L0 ~{core} tokens (choose one with /role)\n"),
    }
}

fn show(r: Option<&Role>, core_on: bool) -> String {
    let Some(r) = r else {
        return format!("role: none — the default agent carries the L0 professional core{}.\nChoose one: /role <ISCO code | 職業名稱 | preset>, e.g. /role 2512, /role devops. List: /role list", if core_on { "" } else { " (switched off: [role] core = false)" });
    };
    let (l0, l1, l2) = r.tokens();
    let mut out = format!("role: {} [{}]\n", r.title, r.id);
    out.push_str(&format!("  L0 {} ~{l0} tokens (in the identity)\n", roles::CORE_SLUG));
    for p in &r.packs {
        out.push_str(&format!("  {} {} — {} (ISCO {}) ~{} tokens{}\n", p.layer.as_str(), p.slug, p.title_zh, p.isco, p.tokens(), if p.regulated { " · regulated" } else { "" }));
    }
    out.push_str(&format!("  total ~{} tokens\n", l0 + l1 + l2));
    if let Some(t) = r.tool_profile() {
        out.push_str(&format!("  tools: profile `{t}`\n"));
    }
    let acts = r.acts();
    if !acts.is_empty() {
        out.push_str(&format!("  reserved acts (handed to a licensed person): {}\n", acts.join(", ")));
    }
    out
}

fn list(k: &Kernel, words: &str) -> String {
    let cfg = k.cfg_now();
    let cat = Catalog::for_config(&cfg);
    if words.trim().is_empty() {
        let mut out = String::from("presets (pre-assembled professional roles):\n");
        for p in roles::presets(&cfg) {
            out.push_str(&format!("  {:<10} {} / {} — {}\n", p.id, p.title_zh, p.title_en, p.summary));
        }
        out.push_str(&format!("plus {} occupation packs by ISCO-08 code: /role list <words or code>, or `seagent role list`.", cat.by_layer(roles::Layer::L2).count()));
        return out;
    }
    match roles::find(&cfg, &cat, words) {
        Found::One(id) => format!("1 match: {id}\nUse it: /role {id}"),
        Found::Many(v) => {
            let mut out = format!("{} matches:\n", v.len());
            for (_, label) in v.iter().take(30) {
                out.push_str(&format!("  {label}\n"));
            }
            if v.len() > 30 {
                out.push_str(&format!("  (+{} more; be more specific)\n", v.len() - 30));
            }
            out
        }
        Found::None => format!("no role matches `{}`", words.trim()),
    }
}

/// Rewrite a live session's `role` segment (or drop it).
pub fn refresh(k: &Kernel, session: &str, role: Option<&Role>) -> Result<(), String> {
    let events = k.store.read(session).map_err(|e| e.to_string())?;
    let current = crate::projection::project(&events).system;
    let mut segs: Vec<SystemSegment> = current.iter().filter(|s| s.id != roles::SEGMENT_ID).cloned().collect();
    if let Some(r) = role {
        let at = segs.iter().position(|s| s.id == "identity").map(|i| i + 1).unwrap_or(0);
        segs.insert(at, r.segment());
    }
    roles::hook::invalidate();
    if segs == current {
        return Ok(());
    }
    k.record(session, crate::event::EventKind::System { segments: segs }).map_err(|e| e.to_string())
}

pub fn command(host: &Host, k: &Kernel, session: Option<&str>, args: &str) -> String {
    let cfg = k.cfg_now();
    let a = args.trim();
    let (verb, rest) = a.split_once(char::is_whitespace).map(|(v, r)| (v, r.trim())).unwrap_or((a, ""));
    match verb.to_lowercase().as_str() {
        "" | "show" | "status" => {
            let mut out = show(session_role(k, session).as_ref(), cfg.role.core);
            out.push_str(&context_line(k, session));
            out
        }
        "list" | "ls" | "search" => list(k, rest),
        _ => {
            let q = if verb.eq_ignore_ascii_case("use") || verb.eq_ignore_ascii_case("set") { rest } else { a };
            let chosen = if roles::is_none(q) {
                None
            } else {
                match roles::find(&cfg, &Catalog::for_config(&cfg), q) {
                    Found::One(id) => Some(id),
                    Found::Many(_) => return format!("`{q}` matches several roles — pick one:\n{}", list(k, q)),
                    Found::None => return format!("no role matches `{q}` (try /role list {q})"),
                }
            };
            let role = match &chosen {
                Some(id) => match roles::resolve(&cfg, &Catalog::for_config(&cfg), id) {
                    Ok(r) => Some(r),
                    Err(e) => return e,
                },
                None => None,
            };
            host.role.set(chosen.as_deref().unwrap_or(""));
            let mut out = match &role {
                Some(r) => format!("role → {} [{}]", r.title, r.id),
                None => "role → none (L0 core only)".into(),
            };
            if let Some(sid) = session {
                match refresh(k, sid, role.as_ref()) {
                    Ok(()) => out.push_str("\n(this session's prompt was rewritten; new sessions of this process use it too)"),
                    Err(e) => out.push_str(&format!("\n(could not rewrite this session's prompt: {e})")),
                }
            }
            if role.as_ref().is_some_and(|r| r.tool_profile().is_some() || !r.policy().is_empty()) {
                out.push_str("\nThe role's tool profile and approval defaults apply from the next start; its refusals (deny list, reserved acts) apply now.");
            }
            out.push_str(&format!("\nNot saved: `seagent role use {}` keeps it across restarts.", chosen.as_deref().unwrap_or("none")));
            out
        }
    }
}
