//! ARP methods behind the Control UI pages (OpenClaw `ui/src/pages/*`, MIT): config,
//! channels, skills + skill workshop, cron, usage, secrets, terminal, dashboards / apps /
//! portals, agents, lobsterdex, memory import, meetings (transcripts), worktrees, cloud
//! workers (sandbox environments), web search, systems / custodian / labs / about / profile.
//! The workboard page uses the kernel's `kanban.*` methods and the dashboards page the
//! surfaces' `surfaces.*`; this module only adds what has no method yet.
//!
//! Registered by `ark daemon run` (`methods`), names listed in `METHODS` for `initialize`.
//! Everything goes through the app token like every other ARP call; secret values are
//! never returned, config text comes back redacted, and the terminal is off unless
//! `[app] terminal = true`.

use ark_kernel::config::{project_config, Config, Paths};
use ark_kernel::daemon::MethodExt;
use ark_kernel::event::EventKind;
use ark_kernel::kernel::Kernel;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Method names exposed to the app server (WebSocket/HTTP ARP) in addition to the daemon's own.
pub const METHODS: &[&str] = &[
    "command.list", "logs.tail",
    "ui.pages",
    "ui.config.get", "ui.config.set", "ui.config.unset", "ui.config.save", "ui.config.backups", "ui.config.restore",
    "ui.channels", "ui.channels.set",
    "ui.skills.list", "ui.skills.get", "ui.skills.toggle", "ui.skills.workshop.list", "ui.skills.workshop.save", "ui.skills.workshop.delete",
    "ui.skills.workshop.archived", "ui.skills.workshop.restore",
    "ui.cron.add", "ui.cron.update", "ui.cron.remove", "ui.cron.enable", "ui.cron.run",
    "ui.usage", "ui.usage.export",
    "ui.secrets.list", "ui.secrets.set", "ui.secrets.delete",
    "ui.terminal.status", "ui.terminal.open", "ui.terminal.write", "ui.terminal.read", "ui.terminal.resize", "ui.terminal.close",
    "ui.apps",
    "ui.agents", "ui.agents.file.get", "ui.agents.file.set",
    "ui.lobsterdex",
    "ui.memory.plan", "ui.memory.apply",
    "ui.transcripts.list", "ui.transcripts.get", "ui.transcripts.export",
    "ui.worktrees.list", "ui.worktrees.create", "ui.worktrees.remove", "ui.worktrees.prune",
    "ui.environments", "ui.environments.destroy",
    "ui.search", "ui.websearch.status", "ui.websearch.set", "ui.websearch.test",
    "ui.systems", "ui.systems.backup", "ui.custodian", "ui.labs", "ui.labs.set", "ui.about", "ui.profile", "ui.profile.set",
];

type Res = Result<Value, (i32, String)>;

fn bad(e: impl Into<String>) -> (i32, String) {
    (-32602, e.into())
}
fn fail(e: impl Into<String>) -> (i32, String) {
    (-32000, e.into())
}

/// Live state the pages need from the daemon's extensions.
#[derive(Clone, Default)]
pub struct Live {
    /// Running channel adapters: name → kind.
    pub channels: BTreeMap<String, String>,
    pub plugins: Vec<Value>,
    pub mcp: Vec<Value>,
    pub mcp_apps: Vec<Value>,
}

pub struct UiCtx {
    pub paths: Paths,
    pub k: Kernel,
    /// Default workspace (the daemon's directory or `[app] workspace`).
    pub ws: PathBuf,
    pub live: Live,
    pub terms: crate::ops::ui_term::Terminals,
}

pub fn methods(paths: &Paths, k: Kernel, ext: Option<&crate::ext::Ext>) -> MethodExt {
    let mut live = Live::default();
    if let Some(e) = ext {
        live.channels = e.channels.iter().map(|(n, (_, c))| (n.clone(), c.kind.clone())).collect();
        live.plugins = e.plugins.iter().map(|p| json!({"name": p.name, "ui": p.ui, "routes": p.routes})).collect();
        live.mcp = e.registry.status().into_iter().map(|(n, tools, running)| json!({"name": n, "tools": tools, "running": running})).collect();
        live.mcp_apps = e.registry.app_tools().into_iter().map(|(s, d)| json!({"server": s, "name": d.name, "description": d.description})).collect();
    }
    let ws = k.cfg.app.get("workspace").and_then(|v| v.as_str()).map(PathBuf::from).or_else(|| std::env::current_dir().ok()).unwrap_or_else(|| PathBuf::from("/"));
    let c = Arc::new(UiCtx { paths: paths.clone(), k, ws, live, terms: Default::default() });
    Arc::new(move |m: &str, p: &Value| call(&c, m, p))
}

/// The page index the web UI builds its navigation from (OpenClaw app-navigation groups).
pub const PAGES: &[(&str, &str, &str)] = &[
    ("channels", "Channels", "control"),
    ("skills", "Skills", "agent"),
    ("skill-workshop", "Skill workshop", "agent"),
    ("cron", "Cron", "control"),
    ("usage", "Usage", "control"),
    ("config", "Config", "settings"),
    ("secrets", "Secrets", "settings"),
    ("terminal", "Terminal", "control"),
    ("dashboards", "Dashboards", "agent"),
    ("apps", "Apps", "agent"),
    ("portals", "Portals", "agent"),
    ("workboard", "Workboard", "agent"),
    ("agents", "Agents", "agent"),
    ("claws", "Claws", "agent"),
    ("lobsterdex", "Lobsterdex", "agent"),
    ("memory-import", "Memory import", "agent"),
    ("meetings", "Meetings", "agent"),
    ("worktrees", "Worktrees", "control"),
    ("cloud-workers", "Cloud workers", "control"),
    ("search", "Search", "settings"),
    ("systems", "Systems", "settings"),
    ("custodian", "Custodian", "settings"),
    ("labs", "Labs", "settings"),
    ("about", "About", "settings"),
    ("profile", "Profile", "settings"),
    // Pages served by `ops::webui` (model providers, paired devices, plugins + MCP, daemon logs).
    ("fleet", "Agent fleet", "control"),
    // ent-062: the central console (nodes, HA, workers, all sessions, managed policy) — served
    // by the daemon's own `cluster.*` methods (ark_kernel::cluster).
    ("cluster", "Cluster", "control"),
    ("models", "Model providers", "settings"),
    ("devices", "Devices", "control"),
    ("plugins", "Plugins", "agent"),
    ("logs", "Logs", "control"),
];

pub fn call(c: &UiCtx, m: &str, p: &Value) -> Option<Res> {
    let s = |k: &str| p[k].as_str().unwrap_or("").trim().to_string();
    // `workspace` comes from the client (`ui.agents.file.set`, `ui.skills.workshop.save`,
    // `ui.worktrees.create`, `ui.terminal.*`, `ui.config.get`…): validate it once here, before
    // any arm can join a name onto it, so `{"workspace": "/etc"}` cannot write outside a
    // configured workspace.
    let ws = match workspace_param(c, p["workspace"].as_str().unwrap_or("")) {
        Ok(w) => w,
        Err(e) => return Some(Err(e)),
    };
    Some(match m {
        "ui.pages" => Ok(json!(PAGES.iter().map(|(id, t, g)| json!({"id": id, "title": t, "group": g})).collect::<Vec<_>>())),
        // ── config ──
        "ui.config.get" => config_get(c, &ws),
        "ui.config.set" => need(&s("key"), "key").and_then(|k| crate::ops::confcli::set(&c.paths, &k, &s("value")).map(|t| json!({"ok": true, "message": t})).map_err(fail)),
        "ui.config.unset" => need(&s("key"), "key").and_then(|k| crate::ops::confcli::unset(&c.paths, &k).map(|t| json!({"ok": true, "message": t})).map_err(fail)),
        "ui.config.save" => config_save(c, p["text"].as_str().unwrap_or("")),
        "ui.config.backups" => Ok(json!(crate::ops::confcli::backups(&c.paths).iter().map(|b| b.display().to_string()).collect::<Vec<_>>())),
        "ui.config.restore" => config_restore(c, &s("path")),
        // ── channels ──
        "ui.channels" => channels(c, &ws),
        "ui.channels.set" => channel_set(c, &s("name"), &s("key"), &s("value")),
        // ── skills ──
        "ui.skills.list" => Ok(skills_list(c, &ws)),
        "ui.skills.get" => skill_get(c, &ws, &s("name")),
        "ui.skills.toggle" => skill_toggle(c, &s("name"), p["enabled"].as_bool().unwrap_or(true)),
        "ui.skills.workshop.list" => Ok(workshop_list(c)),
        "ui.skills.workshop.save" => workshop_save(c, &ws, &s("name"), &s("description"), p["body"].as_str().unwrap_or("")),
        "ui.skills.workshop.delete" => workshop_delete(c, &s("name")),
        "ui.skills.workshop.archived" => Ok(json!(workshop_archived(c).into_iter().map(|(name, dir, ts)| json!({"name": name, "id": dir, "archived_ms": ts})).collect::<Vec<_>>())),
        "ui.skills.workshop.restore" => workshop_restore(c, &s("name")),
        // ── cron ──
        "ui.cron.add" => cron_add(c, p, &ws),
        "ui.cron.update" => cron_update(c, &s("id"), p),
        "ui.cron.remove" => ark_kernel::automation::remove_job(&c.paths.data, &s("id")).map(|ok| json!({"removed": ok})).map_err(fail),
        "ui.cron.enable" => ark_kernel::automation::set_job_enabled(&c.paths.data, &s("id"), p["enabled"].as_bool().unwrap_or(true)).map(|ok| json!({"updated": ok})).map_err(fail),
        "ui.cron.run" => cron_run(c, &s("id")),
        // ── usage ──
        "ui.usage" => Ok(usage(c, p["days"].as_u64().unwrap_or(30))),
        "ui.usage.export" => usage_export(c, p),
        // ── secrets ──
        "ui.secrets.list" => secrets_list(c),
        "ui.secrets.set" => secret_set(c, &s("name"), p["value"].as_str().unwrap_or("")),
        "ui.secrets.delete" => vault(c).and_then(|v| v.remove(&s("name")).map_err(fail)).map(|ok| json!({"removed": ok})),
        // ── terminal ──
        m if m.starts_with("ui.terminal.") => crate::ops::ui_term::call(&c.terms, terminal_enabled(c), &ws, &m["ui.terminal.".len()..], p),
        // ── dashboards / apps / portals ──
        "ui.apps" => Ok(apps(c)),
        // ── agents ──
        "ui.agents" => Ok(agents(c, &ws)),
        "ui.agents.file.get" => agent_file(&ws, &s("name"), None),
        "ui.agents.file.set" => agent_file(&ws, &s("name"), Some(p["content"].as_str().unwrap_or(""))),
        "ui.lobsterdex" => Ok(lobsterdex(c, &ws)),
        // ── memory import ──
        "ui.memory.plan" => Ok(memory_plan(c, p)),
        "ui.memory.apply" => memory_apply(c, &s("provider"), p),
        // ── meetings ──
        "ui.transcripts.list" => Ok(transcripts_list(c, &s("query"))),
        "ui.transcripts.get" => transcript_get(c, &s("id"), &s("query")),
        "ui.transcripts.export" => transcript_export(c, &s("id"), p["format"].as_str().unwrap_or("markdown")),
        // ── worktrees ──
        "ui.worktrees.list" => ark_kernel::worktree::list(&ws).map(|v| json!(v)).map_err(fail),
        "ui.worktrees.create" => need(&s("name"), "name").and_then(|n| ark_kernel::worktree::create(&ws, &n).map(|i| json!({"path": i.path, "branch": i.branch, "repo_root": i.repo_root, "base_commit": i.base_commit})).map_err(fail)),
        "ui.worktrees.remove" => need(&s("name"), "name").and_then(|n| ark_kernel::worktree::remove(&ws, &n).map(|p| json!({"removed": p})).map_err(fail)),
        "ui.worktrees.prune" => ark_kernel::worktree::prune(&ws, p["dry_run"].as_bool().unwrap_or(true)).map(|v| json!({"pruned": v})).map_err(fail),
        // ── cloud workers ──
        "ui.environments" => Ok(environments(c)),
        "ui.environments.destroy" => environment_destroy(c, &s("id")),
        // ── search ──
        "ui.search" => Ok(search(c, &s("query"), p["limit"].as_u64().unwrap_or(20) as usize)),
        "ui.websearch.status" => Ok(websearch_status(c, &ws, None)),
        "ui.websearch.test" => websearch_test(c, &ws, p["query"].as_str().unwrap_or("ark"), None, p["run"].as_bool().unwrap_or(false)),
        "ui.websearch.set" => {
            let v = s("provider");
            let r = if v.is_empty() { crate::ops::confcli::unset(&c.paths, "web.search.provider") } else { crate::ops::confcli::set(&c.paths, "web.search.provider", &format!("{v:?}")) };
            r.map(|t| json!({"ok": true, "message": t})).map_err(fail)
        }
        // ── systems / custodian / labs / about / profile ──
        "ui.systems" => Ok(systems(c)),
        "ui.systems.backup" => {
            let cfg = fresh(c, &ws).unwrap_or_default();
            let dir = crate::ops::backup::default_dir(&c.paths, &cfg.backup);
            let ts = ark_kernel::event::now_ms();
            crate::ops::backup::create(&c.paths, &dir.join(format!("ark-backup-{ts}.tar.gz")), &Default::default()).map(|(p, m)| json!({"path": p.display().to_string(), "manifest": m})).map_err(fail)
        }
        "ui.custodian" => Ok(custodian(c)),
        "ui.labs" => Ok(labs(c, &ws)),
        "ui.labs.set" => labs_set(c, &s("id"), p["enabled"].as_bool().unwrap_or(false)),
        "ui.about" => Ok(about(c)),
        "ui.profile" => Ok(profile(c)),
        "ui.profile.set" => profile_set(c, p),
        _ => return None,
    })
}

fn need(v: &str, what: &str) -> Result<String, (i32, String)> {
    if v.is_empty() {
        Err(bad(format!("{what} is required")))
    } else {
        Ok(v.to_string())
    }
}

/// Roots a client-supplied `workspace` may name: the configured workspace (`[app] workspace`,
/// else the daemon's own directory) and every `trusted_projects` entry — the registries this
/// file already reads (`fresh`, `agent_file`, `workshop_save`).
fn workspace_roots(c: &UiCtx) -> Vec<PathBuf> {
    let mut roots = vec![c.ws.clone()];
    roots.extend(c.k.cfg.trusted_projects.iter().map(PathBuf::from));
    roots.retain(|r| r.is_dir());
    roots.iter().map(|r| std::fs::canonicalize(r).unwrap_or_else(|_| r.clone())).collect()
}

/// Validate the client-supplied `workspace` parameter: empty means the configured workspace,
/// anything else must canonicalise to an existing directory *inside* one of
/// [`workspace_roots`]. `/etc`, `..` escapes and a symlink out of the workspace are refused
/// here, before `ui.agents.file.*`, `ui.skills.workshop.save`, `ui.worktrees.*` or the
/// terminal can join a path onto it.
fn workspace_param(c: &UiCtx, raw: &str) -> Result<PathBuf, (i32, String)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(c.ws.clone());
    }
    let real = std::fs::canonicalize(raw).map_err(|e| bad(format!("workspace {raw}: {e}")))?;
    if !real.is_dir() {
        return Err(bad(format!("workspace {} is not a directory", real.display())));
    }
    let roots = workspace_roots(c);
    if roots.iter().any(|r| real.starts_with(r)) {
        return Ok(real);
    }
    Err(bad(format!(
        "workspace {} is outside the configured workspace (allowed roots: {})",
        real.display(),
        roots.iter().map(|r| r.display().to_string()).collect::<Vec<_>>().join(", ")
    )))
}

/// The config as it is on disk now (the daemon's own copy can be stale after edits).
fn fresh(c: &UiCtx, ws: &Path) -> Result<Config, String> {
    Config::load(Some(&c.paths.user_config()), Some(&project_config(ws)), &[])
}

fn vault(c: &UiCtx) -> Result<ark_kernel::vault::Vault, (i32, String)> {
    ark_kernel::vault::Vault::load(&c.paths.secrets()).map_err(fail)
}

// ───────────────────────── config ─────────────────────────

/// Redacted user config text, its path and the JSON schema (Config page).
fn config_get(c: &UiCtx, ws: &Path) -> Res {
    let path = c.paths.user_config();
    let text = std::fs::read_to_string(&path).unwrap_or_default();
    let valid = fresh(c, ws).err();
    Ok(json!({
        "path": path.display().to_string(),
        "text": crate::slash::redact(&text),
        "redacted": crate::slash::redact(&text) != text,
        "error": valid,
        "schema": crate::ops::confcli::schema(),
        "project": project_config(ws).display().to_string(),
    }))
}

/// Replace the user config with `text` (validated, previous version backed up). Text that
/// still carries a redaction placeholder is refused so a save can never wipe a key.
fn config_save(c: &UiCtx, text: &str) -> Res {
    if text.lines().any(|l| l.split_once('=').is_some_and(|(_, v)| v.trim() == "\"***\"")) {
        return Err(bad("the text still contains redacted values (\"***\"); set those keys one by one or move them to secrets"));
    }
    crate::ops::confcli::write_validated(&c.paths, text, true).map_err(fail)?;
    Ok(json!({"ok": true, "path": c.paths.user_config().display().to_string()}))
}

/// Put one of the config backups back (OpenClaw config page "previous versions"). Only a
/// file `confcli::backups` lists is accepted, so a page cannot read arbitrary paths, and the
/// current file is backed up first (an undo of the undo).
fn config_restore(c: &UiCtx, want: &str) -> Res {
    if want.is_empty() {
        return Err(bad("path is required"));
    }
    let known = crate::ops::confcli::backups(&c.paths);
    let Some(src) = known.iter().find(|p| p.display().to_string() == want || p.file_name().is_some_and(|n| n.to_string_lossy() == want)).cloned() else {
        return Err(bad(format!("no config backup `{want}` (see ui.config.backups)")));
    };
    let text = std::fs::read_to_string(&src).map_err(|e| fail(e.to_string()))?;
    crate::ops::confcli::write_validated(&c.paths, &text, true).map_err(fail)?;
    Ok(json!({"restored": src.display().to_string(), "path": c.paths.user_config().display().to_string(), "restart": true}))
}

// ───────────────────────── channels ──────────────────────────

fn str_list(t: &toml::Table, k: &str) -> Vec<String> {
    t.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from).or_else(|| x.as_integer().map(|i| i.to_string()))).collect()).unwrap_or_default()
}

/// Configured channels with their access policy (no tokens) and whether they are running.
fn channels(c: &UiCtx, ws: &Path) -> Res {
    let cfg = fresh(c, ws).map_err(fail)?;
    let mut out = vec![];
    for (name, t) in &cfg.channels {
        let kind = t.get("kind").and_then(|v| v.as_str()).unwrap_or(name).to_string();
        out.push(json!({
            "name": name,
            "kind": kind,
            "enabled": t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
            "running": c.live.channels.contains_key(name),
            "dm_policy": t.get("dm_policy").and_then(|v| v.as_str()).unwrap_or("pairing"),
            "group_policy": t.get("group_policy").and_then(|v| v.as_str()).unwrap_or(""),
            "allow": str_list(t, "allow"),
            "admins": str_list(t, "allow_admin_from"),
            "default_chat": t.get("default_chat").and_then(|v| v.as_str()),
            "credentials": t.keys().filter(|k| crate::slash::redact(&format!("{k} = \"xxxx\"")).contains("***")).cloned().collect::<Vec<_>>(),
        }));
    }
    for (name, kind) in &c.live.channels {
        if !cfg.channels.contains_key(name) {
            out.push(json!({"name": name, "kind": kind, "enabled": true, "running": true, "plugin": true}));
        }
    }
    Ok(json!({"channels": out, "kinds": ["telegram", "discord", "slack", "whatsapp", "signal", "matrix", "email", "sms", "irc", "mattermost", "teams", "webhook"]}))
}

/// Channel settings the page edits; credentials stay in secrets / `ark channels`.
const CHANNEL_KEYS: &[&str] = &["enabled", "dm_policy", "group_policy", "allow", "allow_admin_from", "group_allow_admin_from", "require_mention", "default_chat", "user_allowed_commands"];

fn channel_set(c: &UiCtx, name: &str, key: &str, value: &str) -> Res {
    if name.is_empty() || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
        return Err(bad("channel name must be letters, digits, - or _"));
    }
    if !CHANNEL_KEYS.contains(&key) {
        return Err(bad(format!("`{key}` is not editable here (editable: {})", CHANNEL_KEYS.join(", "))));
    }
    crate::ops::confcli::set(&c.paths, &format!("channels.{name}.{key}"), value).map(|t| json!({"ok": true, "message": t, "restart": true})).map_err(fail)
}

// ───────────────────────── skills / workshop ─────────────────────────

fn roots(c: &UiCtx, ws: &Path) -> Vec<(PathBuf, ark_skills::skill::Source)> {
    ark_skills::skill::roots(&c.paths, ws, &[])
}

fn skills_list(c: &UiCtx, ws: &Path) -> Value {
    let cfg = fresh(c, ws).unwrap_or_default();
    let st = ark_skills::core::settings::Settings::load(&cfg);
    let all = ark_skills::skill::discover(&roots(c, ws));
    json!(all.iter().map(|s| json!({"name": s.name, "description": s.description, "source": s.source.label(), "category": s.category, "enabled": !st.is_disabled(&s.name), "path": s.file.display().to_string()})).collect::<Vec<_>>())
}

fn skill_get(c: &UiCtx, ws: &Path, name: &str) -> Res {
    let all = ark_skills::skill::discover(&roots(c, ws));
    let s = ark_skills::skill::find(&all, name).ok_or_else(|| bad(format!("no skill `{name}`")))?;
    let mut files = vec![];
    for sub in ["references", "templates", "scripts", "assets"] {
        if let Ok(rd) = std::fs::read_dir(s.dir.join(sub)) {
            files.extend(rd.flatten().map(|e| format!("{sub}/{}", e.file_name().to_string_lossy())));
        }
    }
    files.sort();
    Ok(json!({"name": s.name, "description": s.description, "source": s.source.label(), "front": s.front, "body": s.body().map_err(fail)?, "files": files, "editable": s.source == ark_skills::skill::Source::User}))
}

/// `[skills] disabled` add/remove.
fn skill_toggle(c: &UiCtx, name: &str, enabled: bool) -> Res {
    if !ark_skills::skill::valid_name(name.rsplit('/').next().unwrap_or(name)) && !name.contains(':') {
        return Err(bad(format!("`{name}` is not a skill name")));
    }
    let text = std::fs::read_to_string(c.paths.user_config()).unwrap_or_default();
    let t: toml::Table = text.parse().map_err(|e| fail(format!("config does not parse: {e}")))?;
    let mut list = t.get("skills").and_then(|s| s.get("disabled")).and_then(|v| v.as_array()).cloned().unwrap_or_default();
    list.retain(|v| v.as_str() != Some(name));
    if !enabled {
        list.push(toml::Value::String(name.into()));
    }
    let new = crate::ops::confcli::edited_text(&text, "skills.disabled", Some(toml::Value::Array(list))).map_err(fail)?;
    crate::ops::confcli::write_validated(&c.paths, &new, true).map_err(fail)?;
    Ok(json!({"name": name, "enabled": enabled}))
}

/// Drafts in the user skill dir (the workshop edits only those).
fn workshop_list(c: &UiCtx) -> Value {
    let root = ark_skills::skill::user_dir(&c.paths);
    let all = ark_skills::skill::discover(&[(root, ark_skills::skill::Source::User)]);
    json!(all.iter().map(|s| {
        let mtime = std::fs::metadata(&s.file).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64);
        json!({"name": s.name, "description": s.description, "updated_ms": mtime, "category": s.category})
    }).collect::<Vec<_>>())
}

fn yaml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// Create or update a user skill: `<data>/skills/<name>/SKILL.md`. A skill of that name in
/// a project / bundled / plugin root is not shadowed silently.
fn workshop_save(c: &UiCtx, ws: &Path, name: &str, description: &str, body: &str) -> Res {
    if !ark_skills::skill::valid_name(name) {
        return Err(bad("skill names are lowercase letters, digits, -, _ or . (max 64)"));
    }
    if description.is_empty() {
        return Err(bad("a description is required (it is what the model sees in the skill index)"));
    }
    if description.chars().count() > ark_skills::skill::MAX_DESCRIPTION {
        return Err(bad(format!("description is longer than {} characters", ark_skills::skill::MAX_DESCRIPTION)));
    }
    let all = ark_skills::skill::discover(&roots(c, ws));
    if let Some(o) = all.iter().find(|s| s.name == name && s.source != ark_skills::skill::Source::User) {
        return Err(bad(format!("a {} skill named `{name}` already exists ({}); pick another name", o.source.label(), o.file.display())));
    }
    let dir = ark_skills::skill::user_dir(&c.paths).join(name);
    std::fs::create_dir_all(&dir).map_err(|e| fail(e.to_string()))?;
    let text = format!("---\nname: {name}\ndescription: {}\n---\n\n{}\n", yaml_str(description), body.trim_end());
    ark_kernel::util::atomic_write(&dir.join("SKILL.md"), text.as_bytes()).map_err(|e| fail(e.to_string()))?;
    Ok(json!({"name": name, "path": dir.join("SKILL.md").display().to_string()}))
}

fn workshop_delete(c: &UiCtx, name: &str) -> Res {
    if !ark_skills::skill::valid_name(name) {
        return Err(bad("not a skill name"));
    }
    let dir = ark_skills::skill::user_dir(&c.paths).join(name);
    if !dir.join("SKILL.md").is_file() {
        return Err(bad(format!("no user skill `{name}`")));
    }
    // Moved to the archive (Hermes curator semantics), never deleted outright.
    let archive = ark_skills::skill::user_dir(&c.paths).join(".archive");
    std::fs::create_dir_all(&archive).map_err(|e| fail(e.to_string()))?;
    let dest = archive.join(format!("{name}-{}", ark_kernel::event::now_ms()));
    std::fs::rename(&dir, &dest).map_err(|e| fail(e.to_string()))?;
    Ok(json!({"archived": dest.display().to_string()}))
}

/// Archived workshop drafts: `(name, archive dir name, archived ms)`, newest first.
pub fn workshop_archived(c: &UiCtx) -> Vec<(String, String, u64)> {
    let archive = ark_skills::skill::user_dir(&c.paths).join(".archive");
    let mut v: Vec<(String, String, u64)> = std::fs::read_dir(&archive)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let dir = e.file_name().to_string_lossy().to_string();
                    let (name, ts) = dir.rsplit_once('-').map(|(n, t)| (n.to_string(), t.parse::<u64>().unwrap_or(0))).unwrap_or((dir.clone(), 0));
                    (e.path().join("SKILL.md").is_file() && !name.is_empty()).then_some((name, dir, ts))
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_by_key(|x| std::cmp::Reverse(x.2));
    v
}

/// Put the newest archived version of `name` back (OpenClaw skill-workshop restore).
fn workshop_restore(c: &UiCtx, name: &str) -> Res {
    if !ark_skills::skill::valid_name(name) {
        return Err(bad("not a skill name"));
    }
    let dest = ark_skills::skill::user_dir(&c.paths).join(name);
    if dest.join("SKILL.md").is_file() {
        return Err(bad(format!("a user skill `{name}` already exists; rename or remove it first")));
    }
    let Some((_, dir, _)) = workshop_archived(c).into_iter().find(|row| row.0 == name) else {
        return Err(bad(format!("no archived skill `{name}`")));
    };
    let src = ark_skills::skill::user_dir(&c.paths).join(".archive").join(&dir);
    std::fs::rename(&src, &dest).map_err(|e| fail(e.to_string()))?;
    Ok(json!({"restored": name, "path": dest.join("SKILL.md").display().to_string()}))
}

// ───────────────────────── cron ─────────────────────────

fn cron_add(c: &UiCtx, p: &Value, ws: &Path) -> Res {
    let cron = p["cron"].as_str().unwrap_or("").trim();
    let prompt = p["prompt"].as_str().unwrap_or("").trim();
    ark_kernel::cron::Cron::parse(cron).map_err(|e| bad(format!("cron: {e}")))?;
    if prompt.is_empty() {
        return Err(bad("prompt is required"));
    }
    let model = p["model"].as_str().map(str::trim).filter(|m| !m.is_empty()).map(String::from);
    let j = ark_kernel::automation::add_job(&c.paths.data, cron, prompt, ws, model, p["reuse"].as_bool().unwrap_or(false), c.k.cfg.schedule.utc_offset_minutes).map_err(fail)?;
    Ok(json!(j))
}

/// Edit a job in place (OpenClaw `cron.update`). A changed expression recomputes
/// `next_run` from now, so a job that was paused for days does not fire on its stale slot.
fn cron_update(c: &UiCtx, id: &str, p: &Value) -> Res {
    if id.is_empty() {
        return Err(bad("id is required"));
    }
    let path = ark_kernel::automation::jobs_path(&c.paths.data);
    let mut job = ark_kernel::automation::read_list::<ark_kernel::automation::Job>(&path).map_err(fail)?.into_iter().find(|j| j.id == id).ok_or_else(|| bad(format!("no job `{id}`")))?;
    if let Some(cron) = p["cron"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        let parsed = ark_kernel::cron::Cron::parse(cron).map_err(|e| bad(format!("cron: {e}")))?;
        job.next_run = parsed.next_after(ark_kernel::util::unix_now(), c.k.cfg.schedule.utc_offset_minutes).ok_or_else(|| bad("that schedule never fires"))?;
        job.cron = cron.to_string();
    }
    if let Some(prompt) = p["prompt"].as_str().map(str::trim).filter(|s| !s.is_empty()) {
        job.prompt = prompt.to_string();
    }
    if let Some(m) = p["model"].as_str() {
        job.model = Some(m.trim().to_string()).filter(|m| !m.is_empty());
    }
    if let Some(e) = p["enabled"].as_bool() {
        job.enabled = e;
    }
    let keep = job.clone();
    ark_kernel::automation::with_list::<ark_kernel::automation::Job, _>(&path, |v| {
        if let Some(j) = v.iter_mut().find(|j| j.id == id) {
            *j = keep;
        }
    })
    .map_err(fail)?;
    Ok(json!({"job": job}))
}

/// Run a job now, in the background (results land in its session).
fn cron_run(c: &UiCtx, id: &str) -> Res {
    let jobs: Vec<ark_kernel::automation::Job> = ark_kernel::automation::read_list(&ark_kernel::automation::jobs_path(&c.paths.data)).map_err(fail)?;
    let job = jobs.into_iter().find(|j| j.id == id).ok_or_else(|| bad(format!("no job `{id}`")))?;
    let k = c.k.clone();
    std::thread::spawn(move || {
        let _ = ark_kernel::automation::run_job(&k, &job);
    });
    Ok(json!({"started": id}))
}

// ───────────────────────── usage ─────────────────────────

fn usage(c: &UiCtx, days: u64) -> Value {
    let days = days.clamp(1, 366);
    let since = ark_kernel::event::now_ms().saturating_sub(days * 86_400_000);
    let (rows, n) = crate::models_cli::usage_rows(&c.k.cfg, &c.k.store, since, None);
    let models: Vec<Value> = rows.iter().map(|(m, r)| json!({"model": m, "calls": r.calls, "input": r.input, "output": r.output, "cache_read": r.cache_read, "cache_write": r.cache_write, "cost_usd": r.priced.then_some(r.cost)})).collect();
    // Per day and per session (OpenClaw sessions.usage.timeseries / top sessions).
    let mut daily: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    let mut sessions: Vec<(String, String, u64)> = vec![];
    for s in c.k.store.list().into_iter().filter(|s| s.updated_ms >= since) {
        let Ok(evs) = c.k.store.read(&s.id) else { continue };
        let mut tot = 0;
        for e in evs.iter().filter(|e| e.ts >= since) {
            let u = match &e.kind {
                EventKind::Message { usage: Some(u), .. } => u,
                EventKind::AuxUsage { usage, .. } => usage,
                _ => continue,
            };
            let d = daily.entry(day_of(e.ts)).or_default();
            d.0 += u.input_tokens;
            d.1 += u.output_tokens;
            d.2 += 1;
            tot += u.total();
        }
        if tot > 0 {
            sessions.push((s.id.clone(), s.title.clone().unwrap_or_default(), tot));
        }
    }
    sessions.sort_by_key(|x| std::cmp::Reverse(x.2));
    sessions.truncate(20);
    let total_cost: f64 = rows.values().map(|r| r.cost).sum();
    let total_tokens: u64 = rows.values().map(|r| r.input + r.output).sum();
    json!({
        "days": days,
        "sessions_count": n,
        "models": models,
        "daily": daily.iter().map(|(d, (i, o, calls))| json!({"day": d, "input": i, "output": o, "calls": calls})).collect::<Vec<_>>(),
        "top_sessions": sessions.iter().map(|(id, t, tok)| json!({"id": id, "title": t, "tokens": tok})).collect::<Vec<_>>(),
        "total": {"tokens": total_tokens, "cost_usd": total_cost},
    })
}

/// `YYYY-MM-DD` (UTC) for a millisecond timestamp.
pub fn day_of(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    // Civil-from-days (H. Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    format!("{:04}-{m:02}-{d:02}", if m <= 2 { y + 1 } else { y })
}

fn csv_cell(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

pub fn usage_csv(u: &Value) -> String {
    let mut out = String::from("model,calls,input_tokens,output_tokens,cache_read_tokens,cache_write_tokens,cost_usd\n");
    for m in u["models"].as_array().into_iter().flatten() {
        out.push_str(&format!("{},{},{},{},{},{},{}\n", csv_cell(m["model"].as_str().unwrap_or("")), m["calls"], m["input"], m["output"], m["cache_read"], m["cache_write"], m["cost_usd"].as_f64().map(|c| format!("{c:.6}")).unwrap_or_default()));
    }
    out
}

/// Per-day token series (OpenClaw usage page "export daily").
pub fn usage_daily_csv(u: &Value) -> String {
    let mut out = String::from("day,input_tokens,output_tokens,calls\n");
    for d in u["daily"].as_array().into_iter().flatten() {
        out.push_str(&format!("{},{},{},{}\n", csv_cell(d["day"].as_str().unwrap_or("")), d["input"], d["output"], d["calls"]));
    }
    out
}

/// Top sessions by tokens (OpenClaw usage page "export sessions").
pub fn usage_sessions_csv(u: &Value) -> String {
    let mut out = String::from("session_id,title,tokens\n");
    for s in u["top_sessions"].as_array().into_iter().flatten() {
        out.push_str(&format!("{},{},{}\n", csv_cell(s["id"].as_str().unwrap_or("")), csv_cell(s["title"].as_str().unwrap_or("")), s["tokens"]));
    }
    out
}

/// The Usage page's export menu: models / daily / sessions CSV, or the whole rollup as JSON.
fn usage_export(c: &UiCtx, p: &Value) -> Res {
    let u = usage(c, p["days"].as_u64().unwrap_or(30));
    let (filename, ctype, body) = match p["format"].as_str().unwrap_or("models-csv") {
        "models-csv" => ("ark-usage-models.csv", "text/csv", usage_csv(&u)),
        "daily-csv" => ("ark-usage-daily.csv", "text/csv", usage_daily_csv(&u)),
        "sessions-csv" => ("ark-usage-sessions.csv", "text/csv", usage_sessions_csv(&u)),
        "json" => ("ark-usage.json", "application/json", u.to_string()),
        other => return Err(bad(format!("unknown usage export format `{other}` (models-csv, daily-csv, sessions-csv, json)"))),
    };
    Ok(json!({"filename": filename, "content": body, "type": ctype, "days": u["days"]}))
}

// ───────────────────────── secrets ─────────────────────────

fn secret_refs(text: &str) -> Vec<String> {
    let mut v = vec![];
    let mut rest = text;
    while let Some(i) = rest.find("{{secret:") {
        rest = &rest[i + 9..];
        if let Some(j) = rest.find("}}") {
            v.push(rest[..j].trim().to_string());
            rest = &rest[j..];
        }
    }
    v.sort();
    v.dedup();
    v
}

/// Names only: which secrets exist, which config references them and which are missing.
fn secrets_list(c: &UiCtx) -> Res {
    let v = vault(c)?;
    let text = std::fs::read_to_string(c.paths.user_config()).unwrap_or_default();
    let refs = secret_refs(&text);
    let names = v.names();
    Ok(json!({
        "secrets": names.iter().map(|n| json!({"name": n, "referenced": refs.contains(n)})).collect::<Vec<_>>(),
        "missing": refs.iter().filter(|r| !names.contains(r)).collect::<Vec<_>>(),
        "path": c.paths.secrets().display().to_string(),
    }))
}

fn secret_set(c: &UiCtx, name: &str, value: &str) -> Res {
    if name.is_empty() || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.') {
        return Err(bad("secret names are letters, digits, _, - or ."));
    }
    if value.is_empty() {
        return Err(bad("value is empty"));
    }
    vault(c)?.set(name, value).map_err(fail)?;
    Ok(json!({"name": name, "set": true, "ref": format!("{{{{secret:{name}}}}}")}))
}

// ───────────────────────── terminal ─────────────────────────

/// `[app] terminal = true` (OpenClaw `terminalEnabled`) from the user *and* project
/// config; off by default because it is a full shell as the daemon's user.
pub fn terminal_enabled(c: &UiCtx) -> bool {
    let cfg = fresh(c, &c.ws).unwrap_or_else(|_| c.k.cfg.clone());
    ark_app::AppConfig::parse(&cfg.app).map(|a| a.terminal).unwrap_or(false)
}

// ───────────────────────── dashboards / apps / portals ─────────────────────────

/// Canvas documents (`<data>/surfaces/canvas/documents/<id>/manifest.json`).
fn canvas_documents(c: &UiCtx) -> Vec<Value> {
    let dir = c.paths.data.join("surfaces/canvas/documents");
    let mut v: Vec<Value> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| {
                    let id = e.file_name().to_string_lossy().to_string();
                    let m: Value = std::fs::read(e.path().join("manifest.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(json!({}));
                    e.path().is_dir().then(|| json!({"id": id, "title": m["title"].as_str().unwrap_or(&id), "kind": m["kind"], "url": format!("/surfaces/canvas/documents/{id}/{}", m["localEntrypoint"].as_str().unwrap_or("index.html")), "created": m["createdAt"]}))
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_by(|a, b| b["created"].as_str().cmp(&a["created"].as_str()));
    v
}

/// Apps (plugin UI panels, MCP App tools) and portals (plugin HTTP mounts, canvas documents).
fn apps(c: &UiCtx) -> Value {
    let panels: Vec<Value> = c.live.plugins.iter().flat_map(|p| p["ui"].as_array().cloned().unwrap_or_default().into_iter().map(move |u| json!({"plugin": p["name"], "id": u["id"], "title": u["title"], "surface": u["surface"], "icon": u["icon"]}))).collect();
    let mounts: Vec<Value> = ark_app::server::mounts().into_iter().map(|n| json!({"name": n, "url": format!("/plugins/{n}/")})).collect();
    json!({"panels": panels, "mcp_apps": c.live.mcp_apps, "mcp": c.live.mcp, "portals": mounts, "canvas": canvas_documents(c)})
}

// ───────────────────────── agents ─────────────────────────

/// The workspace bootstrap files an agent's identity is built from (OpenClaw agent files).
pub const AGENT_FILES: &[&str] = &["AGENTS.md", "SOUL.md", "USER.md", "IDENTITY.md", "TOOLS.md", "MEMORY.md", "HEARTBEAT.md", "BOOTSTRAP.md"];

fn agents(c: &UiCtx, ws: &Path) -> Value {
    let cfg = fresh(c, ws).unwrap_or_else(|_| c.k.cfg.clone());
    let files: Vec<Value> = AGENT_FILES.iter().map(|f| {
        let p = ws.join(f);
        json!({"name": f, "exists": p.is_file(), "bytes": std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0)})
    }).collect();
    json!({
        "default": {"model": cfg.model.default, "identity": cfg.identity, "personality": cfg.personality},
        "agents": cfg.agents.iter().map(|(id, a)| json!({"id": id, "def": a})).collect::<Vec<_>>(),
        "bindings": cfg.bindings,
        "workspace": ws.display().to_string(),
        "files": files,
    })
}

fn agent_file(ws: &Path, name: &str, content: Option<&str>) -> Res {
    if !AGENT_FILES.contains(&name) {
        return Err(bad(format!("only {} can be edited here", AGENT_FILES.join(", "))));
    }
    let p = ws.join(name);
    match content {
        None => Ok(json!({"name": name, "content": std::fs::read_to_string(&p).unwrap_or_default(), "exists": p.is_file()})),
        Some(t) => {
            if t.len() > 512 * 1024 {
                return Err(bad("file is larger than 512 KiB"));
            }
            ark_kernel::util::atomic_write(&p, t.as_bytes()).map_err(|e| fail(e.to_string()))?;
            Ok(json!({"name": name, "saved": true}))
        }
    }
}

/// Lobster workflow files (`*.lobster`, `workflows/*.lobster` in the workspace and
/// `<data>/workflows`) plus paused runs.
fn lobsterdex(c: &UiCtx, ws: &Path) -> Value {
    let mut v = vec![];
    for dir in [ws.to_path_buf(), ws.join("workflows"), ws.join(".ark/workflows"), c.paths.data.join("workflows")] {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "lobster") {
                let text = std::fs::read_to_string(&p).unwrap_or_default();
                let stages = ark_app::surfaces::lobster::parse_pipeline(&text).map(|s| s.len());
                let desc = text.lines().find_map(|l| l.trim().strip_prefix('#').map(|d| d.trim().to_string())).unwrap_or_default();
                v.push(json!({"name": p.file_stem().map(|s| s.to_string_lossy().to_string()), "path": p.display().to_string(), "description": desc, "stages": stages.as_ref().ok(), "error": stages.err()}));
            }
        }
    }
    json!({"workflows": v, "paused": ark_app::surfaces::lobster::list_paused(&c.paths.data.join("surfaces"))})
}

// ───────────────────────── memory import ─────────────────────────

/// Memory entries other agents (OpenClaw, Hermes, Claude Code, Codex) hold, per provider.
fn memory_plan(c: &UiCtx, p: &Value) -> Value {
    let dest = c.paths.data.join("memory");
    // `provider` + `path` pin one source (the page can also show a source the host no
    // longer auto-detects); without them every detected source is planned.
    let only = p["provider"].as_str().map(str::trim).filter(|s| !s.is_empty());
    let providers: Vec<(String, PathBuf)> = match (only, p["path"].as_str()) {
        (Some(id), Some(root)) => vec![(id.to_string(), PathBuf::from(root))],
        (Some(id), _) => crate::ops::migrate::detect().into_iter().filter(|d| d.0 == id).map(|(i, r)| (i.to_string(), r)).collect(),
        _ => crate::ops::migrate::detect().into_iter().map(|(i, r)| (i.to_string(), r)).collect(),
    };
    let providers: Vec<Value> = providers
        .into_iter()
        .map(|(id, root)| match crate::ops::migrate::plan(&id, Some(&root), &c.paths.data) {
            Ok(acts) => {
                let items: Vec<Value> = acts
                    .iter()
                    .enumerate()
                    .filter_map(|(i, a)| match a {
                        crate::ops::migrate::Act::Memory(file, text) => {
                            // Same dedupe rule as `migrate::apply`: entries are `§`-separated.
                            let target = dest.join(file);
                            let existing = std::fs::read_to_string(&target).map(|cur| cur.split("\n§\n").any(|x| x.trim() == text.trim())).unwrap_or(false);
                            Some(json!({"id": i, "file": file, "text": text, "target": target.display().to_string(), "existing": existing}))
                        }
                        _ => None,
                    })
                    .collect();
                json!({"id": id, "path": root.display().to_string(), "items": items})
            }
            Err(e) => json!({"id": id, "path": root.display().to_string(), "items": [], "error": e}),
        })
        .collect();
    json!({"providers": providers, "dest": dest.display().to_string()})
}

/// Import the selected memory items of one provider (all when `items` is absent).
fn memory_apply(c: &UiCtx, provider: &str, p: &Value) -> Res {
    let root = crate::ops::migrate::detect().into_iter().find(|d| d.0 == provider).map(|d| d.1);
    let root = p["path"].as_str().map(PathBuf::from).or(root).ok_or_else(|| bad(format!("provider `{provider}` was not found on this machine")))?;
    let acts = crate::ops::migrate::plan(provider, Some(&root), &c.paths.data).map_err(fail)?;
    let pick: Option<Vec<u64>> = p["items"].as_array().map(|a| a.iter().filter_map(|x| x.as_u64()).collect());
    let chosen: Vec<crate::ops::migrate::Act> = acts.into_iter().enumerate().filter(|(i, a)| matches!(a, crate::ops::migrate::Act::Memory(..)) && pick.as_ref().is_none_or(|p| p.contains(&(*i as u64)))).map(|(_, a)| a).collect();
    if chosen.is_empty() {
        return Err(bad("nothing selected to import"));
    }
    let n = chosen.len();
    let summary = crate::ops::migrate::apply(&c.paths, &chosen, p["replace"].as_bool().unwrap_or(false)).map_err(fail)?;
    Ok(json!({"imported": n, "summary": summary}))
}

// ───────────────────────── meetings (transcripts) ─────────────────────────

/// `<data>/transcripts/<id>.json`: `{id, title, source, started_ms, ended_ms, participants,
/// segments: [{speaker, ts, text}], summary}` written by meeting bots / voice calls.
pub fn transcripts_dir(paths: &Paths) -> PathBuf {
    paths.data.join("transcripts")
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.') && !id.starts_with('.')
}

fn transcripts_list(c: &UiCtx, query: &str) -> Value {
    let q = query.to_lowercase();
    let mut v: Vec<Value> = std::fs::read_dir(transcripts_dir(&c.paths))
        .map(|rd| rd.flatten().filter_map(|e| std::fs::read(e.path()).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok())).collect())
        .unwrap_or_default();
    if !q.is_empty() {
        v.retain(|t| t.to_string().to_lowercase().contains(&q));
    }
    v.sort_by(|a, b| b["started_ms"].as_u64().cmp(&a["started_ms"].as_u64()));
    json!(v.iter().map(|t| json!({"id": t["id"], "title": t["title"], "source": t["source"], "started_ms": t["started_ms"], "ended_ms": t["ended_ms"], "participants": t["participants"], "segments": t["segments"].as_array().map(|a| a.len()).unwrap_or(0), "summary": t["summary"]})).collect::<Vec<_>>())
}

fn transcript_get(c: &UiCtx, id: &str, query: &str) -> Res {
    if !valid_id(id) {
        return Err(bad("bad transcript id"));
    }
    let b = std::fs::read(transcripts_dir(&c.paths).join(format!("{id}.json"))).map_err(|_| bad(format!("no transcript `{id}`")))?;
    let mut t: Value = serde_json::from_slice(&b).map_err(|e| fail(e.to_string()))?;
    // In-transcript search (OpenClaw meetings reader): keep the matching segments only and
    // say how many matched, so the page can page through hits instead of dumping everything.
    let q = query.trim().to_lowercase();
    if !q.is_empty() {
        let (hits, total): (Vec<Value>, usize) = {
            let segs = t["segments"].as_array().cloned().unwrap_or_default();
            let total = segs.len();
            (segs.into_iter().filter(|s| s.to_string().to_lowercase().contains(&q)).collect(), total)
        };
        t["segments_total"] = json!(total);
        t["matches"] = json!(hits.len());
        t["segments"] = json!(hits);
        t["query"] = json!(query.trim());
    }
    Ok(t)
}

pub fn transcript_markdown(t: &Value) -> String {
    let mut out = format!("# {}\n\n", t["title"].as_str().unwrap_or("Transcript"));
    if let Some(s) = t["summary"].as_str().filter(|s| !s.is_empty()) {
        out.push_str(&format!("## Summary\n\n{s}\n\n"));
    }
    out.push_str("## Transcript\n\n");
    for seg in t["segments"].as_array().into_iter().flatten() {
        out.push_str(&format!("**{}**: {}\n\n", seg["speaker"].as_str().unwrap_or("?"), seg["text"].as_str().unwrap_or("")));
    }
    out
}

/// One JSON object per line (OpenClaw `transcripts.export` jsonl): a meta line, then segments.
pub fn transcript_jsonl(t: &Value) -> String {
    let mut out = json!({
        "kind": "transcript",
        "id": t["id"], "title": t["title"], "source": t["source"],
        "started_ms": t["started_ms"], "ended_ms": t["ended_ms"],
        "participants": t["participants"], "summary": t["summary"],
    })
    .to_string();
    for seg in t["segments"].as_array().into_iter().flatten() {
        out.push('\n');
        out.push_str(&json!({"kind": "segment", "speaker": seg["speaker"], "ts": seg["ts"], "text": seg["text"]}).to_string());
    }
    out
}

fn transcript_export(c: &UiCtx, id: &str, format: &str) -> Res {
    let t = transcript_get(c, id, "")?;
    match format {
        "markdown" | "md" => Ok(json!({"filename": format!("{id}.md"), "type": "text/markdown", "content": transcript_markdown(&t)})),
        "jsonl" => Ok(json!({"filename": format!("{id}.jsonl"), "type": "application/jsonl", "content": transcript_jsonl(&t)})),
        other => Err(bad(format!("unknown transcript export format `{other}` (markdown, jsonl)"))),
    }
}

// ───────────────────────── cloud workers (sandbox environments) ─────────────────────────

fn raw_user_table(c: &UiCtx) -> toml::Table {
    std::fs::read_to_string(c.paths.user_config()).ok().and_then(|t| t.parse().ok()).unwrap_or_default()
}

fn sandbox_root(c: &UiCtx) -> PathBuf {
    raw_user_table(c).get("exec").and_then(|e| e.get("sandbox")).and_then(|s| s.get("workspace_root")).and_then(|v| v.as_str()).filter(|s| !s.is_empty()).map(PathBuf::from).unwrap_or_else(|| c.paths.data.join("sandboxes"))
}

fn dir_size(p: &Path, depth: u32) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    rd.flatten().map(|e| match e.file_type() {
        Ok(t) if t.is_dir() && depth < 6 => dir_size(&e.path(), depth + 1),
        Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
        _ => 0,
    }).sum()
}

/// `[exec.sandbox]` / backend config and the sandbox workspaces that exist.
fn environments(c: &UiCtx) -> Value {
    let t = raw_user_table(c);
    let exec = t.get("exec").cloned().map(|v| serde_json::to_value(v).unwrap_or_default()).unwrap_or(json!({}));
    let root = sandbox_root(c);
    let envs: Vec<Value> = std::fs::read_dir(&root)
        .map(|rd| rd.flatten().filter(|e| e.path().is_dir()).map(|e| {
            let modified = e.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64);
            json!({"id": e.file_name().to_string_lossy(), "bytes": dir_size(&e.path(), 0), "modified_ms": modified})
        }).collect())
        .unwrap_or_default();
    json!({"sandbox": exec.get("sandbox").cloned().unwrap_or(json!({"mode": "off"})), "backends": exec, "root": root.display().to_string(), "environments": envs})
}

fn environment_destroy(c: &UiCtx, id: &str) -> Res {
    if !valid_id(id) {
        return Err(bad("bad environment id"));
    }
    let p = sandbox_root(c).join(id);
    if !p.is_dir() {
        return Err(bad(format!("no environment `{id}`")));
    }
    std::fs::remove_dir_all(&p).map_err(|e| fail(e.to_string()))?;
    Ok(json!({"destroyed": id}))
}

// ───────────────────────── search ─────────────────────────

fn search(c: &UiCtx, query: &str, limit: usize) -> Value {
    let hits = c.k.store.search(query, limit.clamp(1, 200));
    let titles: BTreeMap<String, String> = c.k.store.list().into_iter().map(|s| (s.id, s.title.unwrap_or_default())).collect();
    json!(hits.iter().map(|h| json!({"session": h.session, "title": titles.get(&h.session), "seq": h.seq, "snippet": h.snippet})).collect::<Vec<_>>())
}

/// A web context from the on-disk config with the vault wired in (search status + test).
fn web_ctx(c: &UiCtx, ws: &Path, env: Option<ark_tools::web::http::EnvFn>) -> Result<ark_tools::web::http::WebCtx, String> {
    let cfg = fresh(c, ws).unwrap_or_else(|_| c.k.cfg.clone());
    let web = serde_json::to_value(&cfg).ok().and_then(|v| v.get("web").cloned()).or_else(|| raw_user_table(c).get("web").and_then(|w| serde_json::to_value(w).ok())).unwrap_or(Value::Null);
    let wc = ark_tools::web::WebConfig::from_value(web)?;
    let env = env.unwrap_or_else(|| Arc::new(|k: &str| std::env::var(k).ok()));
    let mut ctx = ark_tools::web::http::WebCtx::new(Arc::new(wc), env);
    let v = c.k.vault.clone();
    ctx.secrets = Arc::new(move |s: &str| v.substitute(s));
    Ok(ctx)
}

/// Web search providers: which one serves `web_search` and which have credentials
/// (OpenClaw `webSearch.status`). `env` overrides process env (tests).
pub fn websearch_status(c: &UiCtx, ws: &Path, env: Option<ark_tools::web::http::EnvFn>) -> Value {
    let ctx = match web_ctx(c, ws, env) {
        Ok(ctx) => ctx,
        Err(e) => return json!({"error": e, "providers": []}),
    };
    let route = ark_tools::web::search::resolve(&ctx);
    json!({
        "pinned": ctx.cfg.search_pin(),
        "route": route.as_ref().map(|r| r.id()).ok(),
        "error": route.err(),
        "providers": ark_tools::web::providers::all().iter().map(|p| json!({"id": p.id(), "label": p.label(), "configured": p.configured(&ctx), "auto_detect": p.auto_detect()})).collect::<Vec<_>>(),
    })
}

/// Run one search through a *keyed* provider (Search page "Test"). The anonymous keyless
/// ring is never exercised: it has no stable backend, and a page must not spend it silently.
/// `run = false` (the default) only reports which provider a test would use, so nothing
/// spends a key by accident.
pub fn websearch_test(c: &UiCtx, ws: &Path, query: &str, env: Option<ark_tools::web::http::EnvFn>, run: bool) -> Res {
    let ctx = match web_ctx(c, ws, env) {
        Ok(ctx) => ctx,
        Err(e) => return Ok(json!({"ok": false, "error": e})),
    };
    let route = match ark_tools::web::search::resolve(&ctx) {
        Ok(r) => r,
        Err(e) => return Ok(json!({"ok": false, "error": e})),
    };
    if route.id() == "keyless" {
        return Ok(json!({"ok": false, "error": "no keyed provider is configured (only the anonymous free tier); add a provider key to test it here"}));
    }
    let provider = route.id().to_string();
    if !run {
        return Ok(json!({"ok": true, "tested": false, "provider": provider}));
    }
    let req = ark_tools::web::search::parse_request(&json!({"query": query, "count": 3}), 3).map_err(bad)?;
    let started = std::time::Instant::now();
    match ark_tools::web::search::run(&ctx, &route, &req) {
        Ok(o) => {
            let rendered = ark_tools::web::search::render(&o, query, started.elapsed());
            Ok(json!({"ok": true, "tested": true, "provider": o.provider, "cached": o.cached, "took_ms": started.elapsed().as_millis() as u64, "count": rendered["count"], "results": rendered["results"], "notes": o.notes}))
        }
        Err((code, e)) => Ok(json!({"ok": false, "tested": true, "provider": provider, "error": e, "code": code})),
    }
}

// ───────────────────────── systems / custodian / labs / about / profile ─────────────────────────

fn systems(c: &UiCtx) -> Value {
    let cfg = Config::load(Some(&c.paths.user_config()), None, &[]).unwrap_or_else(|_| c.k.cfg.clone());
    let bdir = crate::ops::backup::default_dir(&c.paths, &cfg.backup);
    let backups: Vec<Value> = crate::ops::backup::list(&bdir).into_iter().map(|(p, ts, size)| json!({"path": p.display().to_string(), "ts": ts, "bytes": size})).collect();
    let snapshots: Vec<Value> = crate::ops::backup::snapshot_list(&c.paths).into_iter().map(|(id, ts, label)| json!({"id": id, "ts": ts, "label": label})).collect();
    let now = (ark_kernel::event::now_ms() / 1000) as i64;
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "pid": std::process::id(),
        "paths": {"config": c.paths.config_dir.display().to_string(), "data": c.paths.data.display().to_string(), "runtime": c.paths.runtime.display().to_string()},
        "data_bytes": dir_size(&c.paths.data, 0),
        "sessions": c.k.store.list().len(),
        "backups": backups,
        "backup_dir": bdir.display().to_string(),
        "snapshots": snapshots,
        "service": crate::ops::service::audit(&c.ws).iter().map(|i| json!({"code": i.code, "message": i.message, "fix": i.fix})).collect::<Vec<_>>(),
        "recent_starts": crate::ops::service::recent_starts(&c.paths, now),
    })
}

/// Things that need attention (OpenClaw custodian alerts): failing cron jobs, restart
/// storms, recent errors in the daemon log, secrets the config references but the vault lacks.
pub fn custodian(c: &UiCtx) -> Value {
    let mut alerts: Vec<Value> = vec![];
    let jobs: Vec<ark_kernel::automation::Job> = ark_kernel::automation::read_list(&ark_kernel::automation::jobs_path(&c.paths.data)).unwrap_or_default();
    for j in jobs.iter().filter(|j| j.enabled) {
        if let Some(r) = j.last_result.as_deref().filter(|r| r.to_lowercase().starts_with("error") || r.to_lowercase().contains("failed")) {
            alerts.push(json!({"id": format!("cron:{}", j.id), "severity": "warn", "title": format!("Cron job {} failed", j.id), "detail": r, "session": j.last_session, "since": j.last_run}));
        }
    }
    let now = (ark_kernel::event::now_ms() / 1000) as i64;
    let starts = crate::ops::service::recent_starts(&c.paths, now);
    if starts.len() >= 5 {
        alerts.push(json!({"id": "restart-storm", "severity": "error", "title": format!("arkd restarted {} times recently", starts.len()), "detail": "Check `ark logs --level error` and `ark service audit`.", "since": starts.first()}));
    }
    let log = crate::ops::logs::dir(&c.paths).join("ark.jsonl");
    let day_ago = ark_kernel::event::now_ms().saturating_sub(86_400_000);
    let errors: Vec<Value> = std::fs::read_to_string(&log)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r["level"] == "error" && r["ts"].as_u64().unwrap_or(0) >= day_ago)
        .collect();
    if !errors.is_empty() {
        let last = errors.last().cloned().unwrap_or_default();
        alerts.push(json!({"id": "log-errors", "severity": "warn", "title": format!("{} error(s) in the last 24h", errors.len()), "detail": last["msg"], "session": last["session"], "since": errors[0]["ts"]}));
    }
    if let Ok(v) = secrets_list(c) {
        for m in v["missing"].as_array().into_iter().flatten() {
            alerts.push(json!({"id": format!("secret:{}", m.as_str().unwrap_or("")), "severity": "error", "title": format!("Secret {} is referenced but not set", m.as_str().unwrap_or("")), "detail": "Set it on the Secrets page or with `ark secrets set`."}));
        }
    }
    json!({"alerts": alerts})
}

/// Experimental switches (OpenClaw Labs registry): id, config gate, what it does.
pub const LABS: &[(&str, &str, &str, &str)] = &[
    ("learn", "learn.enabled", "Learning loop", "Let the agent write skills and memories from finished work."),
    ("tool-search", "tools.tool_search.enabled", "Tool search", "Hide rarely used tool schemas behind BM25 tool search."),
    ("trajectories", "trajectory.save", "Save trajectories", "Write every finished session as a ShareGPT trajectory for training/evals."),
    ("checkpoints", "checkpoint.enabled", "Workspace checkpoints", "Snapshot workspace files before edits so /undo can restore them."),
];

fn labs(c: &UiCtx, ws: &Path) -> Value {
    let cfg = fresh(c, ws).unwrap_or_else(|_| c.k.cfg.clone());
    let t = crate::ops::confcli::to_table(&cfg);
    json!(LABS.iter().map(|(id, key, title, desc)| json!({"id": id, "key": key, "title": title, "description": desc, "enabled": crate::ops::confcli::get_in(&t, key).and_then(|v| v.as_bool()).unwrap_or(false)})).collect::<Vec<_>>())
}

fn labs_set(c: &UiCtx, id: &str, on: bool) -> Res {
    let (_, key, ..) = LABS.iter().find(|l| l.0 == id).ok_or_else(|| bad(format!("no lab `{id}`")))?;
    crate::ops::confcli::set(&c.paths, key, if on { "true" } else { "false" }).map(|m| json!({"id": id, "enabled": on, "message": m})).map_err(fail)
}

fn about(c: &UiCtx) -> Value {
    json!({
        "name": "ark",
        "version": env!("CARGO_PKG_VERSION"),
        "target": crate::ops::update::target(),
        "license": "MIT",
        "profile": crate::ops::profile::current(),
        "upstreams": [
            {"name": "OpenClaw", "license": "MIT", "url": "https://github.com/openclaw/openclaw"},
            {"name": "Hermes Agent", "license": "MIT", "url": "https://github.com/NousResearch/hermes-agent"},
        ],
        "update_channel": c.k.cfg.update.channel,
    })
}

fn profile_file(c: &UiCtx) -> PathBuf {
    c.paths.data.join("ui/profile.json")
}

fn profile(c: &UiCtx) -> Value {
    let me: Value = std::fs::read(profile_file(c)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(json!({}));
    json!({
        "profile": crate::ops::profile::current(),
        "profiles": crate::ops::profile::list(),
        "display_name": me["display_name"],
        "avatar": me["avatar"],
        "model": c.k.cfg.model.default,
    })
}

/// Display name (≤ 64 chars) and avatar (a `data:image/…` URL ≤ 256 KiB) for this UI.
fn profile_set(c: &UiCtx, p: &Value) -> Res {
    let mut me: Value = std::fs::read(profile_file(c)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(json!({}));
    if let Some(n) = p["display_name"].as_str() {
        if n.chars().count() > 64 || n.chars().any(char::is_control) {
            return Err(bad("display name must be at most 64 printable characters"));
        }
        me["display_name"] = json!(n.trim());
    }
    if let Some(a) = p["avatar"].as_str() {
        if !a.is_empty() && !(a.starts_with("data:image/png;base64,") || a.starts_with("data:image/jpeg;base64,") || a.starts_with("data:image/webp;base64,")) {
            return Err(bad("avatar must be a PNG, JPEG or WebP data URL"));
        }
        if a.len() > 256 * 1024 {
            return Err(bad("avatar is larger than 256 KiB"));
        }
        me["avatar"] = json!(a);
    }
    let f = profile_file(c);
    std::fs::create_dir_all(f.parent().unwrap()).map_err(|e| fail(e.to_string()))?;
    ark_kernel::util::atomic_write(&f, me.to_string().as_bytes()).map_err(|e| fail(e.to_string()))?;
    Ok(me)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::kit;

    fn ctx(t: &crate::testkit::Kit) -> UiCtx {
        UiCtx { paths: t.paths.clone(), k: t.k.clone(), ws: t.ws.clone(), live: Live::default(), terms: Default::default() }
    }
    fn ok(c: &UiCtx, m: &str, p: Value) -> Value {
        call(c, m, &p).unwrap_or_else(|| panic!("{m} not handled")).unwrap_or_else(|e| panic!("{m}: {e:?}"))
    }
    fn err(c: &UiCtx, m: &str, p: Value) -> String {
        call(c, m, &p).unwrap().unwrap_err().1
    }

    #[test]
    fn every_listed_method_is_served() {
        let t = kit();
        let c = ctx(&t);
        for m in METHODS.iter().filter(|m| m.starts_with("ui.")) {
            assert!(call(&c, m, &json!({})).is_some(), "{m} is listed but not handled");
        }
        assert!(call(&c, "ui.nope", &json!({})).is_none());
        let pages = ok(&c, "ui.pages", json!({}));
        assert!(pages.as_array().unwrap().iter().any(|p| p["id"] == "workboard"));
    }

    #[test]
    fn config_page_redacts_and_refuses_placeholders() {
        let t = kit();
        let c = ctx(&t);
        std::fs::write(t.paths.user_config(), "[model]\ndefault = \"echo/m\"\n[providers.x]\napi_key = \"sk-live-123456\"\n").unwrap();
        let g = ok(&c, "ui.config.get", json!({}));
        let text = g["text"].as_str().unwrap();
        assert!(!text.contains("sk-live-123456") && text.contains("\"***\"") && g["redacted"] == true, "{text}");
        assert!(g["schema"]["properties"]["model"].is_object());
        assert!(err(&c, "ui.config.save", json!({"text": text})).contains("redacted"));
        ok(&c, "ui.config.set", json!({"key": "model.default", "value": "\"echo/other\""}));
        assert!(std::fs::read_to_string(t.paths.user_config()).unwrap().contains("echo/other"));
        assert!(err(&c, "ui.config.save", json!({"text": "[model\n"})).contains("invalid"));
        ok(&c, "ui.config.save", json!({"text": "[model]\ndefault = \"echo/third\"\n"}));
        let backups = ok(&c, "ui.config.backups", json!({}));
        assert!(!backups.as_array().unwrap().is_empty());
        // Restore an older version (config page "previous versions"); unknown paths are refused.
        let old = backups[0].as_str().unwrap().to_string();
        let r = ok(&c, "ui.config.restore", json!({"path": old}));
        assert!(r["restored"].as_str().unwrap().contains("config.toml."));
        assert!(std::fs::read_to_string(t.paths.user_config()).unwrap().contains("[model]"));
        assert!(err(&c, "ui.config.restore", json!({"path": "/etc/passwd"})).contains("no config backup"));
        assert!(err(&c, "ui.config.restore", json!({})).contains("path is required"));
    }

    #[test]
    fn secrets_page_never_returns_values() {
        let t = kit();
        let c = ctx(&t);
        std::fs::write(t.paths.user_config(), "[app]\ntoken = \"{{secret:APP_TOKEN}}\"\n").unwrap();
        let l = ok(&c, "ui.secrets.list", json!({}));
        assert_eq!(l["missing"], json!(["APP_TOKEN"]));
        ok(&c, "ui.secrets.set", json!({"name": "APP_TOKEN", "value": "hunter2-value"}));
        let l = ok(&c, "ui.secrets.list", json!({}));
        assert!(!l.to_string().contains("hunter2-value"));
        assert_eq!(l["secrets"][0], json!({"name": "APP_TOKEN", "referenced": true}));
        assert!(err(&c, "ui.secrets.set", json!({"name": "bad name", "value": "x"})).contains("names"));
        assert_eq!(ok(&c, "ui.secrets.delete", json!({"name": "APP_TOKEN"}))["removed"], true);
        // Custodian notices the missing reference.
        assert!(custodian(&c)["alerts"].to_string().contains("APP_TOKEN"));
    }

    #[test]
    fn channels_page_lists_policy_and_edits_safe_keys() {
        let t = kit();
        let c = ctx(&t);
        std::fs::write(t.paths.user_config(), "[channels.tg]\nkind = \"telegram\"\ntoken = \"{{secret:TG}}\"\nallow = [\"42\"]\n").unwrap();
        let v = ok(&c, "ui.channels", json!({}));
        let ch = &v["channels"][0];
        assert_eq!((ch["name"].as_str(), ch["kind"].as_str(), ch["running"].as_bool()), (Some("tg"), Some("telegram"), Some(false)));
        assert_eq!(ch["allow"], json!(["42"]));
        assert!(!v.to_string().contains("secret:TG"));
        assert!(err(&c, "ui.channels.set", json!({"name": "tg", "key": "token", "value": "\"x\""})).contains("not editable"));
        ok(&c, "ui.channels.set", json!({"name": "tg", "key": "dm_policy", "value": "\"allowlist\""}));
        assert_eq!(ok(&c, "ui.channels", json!({}))["channels"][0]["dm_policy"], "allowlist");
    }

    #[test]
    fn skills_and_workshop() {
        let t = kit();
        let c = ctx(&t);
        let ws = t.ws.join(".ark/skills/proj");
        std::fs::create_dir_all(&ws).unwrap();
        std::fs::write(ws.join("SKILL.md"), "---\nname: proj\ndescription: project skill\n---\nbody\n").unwrap();
        assert!(err(&c, "ui.skills.workshop.save", json!({"name": "proj", "description": "d", "body": "x"})).contains("already exists"));
        assert!(err(&c, "ui.skills.workshop.save", json!({"name": "Bad Name", "description": "d"})).contains("lowercase"));
        ok(&c, "ui.skills.workshop.save", json!({"name": "notes", "description": "Take notes: \"quoted\"", "body": "# Notes\nDo it."}));
        let list = ok(&c, "ui.skills.list", json!({}));
        let names: Vec<&str> = list.as_array().unwrap().iter().filter_map(|s| s["name"].as_str()).collect();
        assert!(names.contains(&"proj") && names.contains(&"notes"), "{names:?}");
        let g = ok(&c, "ui.skills.get", json!({"name": "notes"}));
        assert_eq!(g["description"], "Take notes: \"quoted\"");
        assert!(g["body"].as_str().unwrap().contains("Do it.") && g["editable"] == true);
        ok(&c, "ui.skills.toggle", json!({"name": "notes", "enabled": false}));
        let list = ok(&c, "ui.skills.list", json!({}));
        assert_eq!(list.as_array().unwrap().iter().find(|s| s["name"] == "notes").unwrap()["enabled"], false);
        ok(&c, "ui.skills.toggle", json!({"name": "notes", "enabled": true}));
        assert_eq!(ok(&c, "ui.skills.workshop.list", json!({})).as_array().unwrap().len(), 1);
        ok(&c, "ui.skills.workshop.delete", json!({"name": "notes"}));
        assert!(ok(&c, "ui.skills.workshop.list", json!({})).as_array().unwrap().is_empty());
        // Archived drafts stay restorable (skill-workshop archive tab → restore).
        let arch = ok(&c, "ui.skills.workshop.archived", json!({}));
        assert_eq!((arch.as_array().unwrap().len(), arch[0]["name"].as_str()), (1, Some("notes")));
        assert!(err(&c, "ui.skills.workshop.restore", json!({"name": "nope"})).contains("no archived skill"));
        ok(&c, "ui.skills.workshop.restore", json!({"name": "notes"}));
        assert_eq!(ok(&c, "ui.skills.workshop.list", json!({})).as_array().unwrap().len(), 1);
        assert!(ok(&c, "ui.skills.workshop.archived", json!({})).as_array().unwrap().is_empty());
        assert!(err(&c, "ui.skills.workshop.restore", json!({"name": "notes"})).contains("already exists"));
    }

    /// The `workspace` request parameter is client-supplied: `agent_file` (AGENTS.md) and
    /// `workshop_save` (SKILL.md) may only run for a directory inside a configured workspace,
    /// so `{"workspace": "/etc"}` — or `..`, or a symlink out — reads and writes nothing.
    #[test]
    fn workspace_parameter_is_confined_to_configured_workspaces() {
        let t = kit();
        let c = ctx(&t);
        // The configured workspace, and a directory inside it, are accepted.
        let sub = t.ws.join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        ok(&c, "ui.agents.file.set", json!({"workspace": t.ws.display().to_string(), "name": "AGENTS.md", "content": "# agents\n"}));
        assert!(t.ws.join("AGENTS.md").is_file());
        ok(&c, "ui.agents.file.set", json!({"workspace": sub.display().to_string(), "name": "AGENTS.md", "content": "sub\n"}));
        assert!(sub.join("AGENTS.md").is_file());
        assert_eq!(ok(&c, "ui.agents.file.get", json!({"workspace": sub.display().to_string(), "name": "AGENTS.md"}))["content"], "sub\n");
        // `/etc`, a `..` climb and a symlink out of the workspace are refused for both methods.
        let outside = std::env::temp_dir().join(format!("ark-ui-ws-{}", ark_kernel::util::random_hex(8)));
        std::fs::create_dir_all(&outside).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, t.ws.join("escape")).unwrap();
        let escapes = [
            "/etc".to_string(),
            t.ws.join("..").display().to_string(),
            t.ws.join("../..").display().to_string(),
            t.ws.join("escape").display().to_string(),
            outside.display().to_string(),
        ];
        for w in &escapes {
            for (m, p) in [
                ("ui.agents.file.set", json!({"workspace": w, "name": "AGENTS.md", "content": "pwned"})),
                ("ui.agents.file.get", json!({"workspace": w, "name": "AGENTS.md"})),
                ("ui.skills.workshop.save", json!({"workspace": w, "name": "pwned", "description": "d", "body": "x"})),
            ] {
                let e = err(&c, m, p);
                assert!(e.contains("outside the configured workspace"), "{m} {w}: {e}");
            }
        }
        assert!(!outside.join("AGENTS.md").exists(), "nothing was written through a symlink");
        assert!(!t.ws.parent().unwrap().join("AGENTS.md").exists(), "nothing was written beside the workspace");
        assert_eq!(std::fs::read_to_string(t.ws.join("AGENTS.md")).unwrap(), "# agents\n", "the allowed file is untouched");
        assert!(!c.paths.data.join("skills/pwned").exists(), "no skill was created");
        // A `trusted_projects` entry is a configured workspace too.
        let trusted = std::env::temp_dir().join(format!("ark-ui-trusted-{}", ark_kernel::util::random_hex(8)));
        std::fs::create_dir_all(&trusted).unwrap();
        let t2 = crate::testkit::kit_with(|cfg| cfg.trusted_projects = vec![trusted.display().to_string()]);
        ok(&ctx(&t2), "ui.agents.file.set", json!({"workspace": trusted.display().to_string(), "name": "AGENTS.md", "content": "trusted\n"}));
        assert!(trusted.join("AGENTS.md").is_file());
    }

    #[test]
    fn cron_page_adds_toggles_and_removes() {
        let t = kit();
        let c = ctx(&t);
        assert!(err(&c, "ui.cron.add", json!({"cron": "nope", "prompt": "x"})).contains("cron"));
        let j = ok(&c, "ui.cron.add", json!({"cron": "0 9 * * *", "prompt": "daily summary"}));
        let id = j["id"].as_str().unwrap().to_string();
        assert_eq!(ok(&c, "ui.cron.enable", json!({"id": id, "enabled": false}))["updated"], true);
        let jobs: Vec<ark_kernel::automation::Job> = ark_kernel::automation::read_list(&ark_kernel::automation::jobs_path(&t.paths.data)).unwrap();
        assert!(!jobs[0].enabled);
        assert!(err(&c, "ui.cron.run", json!({"id": "missing"})).contains("no job"));
        // Edit in place (cron.update): a new expression recomputes `next_run`.
        let u = ok(&c, "ui.cron.update", json!({"id": id, "cron": "*/5 * * * *", "prompt": "every five", "model": "echo/m", "enabled": true}));
        assert_eq!((u["job"]["cron"].as_str(), u["job"]["prompt"].as_str(), u["job"]["model"].as_str()), (Some("*/5 * * * *"), Some("every five"), Some("echo/m")));
        assert!(u["job"]["next_run"].as_i64().unwrap() > ark_kernel::util::unix_now());
        assert!(err(&c, "ui.cron.update", json!({"id": id, "cron": "nope"})).contains("cron"));
        assert!(err(&c, "ui.cron.update", json!({"id": "missing", "prompt": "x"})).contains("no job"));
        assert_eq!(ok(&c, "ui.cron.remove", json!({"id": id}))["removed"], true);
    }

    #[test]
    fn usage_rolls_up_models_days_and_sessions() {
        let t = kit();
        let c = ctx(&t);
        let id = t.k.create_session(&t.ws, None, None, None).unwrap();
        t.k.submit(&id, "hi", "test").unwrap();
        t.k.run(&id, Default::default()).unwrap();
        let u = ok(&c, "ui.usage", json!({"days": 7}));
        assert_eq!(u["models"][0]["model"], "echo/m");
        assert_eq!(u["models"][0]["input"], 50);
        assert_eq!(u["daily"][0]["day"], day_of(ark_kernel::event::now_ms()));
        assert_eq!(u["top_sessions"][0]["id"], id.as_str());
        let models = ok(&c, "ui.usage.export", json!({"days": 7}));
        let csv = models["content"].as_str().unwrap();
        assert_eq!((models["filename"].as_str(), models["type"].as_str()), (Some("ark-usage-models.csv"), Some("text/csv")));
        assert!(csv.starts_with("model,calls") && csv.contains("echo/m,1,50,10"), "{csv}");
        // Export menu: daily CSV, sessions CSV and the whole rollup as JSON.
        let daily = ok(&c, "ui.usage.export", json!({"days": 7, "format": "daily-csv"}));
        let d = daily["content"].as_str().unwrap();
        assert!(d.starts_with("day,input_tokens,output_tokens,calls\n") && d.contains(",50,10,1"), "{d}");
        let sessions = ok(&c, "ui.usage.export", json!({"days": 7, "format": "sessions-csv"}));
        assert!(sessions["content"].as_str().unwrap().contains(&format!("{id},,60")), "{}", sessions["content"]);
        let whole = ok(&c, "ui.usage.export", json!({"days": 7, "format": "json"}));
        assert_eq!((whole["type"].as_str(), whole["filename"].as_str()), (Some("application/json"), Some("ark-usage.json")));
        assert!(serde_json::from_str::<Value>(whole["content"].as_str().unwrap()).unwrap()["models"].is_array());
        assert!(err(&c, "ui.usage.export", json!({"format": "xlsx"})).contains("unknown usage export format"));
        assert_eq!(day_of(0), "1970-01-01");
        assert_eq!(day_of(951_782_400_000), "2000-02-29");
        // Search finds the conversation.
        let s = ok(&c, "ui.search", json!({"query": "hi"}));
        assert_eq!(s[0]["session"], id.as_str());
    }

    #[test]
    fn agents_files_meetings_and_profile() {
        let t = kit();
        let c = ctx(&t);
        assert!(err(&c, "ui.agents.file.set", json!({"name": "../x.md", "content": "x"})).contains("only"));
        ok(&c, "ui.agents.file.set", json!({"name": "SOUL.md", "content": "be kind"}));
        assert_eq!(ok(&c, "ui.agents.file.get", json!({"name": "SOUL.md"}))["content"], "be kind");
        let a = ok(&c, "ui.agents", json!({}));
        assert!(a["files"].as_array().unwrap().iter().any(|f| f["name"] == "SOUL.md" && f["exists"] == true));
        // Meetings.
        let d = transcripts_dir(&t.paths);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("m1.json"), json!({"id": "m1", "title": "Standup", "started_ms": 5, "summary": "ship it", "segments": [{"speaker": "Ann", "text": "hello"}]}).to_string()).unwrap();
        let l = ok(&c, "ui.transcripts.list", json!({"query": "standup"}));
        assert_eq!((l[0]["id"].as_str(), l[0]["segments"].as_u64()), (Some("m1"), Some(1)));
        assert!(ok(&c, "ui.transcripts.list", json!({"query": "zzz"})).as_array().unwrap().is_empty());
        let md = ok(&c, "ui.transcripts.export", json!({"id": "m1"}))["content"].as_str().unwrap().to_string();
        assert!(md.contains("# Standup") && md.contains("**Ann**: hello") && md.contains("ship it"));
        // In-transcript search keeps the hits and counts them (meetings reader).
        let hit = ok(&c, "ui.transcripts.get", json!({"id": "m1", "query": "HELLO"}));
        assert_eq!((hit["matches"].as_u64(), hit["segments_total"].as_u64()), (Some(1), Some(1)));
        assert!(ok(&c, "ui.transcripts.get", json!({"id": "m1", "query": "zzz"}))["segments"].as_array().unwrap().is_empty());
        let jsonl = ok(&c, "ui.transcripts.export", json!({"id": "m1", "format": "jsonl"}));
        assert_eq!(jsonl["filename"], "m1.jsonl");
        let lines: Vec<&str> = jsonl["content"].as_str().unwrap().lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(serde_json::from_str::<Value>(lines[1]).unwrap()["speaker"], "Ann");
        assert!(err(&c, "ui.transcripts.export", json!({"id": "m1", "format": "docx"})).contains("unknown transcript export format"));
        assert!(err(&c, "ui.transcripts.get", json!({"id": "../etc"})).contains("bad"));
        // Profile.
        assert!(err(&c, "ui.profile.set", json!({"avatar": "javascript:alert(1)"})).contains("data URL"));
        ok(&c, "ui.profile.set", json!({"display_name": "Noob", "avatar": "data:image/png;base64,AAAA"}));
        let p = ok(&c, "ui.profile", json!({}));
        assert_eq!((p["display_name"].as_str(), p["profile"].is_string()), (Some("Noob"), true));
        assert_eq!(ok(&c, "ui.about", json!({}))["version"], env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn environments_labs_systems_and_apps() {
        let t = kit();
        let c = ctx(&t);
        let root = t.paths.data.join("sandboxes/sess-1");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("f"), "12345").unwrap();
        let e = ok(&c, "ui.environments", json!({}));
        assert_eq!((e["environments"][0]["id"].as_str(), e["environments"][0]["bytes"].as_u64()), (Some("sess-1"), Some(5)));
        assert!(err(&c, "ui.environments.destroy", json!({"id": ".."})).contains("bad"));
        ok(&c, "ui.environments.destroy", json!({"id": "sess-1"}));
        assert!(!root.exists());
        let l = ok(&c, "ui.labs", json!({}));
        assert!(l.as_array().unwrap().iter().any(|x| x["id"] == "learn"));
        ok(&c, "ui.labs.set", json!({"id": "tool-search", "enabled": true}));
        assert!(ok(&c, "ui.labs", json!({})).as_array().unwrap().iter().any(|x| x["id"] == "tool-search" && x["enabled"] == true));
        assert!(err(&c, "ui.labs.set", json!({"id": "nope"})).contains("no lab"));
        let s = ok(&c, "ui.systems", json!({}));
        assert_eq!(s["version"], env!("CARGO_PKG_VERSION"));
        assert!(s["service"].as_array().unwrap().iter().all(|i| i["code"].is_string() && i["message"].is_string()));
        let b = ok(&c, "ui.systems.backup", json!({}));
        assert!(std::path::Path::new(b["path"].as_str().unwrap()).is_file(), "{b}");
        let docs = t.paths.data.join("surfaces/canvas/documents/cv_1");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("manifest.json"), r#"{"title":"Plan","localEntrypoint":"index.html","createdAt":"2026"}"#).unwrap();
        let a = ok(&c, "ui.apps", json!({}));
        assert_eq!(a["canvas"][0]["url"], "/surfaces/canvas/documents/cv_1/index.html");
        assert!(ok(&c, "ui.lobsterdex", json!({}))["workflows"].as_array().unwrap().is_empty());
        assert!(ok(&c, "ui.memory.plan", json!({}))["providers"].is_array());
        let w = websearch_status(&c, &t.ws, Some(Arc::new(|k: &str| (k == "BRAVE_API_KEY").then(|| "bk".to_string()))));
        assert!(w["providers"].as_array().unwrap().iter().any(|p| p["id"] == "brave" && p["configured"] == true), "{w}");
        assert_eq!(w["route"], "brave");
    }

    #[test]
    fn terminal_page_is_gated_by_app_terminal() {
        let t = kit();
        let c = ctx(&t);
        assert_eq!(ok(&c, "ui.terminal.status", json!({}))["enabled"], false);
        assert!(err(&c, "ui.terminal.open", json!({})).contains("[app] terminal = true"));
        std::fs::write(t.paths.user_config(), "[app]\nterminal = true\n").unwrap();
        assert!(terminal_enabled(&c));
        // A client may only name an allowlisted program (a path is refused, see ui_term tests).
        assert!(err(&c, "ui.terminal.open", json!({"shell": "/bin/sh"})).contains("refusing"));
        let id = ok(&c, "ui.terminal.open", json!({"shell": "sh"}))["id"].as_str().unwrap().to_string();
        ok(&c, "ui.terminal.close", json!({"id": id}));
    }

    #[test]
    fn worktrees_page_lists_repo_worktrees() {
        let t = kit();
        let c = ctx(&t);
        assert!(err(&c, "ui.worktrees.list", json!({})).contains("not inside a git repository"));
        let git = |args: &[&str]| assert!(std::process::Command::new("git").args(args).current_dir(&t.ws).output().unwrap().status.success());
        git(&["init", "-q"]);
        std::fs::write(t.ws.join("a"), "1").unwrap();
        git(&["add", "."]);
        git(&["-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "i"]);
        let l = ok(&c, "ui.worktrees.list", json!({}));
        assert_eq!(l.as_array().unwrap().len(), 1);
        assert!(ok(&c, "ui.worktrees.prune", json!({"dry_run": true}))["pruned"].as_array().unwrap().is_empty());
        // Create on a new `ark/<name>` branch, then remove it again.
        let made = ok(&c, "ui.worktrees.create", json!({"name": "feature"}));
        assert_eq!((made["branch"].as_str(), made["repo_root"].is_string()), (Some("ark/feature"), true));
        assert_eq!(ok(&c, "ui.worktrees.list", json!({})).as_array().unwrap().len(), 2);
        assert!(err(&c, "ui.worktrees.create", json!({"name": "feature"})).contains("already exists"));
        assert!(err(&c, "ui.worktrees.create", json!({"name": "../x"})).contains("bad worktree name"));
        ok(&c, "ui.worktrees.remove", json!({"name": "feature"}));
        assert_eq!(ok(&c, "ui.worktrees.list", json!({})).as_array().unwrap().len(), 1);
    }

    #[test]
    fn memory_import_shows_targets_and_applies_a_source() {
        let t = kit();
        let c = ctx(&t);
        let root = t.paths.data.join("fake-openclaw");
        std::fs::create_dir_all(root.join("workspace/memory")).unwrap();
        std::fs::write(root.join("workspace/MEMORY.md"), "- likes tea\n").unwrap();
        std::fs::write(root.join("workspace/memory/2026-01-01.md"), "met Bob").unwrap();
        let plan = ok(&c, "ui.memory.plan", json!({"provider": "openclaw", "path": root.display().to_string()}));
        assert!(plan["dest"].as_str().unwrap().ends_with("memory"));
        let items = plan["providers"][0]["items"].as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|i| i["existing"] == false && i["target"].as_str().unwrap().ends_with(i["file"].as_str().unwrap())));
        // Import everything this source holds; the entries land in `<data>/memory/<file>`.
        let r = ok(&c, "ui.memory.apply", json!({"provider": "openclaw", "path": root.display().to_string(), "replace": false}));
        assert_eq!(r["imported"], 2, "{r}");
        assert!(std::fs::read_to_string(t.paths.data.join("memory/MEMORY.md")).unwrap().contains("likes tea"));
        // The plan now marks them as already imported, and a second apply imports nothing new.
        let again = ok(&c, "ui.memory.plan", json!({"provider": "openclaw", "path": root.display().to_string()}));
        assert!(again["providers"][0]["items"].as_array().unwrap().iter().all(|i| i["existing"] == true), "{again}");
        assert_eq!(ok(&c, "ui.memory.apply", json!({"provider": "openclaw", "path": root.display().to_string()}))["imported"], 2);
        assert!(err(&c, "ui.memory.apply", json!({"provider": "nope"})).contains("was not found"));
        // A message with no selects is refused rather than importing everything silently.
        assert!(err(&c, "ui.memory.apply", json!({"provider": "openclaw", "path": root.display().to_string(), "items": []})).contains("nothing selected"));
    }

    #[test]
    fn search_page_pins_a_provider_and_tests_offline_safely() {
        let t = kit();
        let c = ctx(&t);
        let none: ark_tools::web::http::EnvFn = Arc::new(|_: &str| None);
        let w = websearch_status(&c, &t.ws, Some(none.clone()));
        assert!(w["providers"].as_array().unwrap().len() >= 3);
        // "Test" never spends the anonymous keyless ring and never makes a call without a key.
        let r = websearch_test(&c, &t.ws, "ark", Some(none.clone()), true).unwrap();
        assert_eq!(r["ok"], false);
        let e = r["error"].as_str().unwrap();
        assert!(e.contains("provider") || e.contains("free tier"), "{r}");
        // Without `run` it only reports the route, so nothing spends a key by accident.
        let dry = websearch_test(&c, &t.ws, "ark", Some(none.clone()), false).unwrap();
        assert!(dry["tested"] != true, "{dry}");
        // Pinning a provider writes `web.search.provider`; an empty value unsets it.
        ok(&c, "ui.websearch.set", json!({"provider": "brave"}));
        let text = std::fs::read_to_string(t.paths.user_config()).unwrap();
        assert!(text.contains("\"brave\""), "{text}");
        assert_eq!(ok(&c, "ui.websearch.status", json!({}))["pinned"], "brave");
        ok(&c, "ui.websearch.set", json!({"provider": ""}));
        assert!(!std::fs::read_to_string(t.paths.user_config()).unwrap().contains("brave"));
    }

    #[test]
    fn lobsterdex_lists_workflows_and_their_errors() {
        let t = kit();
        let c = ctx(&t);
        std::fs::write(t.ws.join("plan.lobster"), "# nightly\n    exec echo hi | exec wc -l\n").unwrap();
        std::fs::write(t.ws.join("bad.lobster"), "| nope\n").unwrap();
        std::fs::write(t.ws.join("notes.txt"), "not a pipeline").unwrap();
        let l = ok(&c, "ui.lobsterdex", json!({}));
        let wfs = l["workflows"].as_array().unwrap();
        assert_eq!(wfs.len(), 2);
        let good = wfs.iter().find(|w| w["name"] == "plan").unwrap();
        assert_eq!((good["stages"].as_u64(), good["description"].as_str()), (Some(2), Some("nightly")));
        let bad = wfs.iter().find(|w| w["name"] == "bad").unwrap();
        assert!(bad["stages"].is_null() && bad["error"].as_str().unwrap().contains("empty pipeline stage"));
        assert!(l["paused"].as_array().unwrap().is_empty());
    }

    /// Every ARP method name `pages.js` passes to `call(…)` (quoted), in first-use order.
    fn called_methods(js: &str) -> Vec<String> {
        let mut out: Vec<String> = vec![];
        for (i, _) in js.match_indices("call('") {
            let rest = &js[i + 6..];
            let name: String = rest.chars().take_while(|c| *c != '\'' && !c.is_whitespace()).collect();
            if name.contains('.') && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_') && !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }

    /// Mechanical guard for the Control UI rows: every method `pages.js` calls is served —
    /// `ui.*` by this module (`METHODS` + `call()`), `kanban.*` by the kernel's kanban
    /// handler, everything else by the daemon or the app server's host methods — and every
    /// page in `PAGES` exists in `pages.js` (same count, same ids).
    #[test]
    fn pages_js_calls_only_served_methods() {
        const JS: &str = include_str!("../../../../ui/web/pages.js");
        let called = called_methods(JS);
        let ui: Vec<String> = called.iter().filter(|m| m.starts_with("ui.")).cloned().collect();
        assert!(ui.len() >= 40, "scanner found only {} ui.* methods: {ui:?}", ui.len());
        // Pages may also lean on the sibling registries the daemon serves next to this one
        // (`ops::webui` for model providers / devices / plugins / logs, `ops::dock`); each keeps
        // its own dispatch test. Everything else must be dispatched right here.
        let sibling = |m: &str| crate::ops::webui::METHODS.contains(&m) || crate::ops::dock::METHODS.contains(&m);
        let unlisted: Vec<&String> = ui.iter().filter(|m| !METHODS.contains(&m.as_str()) && !sibling(m)).collect();
        assert!(unlisted.is_empty(), "pages.js calls ui.* methods no module serves: {unlisted:?}");
        assert!(METHODS.iter().all(|m| !crate::ops::webui::METHODS.contains(m)), "a method is registered twice (ui_methods + webui)");
        let t = kit();
        let c = ctx(&t);
        for m in ui.iter().filter(|m| !sibling(m)) {
            assert!(call(&c, m, &json!({})).is_some(), "pages.js calls `{m}`, which `call()` does not dispatch");
        }
        for m in called.iter().filter(|m| !m.starts_with("ui.")) {
            let served = if m.starts_with("kanban.") {
                ark_kernel::kanban::methods::NAMES.contains(&m.as_str())
            } else {
                // `cluster.*` / `ha.*` / `workers.*` are the daemon's own (ark_kernel::cluster, ent-062).
                ark_kernel::daemon::Daemon::METHODS.contains(&m.as_str()) || crate::HOST_METHODS.contains(&m.as_str()) || ark_kernel::cluster::METHODS.contains(&m.as_str())
            };
            assert!(served, "pages.js calls `{m}`, which the app server does not serve/advertise");
        }
        // Page index ⇄ pages.js, both directions.
        for (id, ..) in PAGES {
            assert!(JS.contains(&format!("  {id}: {{")) || JS.contains(&format!("  '{id}': {{")), "page `{id}` is missing from pages.js");
        }
        assert_eq!(JS.matches(": { title:").count(), PAGES.len(), "pages.js and PAGES disagree on the page list");
        assert!(ui.iter().any(|m| m == "ui.terminal.read") && ui.iter().any(|m| m == "ui.config.save"));
    }
}
