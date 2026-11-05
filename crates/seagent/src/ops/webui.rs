//! ARP methods for the Control UI pages that [`crate::ops::ui_methods`] does not cover:
//! model providers + the model catalog (`ui.models.*`), paired devices (`ui.devices*`),
//! plugins and MCP servers (`ui.plugins`, `ui.plugins.set`, `ui.mcp.set`), the daemon's log
//! files (`ui.logs`, `ui.logs.files`), attachment uploads (`ui.upload`, `ui.upload.delete`)
//! and the composer (`ui.submit`).
//!
//! Registered by `seagent daemon run` (`methods`), names listed in `METHODS` for `initialize`.
//! Everything goes through the app token like every other ARP call; secret *values* are
//! never returned (only where a key would come from) and never logged.
//!
//! Offline by design: `ui.models.check` validates references and credentials from config,
//! the vault and the models.dev snapshot only — no provider request is made. `ui.plugins.set`
//! and `ui.mcp.set` only persist the flag; the daemon picks it up on the next start (no
//! process is started or stopped here). `ui.devices*` reuses `seagent_app::node`'s registry and
//! its `node.*` handlers, so the Devices page and `seagent nodes` always agree.

use seagent_kernel::config::{project_config, Config, Paths};
use seagent_kernel::daemon::MethodExt;
use seagent_kernel::kernel::{Kernel, RunOpts};
use seagent_kernel::vault::Vault;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::providers::Providers;

/// Method names exposed to the app server (WebSocket/HTTP ARP) in addition to the daemon's own.
pub const METHODS: &[&str] = &[
    "ui.models.list", "ui.models.set", "ui.models.check", "ui.models.key",
    "ui.devices", "ui.devices.rename", "ui.devices.remove", "ui.devices.approve", "ui.devices.reject",
    "ui.plugins", "ui.plugins.set", "ui.mcp.set",
    "ui.logs", "ui.logs.files",
    "ui.fleet",
    "ui.upload", "ui.upload.delete",
    "ui.submit",
];

type Res = Result<Value, (i32, String)>;

fn bad(e: impl Into<String>) -> (i32, String) {
    (-32602, e.into())
}
fn denied(e: impl Into<String>) -> (i32, String) {
    (-32001, e.into())
}
fn fail(e: impl Into<String>) -> (i32, String) {
    (-32000, e.into())
}
fn io_fail(e: std::io::Error) -> (i32, String) {
    fail(e.to_string())
}

/// 8 MiB per file, 8 files per message, 256 MiB for the whole upload directory.
const MAX_UPLOAD_BYTES: usize = 8 * 1024 * 1024;
const MAX_UPLOADS: usize = 8;
const UPLOAD_BUDGET: u64 = 256 * 1024 * 1024;

/// A plugin process the daemon started: what the Plugins page shows next to the config.
struct LivePlugin {
    name: String,
    ui: Value,
    routes: Value,
    tools: usize,
}

pub struct WebCtx {
    pub paths: Paths,
    pub k: Kernel,
    /// Workspace whose `.seagent/config.toml` layers over the user config.
    pub ws: PathBuf,
    plugins: Vec<LivePlugin>,
    /// MCP server → (tool count, running).
    mcp: Vec<(String, usize, bool)>,
}

pub fn methods(paths: &Paths, k: Kernel, ext: Option<&crate::ext::Ext>) -> MethodExt {
    let mut plugins = Vec::new();
    let mut mcp = Vec::new();
    if let Some(e) = ext {
        let tool_names: Vec<String> = k.tools.iter().map(|t| t.spec().name).collect();
        for p in &e.plugins {
            let prefix = format!("mcp__{}__", p.name);
            plugins.push(LivePlugin {
                name: p.name.clone(),
                ui: json!(p.ui),
                routes: json!(p.routes),
                tools: tool_names.iter().filter(|n| n.starts_with(&prefix)).count(),
            });
        }
        mcp = e.registry.status();
    }
    let ws = k.cfg.app.get("workspace").and_then(|v| v.as_str()).map(PathBuf::from).or_else(|| std::env::current_dir().ok()).unwrap_or_else(|| PathBuf::from("/"));
    let c = Arc::new(WebCtx { paths: paths.clone(), k, ws, plugins, mcp });
    Arc::new(move |m: &str, p: &Value| call(&c, m, p))
}

pub fn call(c: &WebCtx, m: &str, p: &Value) -> Option<Res> {
    let s = |k: &str| p[k].as_str().unwrap_or("").trim().to_string();
    Some(match m {
        // ── models ──
        "ui.models.list" => models_list(c),
        "ui.models.set" => models_set(c, p),
        "ui.models.check" => models_check(c, p),
        "ui.models.key" => models_key(c, &s("provider"), p["key"].as_str().unwrap_or("")),
        // ── devices ──
        "ui.devices" => devices(c),
        "ui.devices.rename" => node("node.rename", json!({"id": s("id"), "name": s("name")})),
        "ui.devices.remove" => node("node.remove", json!({"id": s("id")})),
        "ui.devices.approve" => node("node.pair.approve", json!({"code": s("code")})),
        "ui.devices.reject" => node("node.pair.reject", json!({"code": s("code")})),
        // ── plugins / MCP ──
        "ui.plugins" => plugins(c),
        "ui.plugins.set" => plugin_set(c, &s("name"), p["enabled"].as_bool().unwrap_or(true)),
        "ui.mcp.set" => mcp_set(c, &s("name"), p["enabled"].as_bool().unwrap_or(true)),
        // ── logs ──
        "ui.logs" => logs(c, p),
        "ui.logs.files" => Ok(json!({"files": log_files(c)})),
        // ── multi-agent progress (C10) ──
        "ui.fleet" => Ok(fleet(c)),
        // ── uploads / submit ──
        "ui.upload" => upload(c, &s("name"), p["data"].as_str().unwrap_or("")),
        "ui.upload.delete" => upload_delete(c, &s("path")),
        "ui.submit" => submit(c, p),
        _ => return None,
    })
}

/// The config as it is on disk now (the daemon's copy can be stale after `ui.config.set`).
fn fresh(c: &WebCtx) -> Result<Config, (i32, String)> {
    Config::load(Some(&c.paths.user_config()), Some(&project_config(&c.ws)), &[]).map_err(fail)
}

fn providers_for(cfg: &Config, paths: &Paths) -> Result<Providers, (i32, String)> {
    let vault = Arc::new(Vault::load(&paths.secrets()).map_err(fail)?);
    Providers::new(&cfg.providers, vault).map_err(fail)
}

// ───────────────────────── models ─────────────────────────

/// `key_source` as the page shows it: one of vault | env | config | credential store |
/// key_cmd | none. Cloud credential chains (AWS / Google / Entra) come from the machine's
/// environment, so they are reported as `env`.
fn norm_source(s: &str) -> &'static str {
    match s {
        "vault" => "vault",
        "environment" => "env",
        "config" => "config",
        "credential store" => "credential store",
        "key_cmd" => "key_cmd",
        "AWS credentials" | "Google Cloud credentials" | "Entra ID" => "env",
        _ => "none",
    }
}

fn keyed(src: &str) -> bool {
    matches!(src, "vault" | "env" | "config" | "credential store" | "key_cmd")
}

fn preset_label(id: &str) -> String {
    seagent_model::catalog::catalog().into_iter().find(|p| p.cfg.id == id).map(|p| p.name.to_string()).unwrap_or_else(|| id.to_string())
}

/// One catalog row: capabilities and price for `provider/model` (registry, snapshot or
/// config prices — never a network call).
fn model_row(cfg: &Config, provider: &str, model: &str) -> Value {
    let entry = seagent_model::modelsdb::registry_entry(Some(provider), model);
    let caps = entry.as_ref().map(|i| i.caps()).unwrap_or_else(|| seagent_model::caps_for(model));
    let r = format!("{provider}/{model}");
    let price = entry.and_then(|i| i.pricing).map(|x| (x.input, x.output)).or_else(|| cfg.price(&r).map(|x| (x.input, x.output)));
    json!({
        "ref": r,
        "provider": provider,
        "caps": {
            "tools": caps.tools,
            "vision": caps.vision,
            "explicit_cache": caps.explicit_cache,
            "max_output": caps.max_output,
            "context_window": caps.context_window,
        },
        "context_window": caps.context_window,
        "cost_in": price.map(|(i, _)| i).map(Value::from).unwrap_or(Value::Null),
        "cost_out": price.map(|(_, o)| o).map(Value::from).unwrap_or(Value::Null),
    })
}

fn push_ref(refs: &mut Vec<(String, String)>, p: &str, m: &str) {
    if !p.is_empty() && !m.is_empty() && !refs.iter().any(|(a, b)| a == p && b == m) {
        refs.push((p.to_string(), m.to_string()));
    }
}

/// Every model reference the config names (default, fallback, aux, subagent, tasks, aliases).
fn configured_refs(cfg: &Config) -> Vec<String> {
    let mut v: Vec<String> = vec![cfg.model.default.clone()];
    v.extend(cfg.model.fallback.iter().cloned());
    v.push(cfg.aux_model().to_string());
    v.push(cfg.subagent_model().to_string());
    v.extend(cfg.model.tasks.values().cloned());
    v.extend(cfg.model.aliases.values().cloned());
    let mut out: Vec<String> = Vec::new();
    for m in v {
        let m = cfg.resolve_model(&m).to_string();
        let m = m.trim().to_string();
        if !m.is_empty() && !out.contains(&m) {
            out.push(m);
        }
    }
    out
}

fn model_rows(cfg: &Config, ps: &Providers) -> Vec<Value> {
    let mut refs: Vec<(String, String)> = Vec::new();
    for (id, c) in ps.configs() {
        for m in &c.models {
            push_ref(&mut refs, id, m);
        }
    }
    for r in configured_refs(cfg) {
        if let Some((p, m)) = r.split_once('/') {
            push_ref(&mut refs, p, m);
        }
    }
    refs.iter().map(|(p, m)| model_row(cfg, p, m)).collect()
}

/// Providers, the model catalog and the current routing. Never includes a key value.
fn models_list(c: &WebCtx) -> Res {
    let cfg = fresh(c)?;
    let ps = providers_for(&cfg, &c.paths)?;
    let providers: Vec<Value> = ps
        .configs()
        .iter()
        .map(|(id, pc)| {
            let src = ps.key_source(id).map(norm_source).unwrap_or("none");
            json!({
                "id": id,
                "label": preset_label(id),
                "base_url": pc.base_url,
                "key_source": src,
                "keyed": keyed(src),
                "keyless": pc.keyless(),
                "models": pc.models,
            })
        })
        .collect();
    Ok(json!({
        "default": cfg.model.default,
        "fallback": cfg.model.fallback,
        "aux": cfg.aux_model(),
        "subagent": cfg.subagent_model(),
        "providers": providers,
        "models": model_rows(&cfg, &ps),
    }))
}

/// `provider/model` (or a `model.aliases` name) → canonical `provider/model`.
fn resolve_ref(cfg: &Config, ps: &Providers, raw: &str) -> Result<String, (i32, String)> {
    let raw = cfg.resolve_model(raw.trim());
    let (pid, model) = raw.split_once('/').ok_or_else(|| bad(format!("`{raw}` is not provider/model")))?;
    let (pid, model) = (pid.trim(), model.trim());
    if model.is_empty() {
        return Err(bad(format!("`{raw}` has no model id")));
    }
    let canon = ps.canonical(pid).ok_or_else(|| bad(format!("unknown provider `{pid}`")))?;
    let pc = ps.config(&canon).expect("canonical() resolves to a config");
    let known = pc.models.iter().any(|m| m.eq_ignore_ascii_case(model)) || pc.models.is_empty() || seagent_model::modelsdb::registry_entry(Some(&canon), model).is_some();
    if !known {
        return Err(bad(format!("unknown model `{model}` for provider `{canon}` (known: {})", pc.models.join(", "))));
    }
    Ok(format!("{canon}/{model}"))
}

fn conf_unset_lenient(paths: &Paths, key: &str) -> Result<(), (i32, String)> {
    match crate::ops::confcli::unset(paths, key) {
        Ok(_) => Ok(()),
        Err(e) if e.contains("is not set") => Ok(()),
        Err(e) => Err(fail(e)),
    }
}

/// Set the default / fallback / aux model. Every reference is validated first; the values go
/// through `ops::confcli` so comments in the user config survive and an invalid file is never
/// written. An empty string (or empty array) clears the key.
fn models_set(c: &WebCtx, p: &Value) -> Res {
    let before = fresh(c)?;
    let ps = providers_for(&before, &c.paths)?;
    let has = ["default", "fallback", "aux"].iter().any(|k| p.get(*k).is_some());
    if !has {
        return Err(bad("give `default`, `fallback` or `aux`"));
    }
    if let Some(v) = p.get("default") {
        let v = v.as_str().ok_or_else(|| bad("default must be a string"))?;
        if v.trim().is_empty() {
            conf_unset_lenient(&c.paths, "model.default")?;
        } else {
            let r = resolve_ref(&before, &ps, v)?;
            crate::ops::confcli::set(&c.paths, "model.default", &format!("{r:?}")).map_err(fail)?;
        }
    }
    if let Some(v) = p.get("fallback") {
        let list = v.as_array().ok_or_else(|| bad("fallback must be an array of provider/model"))?;
        let mut out: Vec<toml::Value> = Vec::new();
        for m in list {
            let m = m.as_str().ok_or_else(|| bad("fallback entries must be strings"))?.trim();
            if m.is_empty() {
                continue;
            }
            out.push(toml::Value::String(resolve_ref(&before, &ps, m)?));
        }
        if out.is_empty() {
            conf_unset_lenient(&c.paths, "model.fallback")?;
        } else {
            crate::ops::confcli::set(&c.paths, "model.fallback", &toml::Value::Array(out).to_string()).map_err(fail)?;
        }
    }
    if let Some(v) = p.get("aux") {
        let v = v.as_str().ok_or_else(|| bad("aux must be a string"))?;
        if v.trim().is_empty() {
            conf_unset_lenient(&c.paths, "model.aux")?;
        } else {
            let r = resolve_ref(&before, &ps, v)?;
            crate::ops::confcli::set(&c.paths, "model.aux", &format!("{r:?}")).map_err(fail)?;
        }
    }
    let cfg = fresh(c)?;
    Ok(json!({
        "ok": true,
        "default": cfg.model.default,
        "fallback": cfg.model.fallback,
        "aux": cfg.aux_model(),
    }))
}

/// Offline validation: every reference resolves (known provider + a model it offers) and the
/// provider has a usable credential (vault, env, config, credential store, key_cmd). No
/// network call is made, so a provider being down does not fail the check.
fn models_check(c: &WebCtx, p: &Value) -> Res {
    let cfg = fresh(c)?;
    let ps = providers_for(&cfg, &c.paths)?;
    let refs: Vec<String> = match p.get("refs").and_then(Value::as_array) {
        Some(a) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
        None => configured_refs(&cfg),
    };
    let mut checks = Vec::new();
    let mut all_ok = true;
    for raw in refs {
        let resolved = resolve_ref(&cfg, &ps, &raw);
        let provider = resolved
            .as_ref()
            .ok()
            .and_then(|r| r.split_once('/').map(|(p, _)| p.to_string()))
            .or_else(|| raw.split_once('/').map(|(p, _)| p.to_string()))
            .unwrap_or_default();
        let (src, mut ok, detail) = match ps.key_source(&provider) {
            Ok(s) => {
                let n = norm_source(s);
                let usable = keyed(n) || ps.config(&provider).map(|x| x.keyless()).unwrap_or(false);
                let detail = if usable { format!("ready ({s})") } else { format!("no usable key ({s})") };
                (n, usable, detail)
            }
            Err(e) => ("none", false, e),
        };
        let detail = match &resolved {
            Ok(_) => detail,
            Err((_, e)) => e.clone(),
        };
        ok &= resolved.is_ok();
        all_ok &= ok;
        checks.push(json!({"ref": raw, "provider": provider, "key_source": src, "ok": ok, "detail": detail}));
    }
    Ok(json!({"ok": all_ok, "checks": checks}))
}

/// Store (or remove) the API key of a provider. The key goes to the secret vault under the
/// name the provider config reads (`api_key_env` / `key_envs`), which is the only place the
/// runtime looks for it; a provider without such a name but with a key field gets it written
/// to `[providers.<id>] api_key` (source `config`). The value is never echoed back.
fn models_key(c: &WebCtx, provider: &str, key: &str) -> Res {
    if provider.is_empty() {
        return Err(bad("provider is required"));
    }
    let cfg = fresh(c)?;
    let ps = providers_for(&cfg, &c.paths)?;
    let canon = ps.canonical(provider).ok_or_else(|| bad(format!("unknown provider `{provider}`")))?;
    let pc = ps.config(&canon).expect("canonical() resolves to a config").clone();
    let name = pc.key_env_names().into_iter().next();
    match name {
        Some(name) => {
            let v = Vault::load(&c.paths.secrets()).map_err(fail)?;
            if key.is_empty() {
                let removed = v.remove(&name).map_err(fail)?;
                Ok(json!({"removed": removed, "name": name}))
            } else {
                v.set(&name, key).map_err(fail)?;
                Ok(json!({"ok": true, "source": "vault", "name": name}))
            }
        }
        None if pc.keyless() => Err(bad(format!("provider `{canon}` needs no key"))),
        None => {
            let conf = format!("providers.{canon}.api_key");
            if key.is_empty() {
                let removed = crate::ops::confcli::unset(&c.paths, &conf).is_ok();
                Ok(json!({"removed": removed, "source": "config"}))
            } else {
                crate::ops::confcli::set(&c.paths, &conf, &format!("{key:?}")).map_err(fail)?;
                Ok(json!({"ok": true, "source": "config", "name": conf}))
            }
        }
    }
}

// ───────────────────────── devices ─────────────────────────

/// Call one of `seagent_app::node`'s own handlers (`node.*`), so the Devices page and
/// `seagent nodes` share the same registry and side effects.
fn node(m: &str, p: Value) -> Res {
    let f = seagent_app::node::methods();
    f(m, &p).ok_or_else(|| fail(format!("{m} is not available in this daemon")))?
}

/// C10: the same payload as `seagent fleet --json` (one source of truth: `coord::fleet_overview`)
/// plus the resource/pause picture, so the Agents page can show spend and who is paused.
fn fleet(c: &WebCtx) -> Value {
    let mut v = seagent_kernel::coord::fleet_overview(&c.k);
    v["limits"] = seagent_kernel::limits::status_json(&c.k);
    v["reaper"] = seagent_kernel::reaper::sweep_json(&c.paths.data);
    v
}

fn devices(_c: &WebCtx) -> Res {
    let list = node("node.list", json!({}))?;
    let pending = node("node.pair.list", json!({}))?;
    Ok(json!({
        "nodes": list["connected"].clone(),
        "paired": list["paired"].clone(),
        "pending": pending,
    }))
}

// ───────────────────────── plugins / MCP ─────────────────────────

/// `version` from the package manifest (`plugin.json` / `package.json`), the install record or
/// `seagent-plugin.toml`; built-ins carry seagent's own version.
fn manifest_of(dir: &Path) -> Option<Value> {
    for f in ["plugin.json", "package.json", ".seagent-install.json"] {
        if let Some(v) = std::fs::read_to_string(dir.join(f)).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()) {
            return Some(v);
        }
    }
    let t: toml::Table = std::fs::read_to_string(dir.join("seagent-plugin.toml")).ok()?.parse().ok()?;
    let sec = t.get("plugin").and_then(|v| v.as_table()).unwrap_or(&t);
    Some(json!({"name": sec.get("name"), "version": sec.get("version"), "description": sec.get("description")}))
}

fn plugin_meta(cfg: &Config, paths: &Paths, name: &str, kind: &str) -> (String, String) {
    match kind {
        "builtin" => {
            let d = seagent_plugin::builtin::NAMES.iter().find(|(n, _, _)| *n == name).map(|(_, d, _)| d.to_string()).unwrap_or_default();
            (env!("CARGO_PKG_VERSION").to_string(), d)
        }
        "process" => {
            let t = cfg.plugins.get(name);
            let v = t.and_then(|t| t.get("version")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            let d = t.and_then(|t| t.get("description")).and_then(|v| v.as_str()).unwrap_or("").to_string();
            (v, d)
        }
        _ => {
            let m = manifest_of(&paths.data.join("plugins").join(name));
            let get = |k: &str| m.as_ref().and_then(|v| v.get(k)).and_then(Value::as_str).unwrap_or("").to_string();
            (get("version"), get("description"))
        }
    }
}

/// Plugins (built-ins, process plugins and installed packages) and MCP servers, with what is
/// actually live in this daemon next to what the config says.
fn plugins(c: &WebCtx) -> Res {
    let cfg = fresh(c)?;
    let pm = seagent_skills::hub::plugins::Plugins::new(&cfg, &c.paths);
    let mut out = Vec::new();
    for e in pm.list() {
        let name = e["name"].as_str().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        let kind = e["kind"].as_str().unwrap_or("package").to_string();
        let (version, description) = plugin_meta(&cfg, &c.paths, &name, &kind);
        let live = c.plugins.iter().find(|p| p.name == name);
        let mcp_count = e["mcp"].as_array().map(|a| a.len()).unwrap_or(0);
        out.push(json!({
            "name": name,
            "version": version,
            "enabled": e["enabled"].as_bool().unwrap_or(false),
            "description": description,
            "ui": live.map(|l| l.ui.clone()).unwrap_or_else(|| json!([])),
            "routes": live.map(|l| l.routes.clone()).unwrap_or_else(|| json!([])),
            "tools": live.map(|l| l.tools).unwrap_or(0) + mcp_count,
            "source": kind,
        }));
    }
    let mcp: Vec<Value> = cfg
        .mcp
        .iter()
        .map(|(name, t)| {
            let enabled = t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let live = c.mcp.iter().find(|(n, _, _)| n == name);
            json!({
                "name": name,
                "running": live.map(|(_, _, r)| *r).unwrap_or(false),
                "tools": live.map(|(_, n, _)| *n).unwrap_or(0),
                "enabled": enabled,
            })
        })
        .collect();
    Ok(json!({"plugins": out, "mcp": mcp}))
}

/// Enable/disable a plugin. Persisted exactly like `seagent plugins enable|disable`
/// (`[builtin_plugins.<name>]`, `[plugins.<name>]` or the package's `.disabled` marker); no
/// process is started or stopped — the daemon applies it on the next start.
fn plugin_set(c: &WebCtx, name: &str, enabled: bool) -> Res {
    if name.is_empty() {
        return Err(bad("name is required"));
    }
    let cfg = fresh(c)?;
    let pm = seagent_skills::hub::plugins::Plugins::new(&cfg, &c.paths);
    let msg = pm.set_enabled(name, enabled).map_err(|e| if e.contains("not installed") { denied(e) } else { fail(e) })?;
    Ok(json!({"ok": true, "name": name, "enabled": enabled, "message": msg}))
}

/// Enable/disable an MCP server (`[mcp.<name>] enabled = …`), persisted like the config page.
/// No process is started or stopped here.
fn mcp_set(c: &WebCtx, name: &str, enabled: bool) -> Res {
    if name.is_empty() {
        return Err(bad("name is required"));
    }
    let cfg = fresh(c)?;
    if !cfg.mcp.contains_key(name) {
        return Err(denied(format!("no MCP server `{name}` (see `seagent mcp list`)")));
    }
    let msg = crate::ops::confcli::set(&c.paths, &format!("mcp.{name}.enabled"), if enabled { "true" } else { "false" }).map_err(fail)?;
    Ok(json!({"ok": true, "name": name, "enabled": enabled, "message": msg}))
}

// ───────────────────────── logs ─────────────────────────

fn modified_ms(p: &Path) -> u64 {
    std::fs::metadata(p).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0)
}

fn internal_logs(c: &WebCtx) -> PathBuf {
    crate::ops::logs::dir(&c.paths)
}

fn stderr_log(c: &WebCtx) -> PathBuf {
    c.paths.daemon_log()
}

/// The daemon's own log files: the JSONL tap (`seagent.jsonl`, rotated) and the stderr log.
fn log_files(c: &WebCtx) -> Vec<Value> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(internal_logs(c)).map(|r| r.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "jsonl")).collect()).unwrap_or_default();
    let err = stderr_log(c);
    if err.is_file() {
        paths.push(err);
    }
    let mut out: Vec<Value> = paths
        .into_iter()
        .map(|p| json!({
            "path": p.display().to_string(),
            "name": p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
            "bytes": std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0),
            "modified": modified_ms(&p),
        }))
        .collect();
    out.sort_by_key(|v| v["modified"].as_u64().unwrap_or(0));
    out
}

fn level_rank(l: &str) -> u8 {
    match l {
        "error" => 4,
        "warn" | "warning" => 3,
        "info" => 2,
        _ => 1,
    }
}

fn stderr_level(line: &str) -> &'static str {
    let l = line.to_lowercase();
    if l.contains("error") || l.contains("failed") || l.contains("panic") {
        "error"
    } else if l.contains("warning") || l.contains("stopped") {
        "warn"
    } else {
        "info"
    }
}

/// Records of one log file, oldest first, filtered and capped.
fn tail_file(path: &Path, level: Option<&str>, since_ms: Option<u64>, grep: Option<&str>, limit: usize) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let jsonl = path.extension().is_some_and(|e| e == "jsonl");
    let mtime = modified_ms(path);
    let min = level.map(level_rank).unwrap_or(0);
    let g = grep.map(|g| g.to_lowercase()).filter(|g| !g.is_empty());
    let mut out: Vec<Value> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (ts, level, target, msg) = if jsonl {
            let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
            (v["ts"].as_u64().unwrap_or(0), v["level"].as_str().unwrap_or("info").to_string(), v["kind"].as_str().unwrap_or("").to_string(), v["msg"].as_str().unwrap_or("").to_string())
        } else {
            (mtime, stderr_level(line).to_string(), "seagentd".to_string(), line.to_string())
        };
        if level_rank(&level) < min || since_ms.is_some_and(|s| ts < s) || g.as_ref().is_some_and(|g| !msg.to_lowercase().contains(g.as_str())) {
            continue;
        }
        out.push(json!({"ts": ts, "level": level, "target": target, "text": msg}));
    }
    let skip = out.len().saturating_sub(limit);
    out.split_off(skip)
}

/// Log files plus a tail of one of them (`file` names a listed file; the live JSONL by
/// default). `limit` is capped at 2000 records.
fn logs(c: &WebCtx, p: &Value) -> Res {
    let files = log_files(c);
    let want = p["file"].as_str().unwrap_or("").trim();
    let path = if want.is_empty() {
        let live = internal_logs(c).join("seagent.jsonl");
        if live.is_file() {
            live
        } else if stderr_log(c).is_file() {
            stderr_log(c)
        } else {
            files.last().and_then(|v| v["path"].as_str()).map(PathBuf::from).unwrap_or_else(|| internal_logs(c).join("seagent.jsonl"))
        }
    } else {
        match files.iter().find(|v| v["name"] == want || v["path"] == want) {
            Some(v) => PathBuf::from(v["path"].as_str().unwrap_or("")),
            None => return Err(bad(format!("no log file `{want}` (see `ui.logs.files`)"))),
        }
    };
    let limit = p["limit"].as_u64().unwrap_or(200).min(2000) as usize;
    let since = p["since"].as_str().and_then(|s| crate::ops::logs::parse_since(s, seagent_kernel::event::now_ms()));
    let mut tail = tail_file(&path, p["level"].as_str(), since, p["grep"].as_str(), limit);
    // Best effort: a key printed by a channel or a tool must not come back through the page.
    if let Ok(v) = Vault::load(&c.paths.secrets()) {
        for r in &mut tail {
            if let Some(t) = r["text"].as_str() {
                let red = v.redact(t);
                if red != t {
                    r["text"] = json!(red);
                }
            }
        }
    }
    Ok(json!({"files": files, "file": path.display().to_string(), "tail": tail}))
}

// ───────────────────────── uploads ─────────────────────────

fn uploads_dir(c: &WebCtx) -> PathBuf {
    c.paths.data.join("uploads")
}

/// Uploaded files only: the path must resolve inside `<data>/uploads`.
fn upload_path(c: &WebCtx, p: &str) -> Result<PathBuf, (i32, String)> {
    let dir = uploads_dir(c).canonicalize().map_err(|_| denied("no uploads yet"))?;
    let real = PathBuf::from(p).canonicalize().map_err(|_| denied(format!("no uploaded file `{p}`")))?;
    if !real.starts_with(&dir) || !real.is_file() {
        return Err(denied(format!("`{p}` is not inside the uploads directory")));
    }
    Ok(real)
}

fn mime_of(name: &str) -> String {
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_lowercase()).unwrap_or_default();
    match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "log" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "csv" => "text/csv",
        "html" | "htm" => "text/html",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Image type from the file's magic bytes (`None` = not an image we can send as a block).
fn sniff_image(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF8") {
        Some("image/gif")
    } else if bytes.len() > 12 && &bytes[..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// The media type an uploaded file is sent as: the extension when it names a real image,
/// otherwise the magic bytes (a page may upload `photo` without one).
fn image_mime(name: &str, bytes: &[u8]) -> Option<&'static str> {
    match mime_of(name).as_str() {
        "image/png" => Some("image/png"),
        "image/jpeg" => Some("image/jpeg"),
        "image/gif" => Some("image/gif"),
        "image/webp" => Some("image/webp"),
        _ => sniff_image(bytes),
    }
}

/// A `data:` URL or bare base64 → bytes, plus the media type when the URL carried one.
fn decode_data(raw: &str) -> Result<(Vec<u8>, Option<String>), (i32, String)> {
    if let Some(rest) = raw.strip_prefix("data:") {
        let (meta, b64) = rest.split_once(',').ok_or_else(|| bad("data URL has no `,` before the payload"))?;
        let mime = meta.strip_suffix(";base64").unwrap_or(meta).trim();
        let bytes = seagent_net::crypto::b64_decode(b64).ok_or_else(|| bad("data URL payload is not base64"))?;
        let mime = (!mime.is_empty()).then(|| mime.to_string());
        Ok((bytes, mime))
    } else {
        let bytes = seagent_net::crypto::b64_decode(raw).ok_or_else(|| bad("data must be a data: URL or base64"))?;
        Ok((bytes, None))
    }
}

/// A plain file name: no separators, no leading dot, nothing that could climb out of the
/// uploads directory.
fn safe_name(raw: &str) -> Result<String, (i32, String)> {
    let n = raw.trim();
    if n.is_empty() {
        return Err(bad("name is required"));
    }
    if n.contains('/') || n.contains('\\') || n.contains("..") || n.starts_with('.') {
        return Err(bad(format!("`{raw}` must be a plain file name (no path separators, no leading dot)")));
    }
    let cleaned: String = n.chars().map(|ch| if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ' ') { ch } else { '_' }).collect();
    let cleaned = cleaned.trim().trim_start_matches('.').to_string();
    if cleaned.is_empty() {
        return Err(bad(format!("`{raw}` has no usable file name")));
    }
    Ok(cleaned)
}

fn uploads_bytes(c: &WebCtx) -> u64 {
    std::fs::read_dir(uploads_dir(c)).map(|r| r.flatten().filter_map(|e| e.metadata().ok()).filter(|m| m.is_file()).map(|m| m.len()).sum()).unwrap_or(0)
}

/// Write a decoded upload under `<data>/uploads/<random>-<name>` with mode 0600.
fn upload(c: &WebCtx, name: &str, data: &str) -> Res {
    let name = safe_name(name)?;
    if data.trim().is_empty() {
        return Err(bad("data is required"));
    }
    let (bytes, mime) = decode_data(data)?;
    if bytes.is_empty() {
        return Err(bad("the upload is empty"));
    }
    if bytes.len() > MAX_UPLOAD_BYTES {
        return Err(bad(format!("the upload is {} bytes; the limit is 8 MiB", bytes.len())));
    }
    if uploads_bytes(c) + bytes.len() as u64 > UPLOAD_BUDGET {
        return Err(fail("the uploads directory is full; delete some attachments first"));
    }
    let dir = uploads_dir(c);
    std::fs::create_dir_all(&dir).map_err(io_fail)?;
    let file = format!("{}-{}", seagent_kernel::util::random_hex(8), name);
    let path = dir.join(&file);
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&path).map_err(io_fail)?;
        f.write_all(&bytes).map_err(io_fail)?;
    }
    let mime = mime.filter(|m| !m.is_empty()).unwrap_or_else(|| mime_of(&name));
    Ok(json!({"path": path.display().to_string(), "name": name, "bytes": bytes.len(), "mime": mime}))
}

/// Delete one upload. Only files inside the uploads directory are ever removed.
fn upload_delete(c: &WebCtx, path: &str) -> Res {
    if path.is_empty() {
        return Err(bad("path is required"));
    }
    let real = upload_path(c, path)?;
    let removed = std::fs::remove_file(&real).is_ok();
    Ok(json!({"removed": removed, "path": real.display().to_string()}))
}

// ───────────────────────── submit ─────────────────────────

fn kernel_err(e: seagent_kernel::kernel::KernelError) -> (i32, String) {
    match e {
        seagent_kernel::kernel::KernelError::Store(seagent_kernel::store::StoreError::NotFound(id)) => denied(format!("no session `{id}`")),
        other => fail(other.to_string()),
    }
}

/// Submit a composer message: uploaded files become `Block::Image` blocks (images) or an
/// `[attached: name]` line in the prompt (everything else). The turn is started when the
/// session is idle.
fn submit(c: &WebCtx, p: &Value) -> Res {
    let id = p["id"].as_str().map(str::trim).unwrap_or("").to_string();
    if id.is_empty() {
        return Err(bad("id is required"));
    }
    let uploads: Vec<String> = p["uploads"].as_array().map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default();
    if uploads.len() > MAX_UPLOADS {
        return Err(bad(format!("at most {MAX_UPLOADS} attachments per message")));
    }
    let mut body = p["text"].as_str().unwrap_or("").to_string();
    let mut blocks: Vec<seagent_core::Block> = Vec::new();
    for u in &uploads {
        let real = upload_path(c, u)?;
        let meta = std::fs::metadata(&real).map_err(io_fail)?;
        if meta.len() > MAX_UPLOAD_BYTES as u64 {
            return Err(bad(format!("`{u}` is larger than 8 MiB")));
        }
        let name = real.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let shown = name.split_once('-').map(|(_, rest)| rest).unwrap_or(&name).to_string();
        let bytes = std::fs::read(&real).map_err(io_fail)?;
        match image_mime(&shown, &bytes) {
            Some(media_type) => blocks.push(seagent_core::Block::Image { media_type: media_type.into(), data: seagent_net::crypto::b64(&bytes) }),
            None => body.push_str(&format!("\n[attached: {shown}]")),
        }
    }
    if body.trim().is_empty() && blocks.is_empty() {
        return Err(bad("text or uploads is required"));
    }
    let started = !c.k.is_running(&id);
    c.k.submit_with(&id, &body, blocks.clone(), "web").map_err(kernel_err)?;
    if started {
        let _ = c.k.start(&id, RunOpts::default());
    }
    Ok(json!({"queued": true, "started": started, "blocks": blocks.len(), "attachments": uploads.len()}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{env_lock, kit, Kit};

    const PROBE_KEY_ENV: &str = "SEAGENT_WEBUI_PROBE_KEY";
    const PROBE_CONFIG: &str = "[model]\ndefault = \"probe/m1\"\nfallback = [\"probe/m2\"]\n\n[providers.probe]\nformat = \"openai_chat\"\nbase_url = \"http://127.0.0.1:9/v1\"\napi_key_env = \"SEAGENT_WEBUI_PROBE_KEY\"\n";

    fn ctx(t: &Kit) -> WebCtx {
        WebCtx { paths: t.paths.clone(), k: t.k.clone(), ws: t.ws.clone(), plugins: vec![], mcp: vec![] }
    }
    fn ok(c: &WebCtx, m: &str, p: Value) -> Value {
        call(c, m, &p).unwrap_or_else(|| panic!("{m} not handled")).unwrap_or_else(|e| panic!("{m}: {e:?}"))
    }
    fn err(c: &WebCtx, m: &str, p: Value) -> (i32, String) {
        call(c, m, &p).unwrap_or_else(|| panic!("{m} not handled")).unwrap_err()
    }
    fn png_data() -> String {
        // 1x1 PNG.
        format!("data:image/png;base64,{}", "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
    }

    #[test]
    fn models_list_redacts_keys_and_lists_providers() {
        let _g = env_lock();
        let t = kit();
        std::env::remove_var(PROBE_KEY_ENV);
        std::fs::write(t.paths.user_config(), PROBE_CONFIG).unwrap();
        let v = Vault::load(&t.paths.secrets()).unwrap();
        v.set(PROBE_KEY_ENV, "sk-probe-secret-9f3a2b").unwrap();
        let c = ctx(&t);
        let l = ok(&c, "ui.models.list", json!({}));
        let text = l.to_string();
        assert!(!text.contains("sk-probe-secret-9f3a2b"), "a key value leaked into ui.models.list");
        assert_eq!(l["default"], "probe/m1");
        assert_eq!(l["aux"], "probe/m1", "aux falls back to the default");
        let p = l["providers"].as_array().unwrap().iter().find(|p| p["id"] == "probe").expect("probe listed");
        assert_eq!((p["key_source"].as_str(), p["keyed"].as_bool()), (Some("vault"), Some(true)));
        assert!(p["models"].is_array() && p["label"].is_string());
        let refs: Vec<&str> = l["models"].as_array().unwrap().iter().filter_map(|m| m["ref"].as_str()).collect();
        assert!(refs.contains(&"probe/m1") && refs.contains(&"probe/m2"), "{refs:?}");
        let m1 = l["models"].as_array().unwrap().iter().find(|m| m["ref"] == "probe/m1").unwrap();
        assert!(m1["caps"]["context_window"].as_u64().unwrap() > 0 && m1["context_window"].as_u64().unwrap() > 0);
    }

    #[test]
    fn models_set_writes_confcli_and_rejects_unknown_refs() {
        let _g = env_lock();
        let t = kit();
        std::env::remove_var(PROBE_KEY_ENV);
        std::fs::write(t.paths.user_config(), "# keep me\n[model]\ndefault = \"echo/m\"\n").unwrap();
        let c = ctx(&t);
        let r = ok(&c, "ui.models.set", json!({"default": "openai-codex/gpt-5.5"}));
        assert_eq!(r["default"], "openai-codex/gpt-5.5");
        let text = std::fs::read_to_string(t.paths.user_config()).unwrap();
        assert!(text.contains("# keep me"), "comments must survive: {text}");
        assert!(text.contains("default = \"openai-codex/gpt-5.5\""), "{text}");
        let cfg = Config::load(Some(&t.paths.user_config()), None, &[]).unwrap();
        assert_eq!(cfg.model.default, "openai-codex/gpt-5.5");
        // Aliases resolve too.
        std::fs::write(t.paths.user_config(), "[model]\ndefault = \"echo/m\"\n[model.aliases]\nfast = \"openai-codex/gpt-5.4-mini\"\n").unwrap();
        assert_eq!(ok(&c, "ui.models.set", json!({"default": "fast"}))["default"], "openai-codex/gpt-5.4-mini");
        // Unknown provider / model: -32602, nothing written.
        let before = std::fs::read_to_string(t.paths.user_config()).unwrap();
        let (code, msg) = err(&c, "ui.models.set", json!({"default": "nonesuch/model"}));
        assert_eq!(code, -32602);
        assert!(msg.contains("unknown provider"), "{msg}");
        let (code, msg) = err(&c, "ui.models.set", json!({"default": "openai-codex/definitely-not-a-model"}));
        assert_eq!(code, -32602);
        assert!(msg.contains("unknown model"), "{msg}");
        assert_eq!(std::fs::read_to_string(t.paths.user_config()).unwrap(), before);
        // Fallback chain, aux, then clearing.
        let r = ok(&c, "ui.models.set", json!({"fallback": ["openai-codex/gpt-5.5", "anthropic/claude-sonnet-5-5"]}));
        assert_eq!(r["fallback"].as_array().unwrap().len(), 2);
        assert_eq!(ok(&c, "ui.models.set", json!({"aux": "openai-codex/gpt-5.4-mini"}))["aux"], "openai-codex/gpt-5.4-mini");
        assert_eq!(ok(&c, "ui.models.set", json!({"aux": ""}))["aux"], r["default"], "clearing aux falls back to the default");
        assert_eq!(ok(&c, "ui.models.set", json!({"fallback": []}))["fallback"].as_array().unwrap().len(), 0);
        assert_eq!(err(&c, "ui.models.set", json!({})).0, -32602);
    }

    #[test]
    fn models_check_is_offline_and_flags_missing_keys() {
        let _g = env_lock();
        let t = kit();
        std::env::remove_var(PROBE_KEY_ENV);
        std::fs::write(t.paths.user_config(), PROBE_CONFIG).unwrap();
        let c = ctx(&t);
        let r = ok(&c, "ui.models.check", json!({}));
        assert_eq!(r["ok"], false);
        let checks = r["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 2, "default + fallback");
        for ch in checks {
            assert_eq!((ch["ok"].as_bool(), ch["key_source"].as_str()), (Some(false), Some("none")));
            assert!(ch["detail"].as_str().unwrap().contains("API key"), "{}", ch["detail"]);
        }
        let only = ok(&c, "ui.models.check", json!({"refs": ["probe/m1"]}));
        assert_eq!(only["checks"].as_array().unwrap().len(), 1);
        let bad_ref = ok(&c, "ui.models.check", json!({"refs": ["nonesuch/x", "openai-codex/m9000"]}));
        assert_eq!(bad_ref["ok"], false);
        assert!(bad_ref["checks"][0]["detail"].as_str().unwrap().contains("unknown provider"));
        assert!(bad_ref["checks"][1]["detail"].as_str().unwrap().contains("unknown model"), "{}", bad_ref["checks"][1]);
        ok(&c, "ui.models.key", json!({"provider": "probe", "key": "sk-check-value-77"}));
        let r = ok(&c, "ui.models.check", json!({}));
        assert_eq!((r["ok"].as_bool(), r["checks"][0]["key_source"].as_str()), (Some(true), Some("vault")));
    }

    #[test]
    fn models_key_stores_in_and_removes_from_the_vault() {
        let _g = env_lock();
        let t = kit();
        std::env::remove_var(PROBE_KEY_ENV);
        std::fs::write(t.paths.user_config(), PROBE_CONFIG).unwrap();
        let c = ctx(&t);
        let r = ok(&c, "ui.models.key", json!({"provider": "probe", "key": "sk-store-me-4711"}));
        assert_eq!((r["ok"].as_bool(), r["source"].as_str(), r["name"].as_str()), (Some(true), Some("vault"), Some(PROBE_KEY_ENV)));
        assert!(!r.to_string().contains("sk-store-me-4711"), "the key must never come back");
        let text = std::fs::read_to_string(t.paths.secrets()).unwrap();
        assert!(text.contains(PROBE_KEY_ENV) && text.contains("sk-store-me-4711"), "{text}");
        assert_eq!(modified_mode(&t.paths.secrets()), 0o600, "secrets stay 0600");
        assert_eq!(ok(&c, "ui.models.check", json!({}))["ok"], true);
        // An alias of the provider works too.
        let r = ok(&c, "ui.models.key", json!({"provider": "probe", "key": ""}));
        assert_eq!(r["removed"], true);
        assert!(!std::fs::read_to_string(t.paths.secrets()).unwrap().contains(PROBE_KEY_ENV));
        assert_eq!(ok(&c, "ui.models.check", json!({}))["ok"], false);
        assert_eq!(err(&c, "ui.models.key", json!({"provider": "nonesuch", "key": "x"})).0, -32602);
        assert_eq!(err(&c, "ui.models.key", json!({"key": "x"})).0, -32602);
    }

    fn modified_mode(p: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn plugins_list_and_toggle_persist() {
        let t = kit();
        let dir = t.paths.data.join("plugins").join("thing");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin.json"), r#"{"name":"thing","version":"1.2.3","description":"a test plugin"}"#).unwrap();
        let c = ctx(&t);
        let l = ok(&c, "ui.plugins", json!({}));
        let thing = l["plugins"].as_array().unwrap().iter().find(|p| p["name"] == "thing").cloned().expect("package listed without an Ext");
        assert_eq!((thing["version"].as_str(), thing["description"].as_str(), thing["enabled"].as_bool()), (Some("1.2.3"), Some("a test plugin"), Some(true)));
        assert!(thing["ui"].is_array() && thing["routes"].is_array() && thing["tools"].as_u64().is_some());
        assert!(l["mcp"].as_array().unwrap().is_empty());
        assert_eq!(ok(&c, "ui.plugins.set", json!({"name": "thing", "enabled": false}))["enabled"], false);
        assert!(dir.join(".disabled").exists(), "the package marker is written");
        let l = ok(&c, "ui.plugins", json!({}));
        assert_eq!(l["plugins"].as_array().unwrap().iter().find(|p| p["name"] == "thing").unwrap()["enabled"], false);
        ok(&c, "ui.plugins.set", json!({"name": "thing", "enabled": true}));
        assert!(!dir.join(".disabled").exists());
        assert_eq!(err(&c, "ui.plugins.set", json!({"name": "ghost", "enabled": true})).0, -32001);
        // A built-in toggles through `[builtin_plugins.<name>] enabled`.
        ok(&c, "ui.plugins.set", json!({"name": "achievements", "enabled": true}));
        assert!(std::fs::read_to_string(t.paths.user_config()).unwrap().contains("achievements"));
    }

    #[test]
    fn mcp_set_toggles_the_config_flag() {
        let t = kit();
        let c = ctx(&t);
        crate::ops::confcli::set(&t.paths, "mcp.demo.command", "\"true\"").unwrap();
        let l = ok(&c, "ui.plugins", json!({}));
        let demo = l["mcp"].as_array().unwrap().iter().find(|m| m["name"] == "demo").cloned().expect("mcp server listed");
        assert_eq!((demo["enabled"].as_bool(), demo["running"].as_bool()), (Some(true), Some(false)));
        assert_eq!(ok(&c, "ui.mcp.set", json!({"name": "demo", "enabled": false}))["enabled"], false);
        let text = std::fs::read_to_string(t.paths.user_config()).unwrap();
        assert!(text.contains("[mcp.demo]") && text.contains("enabled = false"), "{text}");
        let l = ok(&c, "ui.plugins", json!({}));
        assert_eq!(l["mcp"].as_array().unwrap()[0]["enabled"], false);
        assert_eq!(err(&c, "ui.mcp.set", json!({"name": "ghost", "enabled": true})).0, -32001);
    }

    #[test]
    fn devices_returns_nodes_paired_and_pending() {
        let t = kit();
        let c = ctx(&t);
        let d = ok(&c, "ui.devices", json!({}));
        for k in ["nodes", "paired", "pending"] {
            assert!(d[k].is_array(), "{k} must be an array: {d}");
        }
        assert_eq!(ok(&c, "ui.devices.remove", json!({"id": "nope"}))["removed"], false);
    }

    #[test]
    fn devices_rename_approve_reject_change_state() {
        let t = kit();
        let c = ctx(&t);
        let id = format!("ui-node-{}", std::process::id());
        let code = seagent_app::node::request_pairing(&id, "pixel", "android", &"ab".repeat(32)).unwrap();
        let has = |d: &Value, key: &str, field: &str, want: &str| d[key].as_array().is_some_and(|a| a.iter().any(|n| n[field] == want));
        // The Devices page lists the request; nothing is paired yet.
        let d = ok(&c, "ui.devices", json!({}));
        assert!(has(&d, "pending", "code", &code) && has(&d, "pending", "name", "pixel"), "{d}");
        assert!(!has(&d, "paired", "id", &id), "{d}");

        // Approve: the request leaves the queue and the device shows up as paired.
        assert_eq!(ok(&c, "ui.devices.approve", json!({"code": code}))["approved"], id);
        let d = ok(&c, "ui.devices", json!({}));
        assert!(!has(&d, "pending", "code", &code), "{d}");
        assert!(has(&d, "paired", "id", &id) && has(&d, "paired", "name", "pixel"), "{d}");

        // Rename stores the operator's name (trimmed and length-capped by the handler).
        assert_eq!(ok(&c, "ui.devices.rename", json!({"id": id, "name": "  kitchen tablet  "}))["name"], "kitchen tablet");
        assert!(has(&ok(&c, "ui.devices", json!({})), "paired", "name", "kitchen tablet"));

        // Error cases: an unknown device, an empty name, and a code that was already used.
        assert_eq!(err(&c, "ui.devices.rename", json!({"id": "no-such-node", "name": "x"})).0, -32001);
        assert_eq!(err(&c, "ui.devices.rename", json!({"id": id, "name": "   "})).0, -32602);
        let (num, msg) = err(&c, "ui.devices.approve", json!({"code": code}));
        assert_eq!(num, -32001);
        assert!(msg.contains("no pending node"), "{msg}");
        assert_eq!(err(&c, "ui.devices.approve", json!({"code": "ZZZZZZZZ"})).0, -32001);

        // Reject: a second request disappears without pairing anything (and is idempotent).
        let other = format!("{id}-2");
        let code2 = seagent_app::node::request_pairing(&other, "old tablet", "ipados", &"cd".repeat(32)).unwrap();
        assert_eq!(ok(&c, "ui.devices.reject", json!({"code": code2}))["rejected"], true);
        let d = ok(&c, "ui.devices", json!({}));
        assert!(!has(&d, "pending", "code", &code2) && !has(&d, "paired", "id", &other), "{d}");
        assert_eq!(ok(&c, "ui.devices.reject", json!({"code": code2}))["rejected"], false);
        assert_eq!(err(&c, "ui.devices.approve", json!({"code": code2})).0, -32001, "a rejected code cannot be approved");
        // Leave the registry as this test found it.
        assert_eq!(ok(&c, "ui.devices.remove", json!({"id": id}))["removed"], true);
    }

    #[test]
    fn uploads_are_private_and_reject_traversal() {
        let t = kit();
        let c = ctx(&t);
        let u = ok(&c, "ui.upload", json!({"name": "shot.png", "data": png_data()}));
        let path = PathBuf::from(u["path"].as_str().unwrap());
        assert!(path.starts_with(uploads_dir(&c)) && path.is_file());
        assert_eq!(modified_mode(&path), 0o600);
        assert_eq!((u["name"].as_str(), u["mime"].as_str()), (Some("shot.png"), Some("image/png")));
        assert!(u["bytes"].as_u64().unwrap() > 0);
        assert!(path.file_name().unwrap().to_string_lossy().ends_with("-shot.png"));
        // Traversal and separators are refused outright.
        for n in ["../../etc/passwd", "..\\..\\etc\\passwd", ".bashrc", "dir/file.txt"] {
            let (code, msg) = err(&c, "ui.upload", json!({"name": n, "data": png_data()}));
            assert_eq!(code, -32602);
            assert!(msg.contains("plain file name"), "{n}: {msg}");
        }
        assert!(!Path::new("/etc/passwd.seagent-test").exists());
        // Size cap.
        let big = seagent_net::crypto::b64(&vec![0u8; MAX_UPLOAD_BYTES + 1]);
        let (code, msg) = err(&c, "ui.upload", json!({"name": "big.bin", "data": big}));
        assert_eq!(code, -32602);
        assert!(msg.contains("8 MiB"), "{msg}");
        // Deletion is confined to the uploads directory.
        let outside = t.ws.join("secret.txt");
        std::fs::write(&outside, "x").unwrap();
        let (code, msg) = err(&c, "ui.upload.delete", json!({"path": outside.display().to_string()}));
        assert_eq!(code, -32001);
        assert!(msg.contains("uploads directory"), "{msg}");
        assert!(outside.exists());
        assert_eq!(ok(&c, "ui.upload.delete", json!({"path": u["path"]}))["removed"], true);
        assert!(!path.exists());
        assert_eq!(err(&c, "ui.upload.delete", json!({"path": u["path"]})).0, -32001);
    }

    #[test]
    fn submit_queues_a_turn_with_attachment_blocks() {
        let t = kit();
        let c = ctx(&t);
        let sid = t.k.create_session(&t.ws, None, None, None).unwrap();
        let img = ok(&c, "ui.upload", json!({"name": "shot.png", "data": png_data()}));
        let txt = ok(&c, "ui.upload", json!({"name": "notes.txt", "data": seagent_net::crypto::b64(b"hello notes")}));
        let blob = ok(&c, "ui.upload", json!({"name": "screenshot", "data": png_data()}));
        let r = ok(&c, "ui.submit", json!({"id": sid, "text": "look at this", "uploads": [img["path"], txt["path"], blob["path"]]}));
        assert_eq!((r["queued"].as_bool(), r["started"].as_bool(), r["blocks"].as_u64()), (Some(true), Some(true), Some(2)), "both pngs become image blocks ({r})");
        // Wait for the turn the method started (the thread may not have registered yet).
        let mut v = seagent_kernel::projection::project(&t.k.store.read(&sid).unwrap());
        for _ in 0..500 {
            v = seagent_kernel::projection::project(&t.k.store.read(&sid).unwrap());
            if !t.k.is_running(&sid) && v.messages.iter().any(|m| m.role == seagent_core::Role::User) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let user = v.messages.iter().find(|m| m.role == seagent_core::Role::User).expect("the submitted message is in the history");
        let text = user.text();
        assert!(text.contains("look at this"), "{text}");
        assert!(text.contains("[attached: notes.txt]"), "{text}");
        assert_eq!(user.content.iter().filter(|b| matches!(b, seagent_core::Block::Image { media_type, .. } if media_type == "image/png")).count(), 2, "image blocks missing: {:?}", user.content);
        // Bad input.
        assert_eq!(err(&c, "ui.submit", json!({"text": "hi"})).0, -32602);
        assert_eq!(err(&c, "ui.submit", json!({"id": "missing", "text": "hi"})).0, -32001);
        let many: Vec<String> = (0..MAX_UPLOADS + 1).map(|_| img["path"].as_str().unwrap().to_string()).collect();
        assert_eq!(err(&c, "ui.submit", json!({"id": sid, "text": "x", "uploads": many})).0, -32602);
    }

    #[test]
    fn logs_lists_files_and_filters() {
        let t = kit();
        let c = ctx(&t);
        let dir = crate::ops::logs::dir(&t.paths);
        std::fs::create_dir_all(&dir).unwrap();
        let mut text = String::new();
        for (i, (level, msg)) in [("info", "started up"), ("warn", "slow helper"), ("error", "boom happened"), ("info", "still fine"), ("error", "boom again")].iter().enumerate() {
            text.push_str(&serde_json::json!({"ts": 1_000 + i as u64, "level": level, "session": "", "kind": "turn", "msg": msg}).to_string());
            text.push('\n');
        }
        std::fs::write(dir.join("seagent.jsonl"), &text).unwrap();
        let l = ok(&c, "ui.logs", json!({}));
        let files = l["files"].as_array().unwrap();
        let f = files.iter().find(|f| f["name"] == "seagent.jsonl").expect("log file listed");
        assert!(f["bytes"].as_u64().unwrap() > 0 && f["path"].as_str().unwrap().ends_with("seagent.jsonl"));
        assert_eq!(l["tail"].as_array().unwrap().len(), 5);
        assert_eq!(l["tail"][0]["target"], "turn");
        let errs = ok(&c, "ui.logs", json!({"level": "error"}));
        let tail = errs["tail"].as_array().unwrap();
        assert_eq!(tail.len(), 2);
        assert!(tail.iter().all(|r| r["level"] == "error"));
        assert_eq!(ok(&c, "ui.logs", json!({"limit": 2}))["tail"].as_array().unwrap().len(), 2);
        let g = ok(&c, "ui.logs", json!({"grep": "BOOM AGAIN"}));
        assert_eq!(g["tail"].as_array().unwrap().len(), 1);
        assert_eq!(g["tail"][0]["text"], "boom again");
        assert_eq!(ok(&c, "ui.logs", json!({"since": "1h"}))["tail"].as_array().unwrap().len(), 0, "records older than the window drop out");
        assert_eq!(ok(&c, "ui.logs.files", json!({}))["files"].as_array().unwrap().len(), 1);
        assert_eq!(err(&c, "ui.logs", json!({"file": "../secrets.toml"})).0, -32602);
        // The daemon's stderr log is listed and readable too.
        std::fs::write(t.paths.daemon_log(), "seagentd: channel tg: reply failed: x\n").unwrap();
        let l = ok(&c, "ui.logs", json!({"file": "seagentd.log"}));
        assert_eq!(l["tail"][0]["target"], "seagentd");
        assert_eq!(l["tail"][0]["level"], "error");
    }

    #[test]
    fn every_listed_method_is_dispatched() {
        let t = kit();
        let c = ctx(&t);
        for m in METHODS {
            assert!(call(&c, m, &json!({})).is_some(), "{m} is listed but `call()` does not dispatch it");
        }
        assert!(call(&c, "ui.nope", &json!({})).is_none());
        assert!(METHODS.contains(&"ui.models.list") && METHODS.contains(&"ui.submit") && METHODS.contains(&"ui.devices"));
    }
}
