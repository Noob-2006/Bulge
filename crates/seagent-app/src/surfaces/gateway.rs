//! `gateway`: read and patch seagent's config, look up its schema, restart the daemon and run
//! an update (OpenClaw src/agents/tools/gateway-tool.ts, MIT).
//!
//! Safety guards: patches go to the user config only, need the `baseHash` of the file they
//! were written against, are validated by loading the result before anything is written,
//! and may not touch the gates, trusted projects, hooks or this tool's own settings.
//! `update.run` is refused for sessions that came from a channel chat (only the owner at
//! the machine or an operator schedule may update) and never runs model-supplied commands.

use super::{now_ms, read_json, write_atomic, write_json, Env};
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use seagent_kernel::config::Config;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const MAX_GET_CHARS: usize = 12_000;
/// Largest whole-config document `config.apply` accepts (OpenClaw `config.apply` raw).
/// Anything bigger is an edit to make in the file, not through a tool call.
const MAX_APPLY_CHARS: usize = 256 * 1024;
const SCHEMA_NOT_FOUND: &str = "config schema path not found";
/// Keys the agent may not change through the tool.
const PROTECTED: &[&str] = &["gate", "trusted_projects", "hooks", "surfaces.gateway", "compliance"];

fn yes() -> bool {
    true
}

/// `[surfaces.gateway]`
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayConfig {
    /// Offer config.get / config.schema.lookup. Default true.
    #[serde(default = "yes")]
    pub allow_config_reads: bool,
    /// Offer config.patch (still gated as a write to the config file). Default true.
    #[serde(default = "yes")]
    pub allow_config_patch: bool,
    /// argv for update.run. Default: `<this seagent binary> update`.
    pub update_command: Vec<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        GatewayConfig { allow_config_reads: true, allow_config_patch: true, update_command: vec![] }
    }
}

pub struct GatewayTool(pub Arc<Env>);

fn file_hash(p: &Path) -> String {
    seagent_net::crypto::hex(&seagent_net::crypto::sha256(&std::fs::read(p).unwrap_or_default()))
}

fn to_json(v: &toml::Value) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

fn get_path<'a>(mut v: &'a Value, path: &str) -> Option<&'a Value> {
    let norm = path.trim().replace('[', ".").replace(']', "");
    let parts: Vec<&str> = norm.split('.').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    for p in parts {
        v = match v {
            Value::Object(o) => o.get(p)?,
            Value::Array(a) => a.get(p.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(v)
}

fn type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_f64() => "number",
        Value::Number(_) => "integer",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Free-form tables: any key below them is valid.
const OPEN_TABLES: &[&str] = &["providers", "prices", "mcp", "plugins", "channels", "acp", "app", "surfaces"];

/// Schema facts for one dotted key, derived from the built-in defaults.
pub fn schema_lookup(path: &str) -> Option<Value> {
    let def = to_json(&toml::Value::try_from(Config::default()).ok()?);
    let p = path.trim().trim_matches('.');
    if p.is_empty() {
        return Some(json!({"path": "", "type": "object", "children": def.as_object().map(|o| o.keys().cloned().collect::<Vec<_>>())}));
    }
    match get_path(&def, p) {
        Some(v) => {
            let mut out = json!({"path": p, "type": type_name(v), "default": v});
            if let Some(o) = v.as_object() {
                out["children"] = json!(o.keys().collect::<Vec<_>>());
                out.as_object_mut().unwrap().remove("default");
            }
            if OPEN_TABLES.contains(&p.split('.').next().unwrap_or("")) {
                out["freeForm"] = true.into();
            }
            Some(out)
        }
        None => {
            let top = p.split('.').next().unwrap_or("");
            OPEN_TABLES.contains(&top).then(|| json!({"path": p, "type": "any", "freeForm": true, "note": format!("[{top}] entries are parsed by their own component")}))
        }
    }
}

fn protected(path: &str) -> Option<&'static str> {
    PROTECTED.iter().find(|k| path == **k || path.starts_with(&format!("{k}."))).copied()
}

/// Flatten a patch table into dotted keys (to check protected paths).
fn keys_of(t: &toml::Table, prefix: &str, out: &mut Vec<String>) {
    for (k, v) in t {
        let p = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        out.push(p.clone());
        if let toml::Value::Table(sub) = v {
            keys_of(sub, &p, out);
        }
    }
}

fn merge(base: &mut toml::Table, over: toml::Table) {
    for (k, v) in over {
        match (base.get_mut(&k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            (_, v) => {
                base.insert(k, v);
            }
        }
    }
}

/// JSON merge patch (null deletes) into TOML.
fn json_merge(base: &mut toml::Table, patch: &serde_json::Map<String, Value>) -> Result<(), String> {
    for (k, v) in patch {
        match v {
            Value::Null => {
                base.remove(k);
            }
            Value::Object(o) => {
                let e = base.entry(k.clone()).or_insert_with(|| toml::Value::Table(toml::Table::new()));
                if !e.is_table() {
                    *e = toml::Value::Table(toml::Table::new());
                }
                json_merge(e.as_table_mut().unwrap(), o)?;
            }
            v => {
                let tv: toml::Value = serde_json::from_value(v.clone()).map_err(|e| format!("`{k}`: {e}"))?;
                base.insert(k.clone(), tv);
            }
        }
    }
    Ok(())
}

fn patch_keys(p: &serde_json::Map<String, Value>, prefix: &str, out: &mut Vec<String>) {
    for (k, v) in p {
        let path = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        out.push(path.clone());
        if let Value::Object(o) = v {
            patch_keys(o, &path, out);
        }
    }
}

/// Dotted keys whose value differs between `old` and `new` (raised, changed or removed).
fn changed_keys(old: &toml::Table, new: &toml::Table, prefix: &str, out: &mut Vec<String>) {
    for (k, v) in new {
        let p = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
        match (old.get(k), v) {
            (Some(toml::Value::Table(o)), toml::Value::Table(n)) => changed_keys(o, n, &p, out),
            (Some(o), n) if o == n => {}
            _ => out.push(p),
        }
    }
    for k in old.keys() {
        if !new.contains_key(k) {
            out.push(if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") });
        }
    }
}

/// `config.apply` takes the whole config the way `config.get` shows it: TOML, or JSON
/// (what a UI sends back). Anything that is not one table is refused.
fn parse_apply_raw(raw: &str) -> Result<toml::Table, String> {
    let toml_err = match raw.parse::<toml::Table>() {
        Ok(t) => return Ok(t),
        Err(e) => e,
    };
    let v: Value = serde_json::from_str(raw).map_err(|e| format!("raw is not valid TOML ({toml_err}) or JSON ({e})"))?;
    if !v.is_object() {
        return Err("raw must be a config object (the whole config), not a scalar or list".into());
    }
    serde_json::from_value(v).map_err(|e| format!("raw is not a TOML-compatible config object: {e}"))
}

/// Where the restart notice waits for the next daemon start.
fn sentinel(env: &Env) -> PathBuf {
    env.dir.join("gateway/restart.json")
}

/// The daemon's own command line (`seagent daemon run …`), if this process is seagentd.
fn daemon_args() -> Option<Vec<String>> {
    let a: Vec<String> = std::env::args().collect();
    let i = a.windows(2).position(|w| w[0] == "daemon" && w[1] == "run")?;
    Some(a[i + 2..].to_vec())
}

/// The shell line that restarts seagentd (systemd unit, or stop + start of this binary).
pub fn restart_command() -> Result<String, String> {
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    if std::env::var_os("INVOCATION_ID").is_some() && std::env::var("SYSTEMD_UNIT").map(|u| u.contains("seagentd")).unwrap_or(true) {
        return Ok("sleep 2; systemctl --user restart seagentd.service".into());
    }
    let rest = daemon_args().ok_or("restart applies to the seagent daemon (seagentd); this session is not running inside it")?;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?.display().to_string();
    Ok(format!("sleep 2; {e} daemon stop; {e} daemon start {}", rest.iter().map(|s| quote(s)).collect::<Vec<_>>().join(" "), e = quote(&exe)))
}

fn spawn_detached(line: &str) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c").arg(line).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    cmd.spawn().map(|_| ()).map_err(|e| format!("restart: {e}"))
}

fn update_argv(env: &Env) -> Result<Vec<String>, String> {
    if !env.cfg.gateway.update_command.is_empty() {
        return Ok(env.cfg.gateway.update_command.clone());
    }
    Ok(vec![std::env::current_exe().map_err(|e| e.to_string())?.display().to_string(), "update".into()])
}

/// After a restart: deliver the pending notice to the session (and its chat).
pub fn deliver_restart_notice(env: &Env) {
    let p = sentinel(env);
    let Some(v) = read_json::<Value>(&p) else { return };
    let _ = std::fs::remove_file(&p);
    let session = v["session"].as_str().unwrap_or("");
    let text = format!("seagent daemon restarted ({}){}", v["reason"].as_str().unwrap_or("restart"), v["note"].as_str().filter(|n| !n.is_empty()).map(|n| format!(": {n}")).unwrap_or_default());
    if let Some((ch, chat, thread, _)) = env.route_of(session) {
        if let Some(c) = env.channels.get(&ch) {
            let _ = c.send(&seagent_channel::Outbound { chat, text: text.clone(), thread, ..Default::default() });
        }
    }
    if let (Ok(k), false) = (env.kernel(), session.is_empty()) {
        let _ = k.submit(session, &format!("[notice] {text}"), "gateway");
    }
}

impl GatewayTool {
    fn project_config(ctx: &ToolCtx) -> PathBuf {
        seagent_kernel::config::project_config(&ctx.workspace)
    }

    /// Load the candidate config the way seagent would, before anything is written.
    fn validate(env: &Env, ctx: &ToolCtx, text: &str, what: &str) -> Result<(), String> {
        let probe = env.dir.join(format!("gateway/probe-{}.toml", seagent_net::crypto::random_token(6)));
        write_atomic(&probe, text.as_bytes())?;
        let checked = Config::load(Some(&probe), Some(&Self::project_config(ctx)), &[]);
        let _ = std::fs::remove_file(&probe);
        checked.map(|_| ()).map_err(|e| format!("{what} config is invalid, nothing written: {e}"))
    }

    fn run(&self, ctx: &ToolCtx, p: &Value) -> Result<Value, String> {
        let env = &self.0;
        let g = &env.cfg.gateway;
        let action = p["action"].as_str().ok_or("action required")?;
        match action {
            "config.get" if g.allow_config_reads => {
                let cfg = Config::load(Some(&env.user_config), Some(&Self::project_config(ctx)), &[])?;
                let mut text = toml::to_string(&cfg).map_err(|e| e.to_string())?;
                if let Ok(k) = env.kernel() {
                    text = k.vault.redact(&text);
                }
                let full: toml::Value = text.parse::<toml::Table>().map(toml::Value::Table).map_err(|e| e.to_string())?;
                let full = to_json(&full);
                let hash = file_hash(&env.user_config);
                let result = match p["path"].as_str().filter(|s| !s.trim().is_empty()) {
                    Some(path) => {
                        let v = get_path(&full, path).ok_or_else(|| format!("config path not found: {path}"))?;
                        json!({"hash": hash, "path": path, "config": v})
                    }
                    None => json!({"hash": hash, "path": env.user_config, "config": full}),
                };
                let payload = json!({"ok": true, "result": result});
                if serde_json::to_string_pretty(&payload).unwrap_or_default().len() > MAX_GET_CHARS {
                    if p["path"].as_str().is_some_and(|s| !s.trim().is_empty()) {
                        return Err("config.get response is too large; use path to request a narrower config subtree".into());
                    }
                    // The whole config outgrew one tool result: still hand back the hash (needed
                    // for config.patch / config.apply) and the top-level keys to narrow with `path`.
                    let keys: Vec<&String> = full.as_object().map(|o| o.keys().collect()).unwrap_or_default();
                    return Ok(json!({"ok": true, "result": {"hash": hash, "path": env.user_config, "truncated": true, "keys": keys,
                        "message": "config.get response is too large; use path to request a narrower config subtree"}}));
                }
                Ok(payload)
            }
            "config.schema.lookup" if g.allow_config_reads => {
                let path = p["path"].as_str().ok_or("path required")?;
                Ok(match schema_lookup(path) {
                    Some(r) => json!({"ok": true, "result": r}),
                    None => json!({"ok": false, "code": "schema_path_not_found", "path": path, "message": SCHEMA_NOT_FOUND}),
                })
            }
            "config.patch" if g.allow_config_patch => {
                let base = p["baseHash"].as_str().ok_or("baseHash required: read it with config.get first")?;
                let path = &env.user_config;
                let cur_text = std::fs::read_to_string(path).unwrap_or_default();
                let cur_hash = file_hash(path);
                if base != cur_hash {
                    return Ok(json!({"ok": false, "code": "conflict", "message": "the config changed since config.get; read it again and retry", "hash": cur_hash}));
                }
                let mut table: toml::Table = cur_text.parse().map_err(|e| format!("{}: {e}", path.display()))?;
                let mut keys = Vec::new();
                match (p["raw"].as_str(), p["patch"].as_object()) {
                    (Some(raw), None) => {
                        let over: toml::Table = raw.parse().map_err(|e| format!("raw is not valid TOML: {e}"))?;
                        keys_of(&over, "", &mut keys);
                        if let Some(k) = keys.iter().find_map(|k| protected(k)) {
                            return Err(format!("`{k}` cannot be changed through the gateway tool; edit the config yourself"));
                        }
                        merge(&mut table, over);
                    }
                    (None, Some(obj)) => {
                        patch_keys(obj, "", &mut keys);
                        if let Some(k) = keys.iter().find_map(|k| protected(k)) {
                            return Err(format!("`{k}` cannot be changed through the gateway tool; edit the config yourself"));
                        }
                        json_merge(&mut table, obj)?;
                    }
                    _ => return Err("config.patch needs exactly one of raw (TOML) or patch (JSON merge patch)".into()),
                }
                let new_text = toml::to_string_pretty(&table).map_err(|e| e.to_string())?;
                Self::validate(env, ctx, &new_text, "patched")?;
                write_atomic(path, new_text.as_bytes())?;
                Ok(json!({"ok": true, "path": path, "changed": keys, "hash": file_hash(path), "note": "takes effect for new sessions; restart the daemon to apply it to channels and the app server"}))
            }
            "config.apply" if g.allow_config_patch => {
                // A full replacement (OpenClaw `config.apply`): the config as a whole, not a delta.
                let raw = p["raw"].as_str().ok_or("raw required: the whole config as TOML or JSON (config.get shows it)")?;
                if raw.trim().is_empty() {
                    return Err("raw must not be empty; config.apply replaces the whole config".into());
                }
                if raw.len() > MAX_APPLY_CHARS {
                    return Err(format!("config.apply raw is {} bytes, over the {MAX_APPLY_CHARS}-byte limit; edit the config file directly instead", raw.len()));
                }
                let base = p["baseHash"].as_str().ok_or("baseHash required: read it with config.get first")?;
                let path = &env.user_config;
                let cur_hash = file_hash(path);
                if base != cur_hash {
                    return Ok(json!({"ok": false, "code": "conflict", "message": "the config changed since config.get; read it again and retry", "hash": cur_hash}));
                }
                let cur_text = std::fs::read_to_string(path).unwrap_or_default();
                let cur: toml::Table = cur_text.parse().map_err(|e| format!("{}: {e}", path.display()))?;
                let table = parse_apply_raw(raw)?;
                let mut keys = Vec::new();
                changed_keys(&cur, &table, "", &mut keys);
                if let Some(k) = keys.iter().find_map(|k| protected(k)) {
                    return Err(format!("`{k}` cannot be changed through the gateway tool; edit the config yourself"));
                }
                let new_text = toml::to_string_pretty(&table).map_err(|e| e.to_string())?;
                Self::validate(env, ctx, &new_text, "applied")?;
                write_atomic(path, new_text.as_bytes())?;
                Ok(json!({"ok": true, "path": path, "changed": keys, "hash": file_hash(path), "note": "takes effect for new sessions; restart the daemon to apply it to channels and the app server"}))
            }
            "restart" => {
                let line = restart_command()?;
                write_json(&sentinel(env), &json!({"session": ctx.session_id, "note": p["note"], "reason": "restart", "at": now_ms()}))?;
                spawn_detached(&line)?;
                Ok(json!({"ok": true, "restarting": true, "message": "seagentd restarts in about 2 seconds; a completion notice follows"}))
            }
            "update.run" => {
                if let Some((ch, _, _, sender)) = env.route_of(&ctx.session_id) {
                    return Ok(json!({"ok": false, "code": "owner_required", "reason": "owner_required", "message": format!("No owner authorizes this update: the session came from channel `{ch}`{}. Run it from the machine (seagent chat / web UI) or an operator schedule.", sender.map(|s| format!(" (sender {s})")).unwrap_or_default())}));
                }
                let argv = update_argv(env)?;
                let out = std::process::Command::new(&argv[0]).args(&argv[1..]).stdin(std::process::Stdio::null()).output().map_err(|e| format!("{}: {e}", argv[0]))?;
                let tail = |b: &[u8]| String::from_utf8_lossy(b).lines().rev().take(20).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("\n");
                if !out.status.success() {
                    return Ok(json!({"ok": false, "code": "update_failed", "status": out.status.code(), "stdout": tail(&out.stdout), "stderr": tail(&out.stderr)}));
                }
                let restart = restart_command().ok();
                if let Some(line) = &restart {
                    write_json(&sentinel(env), &json!({"session": ctx.session_id, "note": p["note"], "reason": "update", "at": now_ms()}))?;
                    spawn_detached(line)?;
                }
                Ok(json!({"ok": true, "updated": true, "stdout": tail(&out.stdout), "restarting": restart.is_some()}))
            }
            a if matches!(a, "config.get" | "config.schema.lookup" | "config.patch" | "config.apply") => Err(format!("Action not available: {a}")),
            other => Err(format!("Unknown action: {other}")),
        }
    }
}

impl Tool for GatewayTool {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "gateway".into(),
            description: "Read seagent's effective config (config.get {path?}; secrets stay redacted; returns `hash`) and its schema (config.schema.lookup {path}); config.patch {baseHash, raw TOML | patch JSON-merge} merges into the user config and config.apply {baseHash, raw} replaces the whole config (TOML or JSON, up to 256 KiB); both are gated by allow_config_patch and validate the result first (gates, trusted projects, hooks and compliance are off limits); restart restarts the seagent daemon with a completion notice; update.run updates seagent on an explicit owner request, then restarts. Never do these via shell.".into(),
            input_schema: json!({"type": "object", "properties": {
                "action": {"type": "string", "enum": ["config.get", "config.schema.lookup", "config.patch", "config.apply", "restart", "update.run"]},
                "path": {"type": "string", "description": "Dotted key: optional for config.get, required for config.schema.lookup."},
                "baseHash": {"type": "string", "description": "config.patch / config.apply: the hash config.get returned."},
                "raw": {"type": "string", "description": "config.patch: TOML fragment merged into the user config. config.apply: the whole config, as TOML or JSON."},
                "patch": {"type": "object", "description": "config.patch: JSON merge patch (null deletes a key)."},
                "note": {"type": "string", "description": "Short human note for the restart notice."}
            }, "required": ["action"]}),
            parallel_safe: false,
            idempotent: false,
            pinned: false,
        }
    }
    fn effects(&self, _ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        match input["action"].as_str() {
            Some("config.get") | Some("config.schema.lookup") => vec![Effect::Read { path: self.0.user_config.clone() }],
            Some("config.patch") | Some("config.apply") => vec![Effect::Write { path: self.0.user_config.clone() }],
            Some("restart") => vec![Effect::Exec { command: restart_command().unwrap_or_else(|_| "systemctl --user restart seagentd.service".into()) }],
            Some("update.run") => {
                let argv = update_argv(&self.0).unwrap_or_default();
                vec![Effect::Exec { command: format!("{}; {}", argv.join(" "), restart_command().unwrap_or_default()) }]
            }
            _ => vec![],
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        match self.run(ctx, &input) {
            Ok(v) => {
                let text = serde_json::to_string_pretty(&v).unwrap_or_default();
                if v["ok"] == false { ToolOutput { content: text, is_error: true, ui_resource: None } } else { ToolOutput::ok(text) }
            }
            Err(e) => ToolOutput::err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit;
    use super::*;

    #[test]
    fn get_lookup_and_guarded_patch() {
        let (env, _) = testkit::env("gw", &[], "");
        let t = GatewayTool(env.clone());
        let ws = testkit::temp("gw-ws");
        let ctx = testkit::ctx(&env, &ws);
        assert!(matches!(&t.effects(&ctx, &json!({"action": "config.patch"}))[0], Effect::Write { path } if *path == env.user_config));
        let o = t.call(&ctx, json!({"action": "config.get", "path": "model.default"}));
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!(v["result"]["config"], "fake/m");
        let hash = v["result"]["hash"].as_str().unwrap().to_string();
        assert!(t.call(&ctx, json!({"action": "config.get", "path": "nope.x"})).content.contains("config path not found"));
        assert!(t.call(&ctx, json!({"action": "config.schema.lookup", "path": "runner.max_steps_per_turn"})).content.contains("\"type\": \"integer\""));
        let nf = t.call(&ctx, json!({"action": "config.schema.lookup", "path": "bogus.key"}));
        assert!(nf.is_error && nf.content.contains("schema_path_not_found"));
        assert!(t.call(&ctx, json!({"action": "config.schema.lookup", "path": "channels.tg.token"})).content.contains("freeForm"));
        // Guards.
        assert!(t.call(&ctx, json!({"action": "config.patch", "raw": "identity = \"x\""})).content.contains("baseHash required"));
        assert!(t.call(&ctx, json!({"action": "config.patch", "baseHash": "00", "raw": "identity = \"x\""})).content.contains("conflict"));
        assert!(t.call(&ctx, json!({"action": "config.patch", "baseHash": hash, "raw": "[gate]\negress = \"allow\""})).content.contains("`gate` cannot be changed"));
        assert!(t.call(&ctx, json!({"action": "config.patch", "baseHash": hash, "patch": {"surfaces": {"gateway": {"allow_config_patch": true}}}})).content.contains("surfaces.gateway"));
        assert!(t.call(&ctx, json!({"action": "config.patch", "baseHash": hash, "raw": "[runner]\nmax_steps_per_turn = 0"})).content.contains("nothing written"));
        let o = t.call(&ctx, json!({"action": "config.patch", "baseHash": hash, "patch": {"identity": "Be brief.", "runner": {"max_steps_per_turn": 40}}}));
        assert!(!o.is_error, "{}", o.content);
        let cfg = Config::load(Some(&env.user_config), None, &[]).unwrap();
        assert_eq!((cfg.identity.as_str(), cfg.runner.max_steps_per_turn), ("Be brief.", 40));
        assert_eq!(cfg.model.default, "fake/m", "untouched keys survive");
        // A second patch with the stale hash conflicts.
        assert!(t.call(&ctx, json!({"action": "config.patch", "baseHash": hash, "raw": "identity = \"y\""})).content.contains("conflict"));
    }

    #[test]
    fn apply_replaces_the_whole_config_behind_the_same_guards() {
        let (env, _) = testkit::env("gwapply", &[], "");
        let t = GatewayTool(env.clone());
        let ws = testkit::temp("gwapply-ws");
        let ctx = testkit::ctx(&env, &ws);
        assert!(matches!(&t.effects(&ctx, &json!({"action": "config.apply"}))[0], Effect::Write { path } if *path == env.user_config));
        let ok_get: Value = serde_json::from_str(&t.call(&ctx, json!({"action": "config.get"})).content).unwrap();
        let hash = ok_get["result"]["hash"].as_str().unwrap().to_string();
        let whole = "identity = \"Whole config, TOML.\"\n[model]\ndefault = \"fake/m\"\naux = \"fake/aux\"\n[surfaces]\n";
        // Guards: needs a baseHash, a non-empty document and a small one.
        assert!(t.call(&ctx, json!({"action": "config.apply", "raw": whole})).content.contains("baseHash required"));
        assert!(t.call(&ctx, json!({"action": "config.apply", "baseHash": hash, "raw": "  "})).content.contains("must not be empty"));
        assert!(t.call(&ctx, json!({"action": "config.apply", "baseHash": "00", "raw": whole})).content.contains("conflict"));
        let big = format!("identity = \"{}\"", "a".repeat(MAX_APPLY_CHARS));
        let o = t.call(&ctx, json!({"action": "config.apply", "baseHash": hash, "raw": big}));
        assert!(o.is_error && o.content.contains(&format!("over the {MAX_APPLY_CHARS}-byte limit")), "{}", o.content);
        // Protected keys are off limits whether they are added, changed or dropped.
        let o = t.call(&ctx, json!({"action": "config.apply", "baseHash": hash, "raw": "[gate]\negress = \"allow\"\n[model]\ndefault = \"fake/m\""}));
        assert!(o.is_error && o.content.contains("`gate` cannot be changed"), "{}", o.content);
        let o = t.call(&ctx, json!({"action": "config.apply", "baseHash": hash, "raw": "[hooks]\nenabled = true\n[model]\ndefault = \"fake/m\""}));
        assert!(o.is_error && o.content.contains("`hooks` cannot be changed"), "{}", o.content);
        let (with_gate, _) = testkit::env("gwapply2", &[], "");
        std::fs::write(&with_gate.user_config, "[model]\ndefault = \"fake/m\"\n[gate]\nprivilege = \"ask\"\n").unwrap();
        let t2 = GatewayTool(with_gate.clone());
        let gctx = testkit::ctx(&with_gate, &ws);
        let h2: Value = serde_json::from_str(&t2.call(&gctx, json!({"action": "config.get"})).content).unwrap();
        let h2 = h2["result"]["hash"].as_str().unwrap().to_string();
        // Replacing the config without the gate table would silently drop it.
        let o = t2.call(&gctx, json!({"action": "config.apply", "baseHash": h2, "raw": "[model]\ndefault = \"fake/m\""}));
        assert!(o.is_error && o.content.contains("`gate` cannot be changed"), "{}", o.content);
        // The replacement is validated as seagent would load it, before anything is written.
        let before = std::fs::read_to_string(&env.user_config).unwrap();
        assert!(t.call(&ctx, json!({"action": "config.apply", "baseHash": hash, "raw": "[runner]\nmax_steps_per_turn = 0"})).content.contains("nothing written"));
        assert_eq!(std::fs::read_to_string(&env.user_config).unwrap(), before);
        // TOML.
        let o = t.call(&ctx, json!({"action": "config.apply", "baseHash": hash, "raw": whole}));
        assert!(!o.is_error, "{}", o.content);
        let v: Value = serde_json::from_str(&o.content).unwrap();
        assert_eq!(v["changed"], json!(["identity"]), "only the real edit is reported: {v}");
        let new_hash = v["hash"].as_str().unwrap().to_string();
        assert_ne!(new_hash, hash);
        let cfg = Config::load(Some(&env.user_config), None, &[]).unwrap();
        assert_eq!((cfg.identity.as_str(), cfg.model.default.as_str()), ("Whole config, TOML.", "fake/m"));
        // JSON (a UI echoing the config back), then the stale hash conflicts.
        let json_raw = json!({"model": {"default": "fake/m", "aux": "fake/aux"}, "identity": "Whole config, JSON."}).to_string();
        let o = t.call(&ctx, json!({"action": "config.apply", "baseHash": new_hash, "raw": json_raw}));
        assert!(!o.is_error, "{}", o.content);
        assert_eq!(Config::load(Some(&env.user_config), None, &[]).unwrap().identity, "Whole config, JSON.");
        assert!(t.call(&ctx, json!({"action": "config.apply", "baseHash": hash, "raw": whole})).content.contains("conflict"));
        // Gated like config.patch.
        let (off, _) = testkit::env("gwapply3", &[], "[gateway]\nallow_config_patch = false\n");
        let toff = GatewayTool(off.clone());
        let off_ctx = testkit::ctx(&off, &ws);
        let o = toff.call(&off_ctx, json!({"action": "config.apply", "baseHash": "00", "raw": whole}));
        assert!(o.is_error && o.content.contains("Action not available: config.apply"), "{}", o.content);
    }

    #[test]
    fn update_requires_an_owner_and_restart_needs_the_daemon() {
        let (env, _) = testkit::env("gw2", &[], "[gateway]\nupdate_command = [\"/bin/false\"]\n");
        let router = seagent_channel::router::Router::open(env.routes.clone(), Default::default());
        router.bind(&seagent_channel::router::RouteKey { channel: "tg".into(), chat: "9".into(), sender: Some("u1".into()) }, "s1");
        let t = GatewayTool(env.clone());
        let ws = testkit::temp("gw2-ws");
        let ctx = testkit::ctx(&env, &ws);
        let o = t.call(&ctx, json!({"action": "update.run"}));
        assert!(o.is_error && o.content.contains("owner_required") && o.content.contains("sender u1"), "{}", o.content);
        let mut ctx2 = ctx.clone();
        ctx2.session_id = "local".into();
        let o = t.call(&ctx2, json!({"action": "update.run"}));
        assert!(o.content.contains("update_failed"), "{}", o.content);
        if std::env::var_os("INVOCATION_ID").is_none() {
            assert!(t.call(&ctx2, json!({"action": "restart"})).content.contains("not running inside it"));
        }
        // The notice waits for the next start.
        write_json(&sentinel(&env), &json!({"session": "local", "note": "after config change", "reason": "restart"})).unwrap();
        deliver_restart_notice(&env);
        assert!(!sentinel(&env).exists());
    }
}
