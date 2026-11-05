//! OpenClaw `openclaw.plugin.json` → [`Imported`].
//!
//! The manifest is the declarative half of an OpenClaw extension: `id`, `name`,
//! `description`, `categories`, `activation.onStartup`, `cliCommands`,
//! `configSchema`/`uiHints`, `setup.providers[].envVars`, and `contracts`
//! (arbitrary keys — `webSearchProviders`, `memoryProviders`, `channelProviders`,
//! `modelProviders`, `tools`, … — collected generically, never hardcoded).
//!
//! The code half (`index.js` + `package.json`) imports `openclaw/plugin-sdk` and
//! the compiled gateway runtime, neither of which seagent ships; such a plugin gets a
//! zero-dependency Node shim speaking seagent's plugin protocol and a warning saying
//! exactly what is forwarded and what is not.

use super::{child_within, fragment, sanitize_id, secret_env, Imported, Shim};
use crate::backends::Kind;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::trim).filter(|x| !x.is_empty()).map(String::from).collect(),
        Some(Value::String(s)) => vec![s.trim().to_string()].into_iter().filter(|x| !x.is_empty()).collect(),
        _ => vec![],
    }
}

/// The capability family a `contracts.<key>` block feeds, where seagent has one.
fn contract_kind(key: &str) -> Option<String> {
    if let Some(k) = Kind::parse(key.trim_end_matches("Providers").trim_end_matches("Tools")) {
        return Some(format!("seagent `{}` backend ({})", k.as_str(), k.config_key()));
    }
    let x = key.to_ascii_lowercase();
    let mapped = if x.contains("memory") {
        "seagent memory provider (`seagent/memory.call`)"
    } else if x.contains("channel") {
        "seagent channel bridge (`seagent/channel.send`)"
    } else if x.contains("model") || x.contains("decision") || x.contains("embedding") || x.contains("usage") {
        "seagent model provider (`seagent/provider.complete`)"
    } else if x.contains("middleware") {
        "seagent middleware (`seagent/middleware`)"
    } else if x.contains("command") || x == "cli" {
        "seagent slash command / CLI (`seagent/command`, `seagent/cli`)"
    } else if x == "tools" {
        "seagent plugin tool (MCP `tools/list`)"
    } else {
        return None;
    };
    Some(mapped.to_string())
}

pub fn import(dir: &Path) -> Result<Imported, String> {
    let root = dir.canonicalize().map_err(|e| format!("{}: {e}", dir.display()))?;
    let man = root.join("openclaw.plugin.json");
    let text = fs::read_to_string(&man).map_err(|e| format!("{}: {e}", man.display()))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", man.display()))?;
    let obj = v.as_object().ok_or_else(|| format!("{}: not a JSON object", man.display()))?;
    let dir_name = root.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let id = sanitize_id(if s(&v, "id").is_empty() { dir_name } else { s(&v, "id") });
    if id.is_empty() {
        return Err(format!("{}: no usable `id`", man.display()));
    }
    let name = if s(&v, "name").is_empty() { id.clone() } else { s(&v, "name").to_string() };
    let description = s(&v, "description").to_string();
    let mut capabilities: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    for c in strings(obj.get("categories")) {
        capabilities.push(format!("category: {c}"));
    }
    let activation = obj.get("activation").and_then(Value::as_object);
    if let Some(a) = activation {
        if a.get("onStartup").and_then(Value::as_bool) == Some(true) {
            capabilities.push("activation: onStartup".into());
            warnings.push("activation.onStartup: OpenClaw starts this on gateway boot; on seagent it starts on the first session that loads the plugin.".into());
        }
        let paths = strings(a.get("onConfigPaths"));
        if !paths.is_empty() {
            capabilities.push(format!("activation onConfigPaths: {}", paths.join(", ")));
            warnings.push(format!("activation.onConfigPaths ({}): seagent has no config-path activation trigger; the plugin runs (or not) by session, not by config.", paths.join(", ")));
        }
    }

    // cliCommands: name/description/hasSubcommands → forwarded by the shim as `seagent/command`.
    let mut cli: Vec<Value> = Vec::new();
    for c in obj.get("cliCommands").and_then(Value::as_array).into_iter().flatten() {
        let n = s(c, "name");
        if n.is_empty() {
            continue;
        }
        capabilities.push(format!("cli: {n}{}", if c.get("hasSubcommands").and_then(Value::as_bool) == Some(true) { " (subcommands)" } else { "" }));
        cli.push(json!({"name": n, "description": s(c, "description")}));
    }

    // contracts: every key, generically.
    let mut contracts: Vec<Value> = Vec::new();
    if let Some(c) = obj.get("contracts").and_then(Value::as_object) {
        for (key, val) in c {
            let items = match val {
                Value::Array(_) => strings(Some(val)),
                Value::Object(m) => m.keys().cloned().collect(),
                Value::String(x) => vec![x.clone()],
                _ => vec![],
            };
            capabilities.push(format!("contracts.{key}: {}", if items.is_empty() { "-".into() } else { items.join(", ") }));
            contracts.push(json!({"key": key, "items": items}));
            if let Some(k) = contract_kind(key) {
                warnings.push(format!("contracts.{key}: the implementation lives in the OpenClaw runtime; seagent's counterpart is the {k}, which this import does not synthesise. Re-register it with an seagent plugin if you need it."));
            } else {
                warnings.push(format!("contracts.{key}: no seagent counterpart; the declaration is recorded only."));
            }
        }
    }

    // setup.providers[].envVars (and the auth-choice keys that carry env vars).
    let mut secrets: Vec<String> = Vec::new();
    if let Some(providers) = obj.get("setup").and_then(|x| x.get("providers")).and_then(Value::as_array) {
        for p in providers {
            let pid = s(p, "id");
            let envs = strings(p.get("envVars"));
            for e in &envs {
                if !secrets.contains(e) {
                    secrets.push(e.clone());
                }
            }
            if !pid.is_empty() || !envs.is_empty() {
                capabilities.push(format!("provider: {pid}{}", if envs.is_empty() { String::new() } else { format!(" (env {})", envs.join(", ")) }));
            }
        }
    }
    for k in ["providerAuthChoices", "providerUsageAuthEnvVars", "syntheticAuthRefs"] {
        for e in strings(obj.get(k)) {
            if !secrets.contains(&e) {
                secrets.push(e);
            }
        }
    }
    if !secrets.is_empty() {
        warnings.push(format!("env: {} — set them in the vault (referenced as {{{{secret:NAME}}}}); nothing is copied into config.", secrets.join(", ")));
    }

    // Skills the manifest points at (`skills: ["./skills"]`), inside the plugin only.
    let mut skills = Vec::new();
    for rel in strings(obj.get("skills")) {
        match child_within(&root, &rel) {
            Some(p) if p.is_dir() => skills.push(p),
            Some(p) => warnings.push(format!("skills `{rel}` resolves to {} which is not a directory", p.display())),
            None => warnings.push(format!("skills `{rel}` is missing or outside the plugin directory; not imported")),
        }
    }

    // MCP servers a manifest may declare (`mcpServers`, the Claude-plugin shape).
    let mcp_servers = mcp_tables(obj.get("mcpServers"));

    // Declarative vs Node.
    let entry = ["index.js", "index.mjs", "index.cjs"].iter().map(|f| root.join(f)).find(|p| p.is_file());
    let pkg = fs::read_to_string(root.join("package.json")).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
    let pkg_entry = pkg.as_ref().and_then(|p| p.get("openclaw")).and_then(|o| o.get("extensions")).map(|a| strings(Some(a))).unwrap_or_default();
    let node = entry.is_some() || !pkg_entry.is_empty() || pkg.is_some();
    let kind = if node { "node" } else { "declarative" };

    let mut shim = None;
    let mut config_toml = None;
    if node {
        let manifest = json!({
            "name": name,
            "description": description,
            "cliCommands": cli,
            "contracts": contracts,
            "categories": strings(obj.get("categories")),
            "entries": pkg_entry,
        });
        let contents = include_str!("shim/openclaw_shim.mjs")
            .replace("__ID__", &json!(id).to_string())
            .replace("__PLUGIN_DIR__", &json!(root.display().to_string()).to_string())
            .replace("__MANIFEST__", &manifest.to_string());
        let mut t = toml::Table::new();
        t.insert("command".into(), "node".into());
        t.insert("args".into(), toml::Value::Array(vec![toml::Value::String(super::SHIM_PLACEHOLDER.into())]));
        t.insert("cwd".into(), root.display().to_string().into());
        if !secrets.is_empty() {
            t.insert("env".into(), toml::Value::Table(secret_env(&secrets)));
        }
        config_toml = Some(fragment(&id, t)?);
        shim = Some(Shim { file: "openclaw_shim.mjs".into(), contents });
        warnings.push(format!("runtime: the shim loads `index.js` from {} in place; moving or deleting that directory ends the import.", root.display()));
        warnings.push("runtime: the plugin imports `openclaw/plugin-sdk` and the compiled gateway runtime; seagent provides neither. The shim speaks MCP JSON-RPC over stdio (one JSON object per line) and forwards only the manifest's CLI commands and whatever hooks/tools the entry registers through a plain `register(api)` (a failed import is caught and reported on stderr). Everything else — workers, channels, gateway methods, HTTP routes, providers, UI — is unsupported.".into());
    } else {
        warnings.push("manifest only (no index.js / package.json): imported as a declaration; nothing is started. Declared providers/channels have no seagent implementation, so enable an seagent equivalent instead.".into());
    }
    if obj.get("configSchema").is_some() || obj.get("uiHints").is_some() {
        warnings.push("configSchema/uiHints: not applied. seagent plugins are configured with TOML (`[plugins.<id>]`, `[builtin_plugins.<id>]`); the schema is kept as metadata only.".into());
    }
    if !skills.is_empty() {
        capabilities.push(format!("skills: {}", skills.len()));
    }
    for (n, _) in &mcp_servers {
        capabilities.push(format!("mcp server: {n}"));
    }

    Ok(Imported {
        id,
        name,
        idiom: "openclaw".into(),
        description,
        kind: kind.into(),
        config_toml,
        secrets,
        skills,
        mcp_servers,
        capabilities,
        warnings,
        shim,
    })
}

/// OpenClaw has no MCP manifest of its own; a package that carries `mcpServers`
/// (the Claude-plugin shape OpenClaw also accepts) is imported as `[mcp.*]`.
fn mcp_tables(v: Option<&Value>) -> Vec<(String, toml::Table)> {
    let Some(Value::Object(servers)) = v else { return vec![] };
    let mut out = Vec::new();
    for (n, e) in servers {
        let name = sanitize_id(n);
        let Some(e) = e.as_object() else { continue };
        let mut t = toml::Table::new();
        if let Some(u) = e.get("url").and_then(Value::as_str).filter(|u| !u.is_empty()) {
            t.insert("url".into(), u.to_string().into());
            if e.get("type").and_then(Value::as_str) == Some("sse") {
                t.insert("transport".into(), "sse".into());
            }
        } else if let Some(c) = e.get("command").and_then(Value::as_str).filter(|c| !c.is_empty()) {
            t.insert("command".into(), c.to_string().into());
            let args = strings(e.get("args"));
            if !args.is_empty() {
                t.insert("args".into(), toml::Value::Array(args.into_iter().map(toml::Value::String).collect()));
            }
        } else {
            continue;
        }
        if e.get("auth").and_then(Value::as_str) == Some("oauth") {
            t.insert("auth".into(), "oauth".into());
        }
        if let Some(env) = e.get("env").and_then(Value::as_object) {
            let mut et = toml::Table::new();
            for (k, v) in env {
                let raw = v.as_str().unwrap_or("");
                et.insert(k.clone(), secret_ref(raw).into());
            }
            t.insert("env".into(), toml::Value::Table(et));
        }
        if !name.is_empty() && !t.is_empty() {
            out.push((name, t));
        }
    }
    out
}

/// `${VAR}` stays a vault reference; literals are dropped rather than copied.
pub(crate) fn secret_ref(raw: &str) -> String {
    match raw.strip_prefix("${").and_then(|x| x.strip_suffix('}')) {
        Some(var) => format!("{{{{secret:{var}}}}}"),
        None => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::SHIM_PLACEHOLDER;
    use super::*;

    fn fixture(name: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat").join(name)
    }

    #[test]
    fn compat_openclaw_node_manifest_is_imported_with_a_shim() {
        let imp = import(&fixture("openclaw-node")).unwrap();
        assert_eq!(imp.id, "demo-search");
        assert_eq!(imp.name, "Demo Search");
        assert_eq!(imp.idiom, "openclaw");
        assert_eq!(imp.kind, "node");
        assert!(imp.description.contains("search"));
        assert!(imp.capabilities.iter().any(|c| c == "category: web"), "{:?}", imp.capabilities);
        assert!(imp.capabilities.iter().any(|c| c == "activation: onStartup"));
        assert!(imp.capabilities.iter().any(|c| c.starts_with("cli: demo")), "{:?}", imp.capabilities);
        // contracts are collected generically, one line per key, in whatever shape they come.
        assert!(imp.capabilities.iter().any(|c| c == "contracts.webSearchProviders: demo, demo-llm"), "{:?}", imp.capabilities);
        assert!(imp.capabilities.iter().any(|c| c == "contracts.tools: demo_search"), "{:?}", imp.capabilities);
        assert!(imp.capabilities.iter().any(|c| c == "contracts.memoryProviders: memory-core"), "{:?}", imp.capabilities);
        assert_eq!(imp.secrets, vec!["DEMO_API_KEY"]);
        let shim = imp.shim.as_ref().unwrap();
        assert_eq!(shim.file, "openclaw_shim.mjs");
        assert!(shim.contents.contains("\"demo-search\""));
        assert!(!shim.contents.contains("__MANIFEST__"));
        assert!(shim.contents.contains("openclaw/plugin-sdk"), "the warning is in Rust, the shim names the SDK it cannot load");
        let cfg = imp.config_toml.as_ref().unwrap();
        assert!(cfg.starts_with("[plugins.demo-search]"), "{cfg}");
        assert!(cfg.contains("command = \"node\"") && cfg.contains(SHIM_PLACEHOLDER), "{cfg}");
        assert!(cfg.contains("DEMO_API_KEY = \"{{secret:DEMO_API_KEY}}\""), "{cfg}");
        // configSchema has no seagent equivalent and is called out, not silently dropped.
        assert!(imp.warnings.iter().any(|w| w.contains("configSchema/uiHints")), "{:?}", imp.warnings);
        assert!(imp.warnings.iter().any(|w| w.contains("openclaw/plugin-sdk")), "{:?}", imp.warnings);
        assert!(imp.warnings.iter().any(|w| w.contains("web_search") || w.contains("webSearchProviders")), "{:?}", imp.warnings);
        assert_eq!(imp.skills.len(), 1);
        assert!(imp.skills[0].ends_with("skills"));
    }

    #[test]
    fn compat_openclaw_declarative_manifest_gets_no_shim() {
        let imp = import(&fixture("openclaw-declarative")).unwrap();
        assert_eq!(imp.kind, "declarative");
        assert!(imp.shim.is_none() && imp.config_toml.is_none());
        assert!(imp.warnings.iter().any(|w| w.contains("manifest only")), "{:?}", imp.warnings);
        assert_eq!(imp.id, "demo-channel");
        // A skills entry that escapes the plugin directory is refused, not imported.
        assert!(imp.skills.is_empty());
        assert!(imp.warnings.iter().any(|w| w.contains("outside the plugin directory")), "{:?}", imp.warnings);
    }

    #[test]
    fn compat_openclaw_never_panics_on_broken_input() {
        let d = seagent_core::tmp::scratch_path(format!("seagent-compat-oc-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        for body in ["", "null", "[]", "{\"id\": 3}", "{\"id\": \"ok\", \"contracts\": 7}", "{\"id\": \"ok\", \"setup\": [1]}"] {
            fs::write(d.join("openclaw.plugin.json"), body).unwrap();
            let _ = import(&d); // must not panic
        }
        fs::write(d.join("openclaw.plugin.json"), "{\"id\":\"ok\"}").unwrap();
        assert_eq!(import(&d).unwrap().id, "ok");
        let _ = fs::remove_dir_all(&d);
    }
}
