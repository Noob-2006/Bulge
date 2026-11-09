//! The rest of Settings → Connections — setup flows that used to need a terminal:
//!
//! - hooks: `seagent hooks list | approve | revoke | enable | disable | install`
//!   (`hooks_cli::gui`, the same helpers; an install is an uploaded pack);
//! - Gmail: `seagent webhook gmail setup | status | enable | disable | reset | watch`
//!   (`gmail_hook::run`, the CLI's own function with its report collected);
//! - MCP pins: `seagent mcp pins diff | forget`;
//! - skill setup: `seagent skills setup <name>` (required env vars; values go to the vault
//!   through `setup::capture`, the function the CLI's prompt feeds);
//! - the plugin MCP catalog: `seagent plugins mcps | mcp-install`;
//! - devices: `seagent nodes setup-code` (with the QR code `seagent_app::qr` draws);
//! - the one-click daemon restart for the few changes `connectors_live` cannot hot-apply.
//!
//! Dispatched from `ops::connectors::call`; writes report `applied` / `restart` the same way.

use super::connectors::{bad, fail, fresh, need, valid_name, vault, ConnCtx, Res};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

pub const METHODS: &[&str] = &[
    "ui.connectors.hooks.list", "ui.connectors.hooks.approve", "ui.connectors.hooks.revoke", "ui.connectors.hooks.enable", "ui.connectors.hooks.install",
    "ui.connectors.gmail.status", "ui.connectors.gmail.setup", "ui.connectors.gmail.enable", "ui.connectors.gmail.reset", "ui.connectors.gmail.watch",
    "ui.connectors.mcp.pins.diff", "ui.connectors.mcp.pins.forget",
    "ui.connectors.skills.setup", "ui.connectors.skills.setup.save", "ui.connectors.skills.enable",
    "ui.connectors.plugins.mcps", "ui.connectors.plugins.mcp.install",
    "ui.connectors.nodes.setup_code",
    "ui.connectors.restart",
];

pub fn call(c: &ConnCtx, m: &str, p: &Value) -> Option<Res> {
    let s = |k: &str| p[k].as_str().unwrap_or("").trim().to_string();
    let live = crate::ops::connectors_live::applied;
    Some(match m {
        // ── hooks (applied live: `connectors_live::reload_hooks`) ──
        "ui.connectors.hooks.list" => hooks(c, "list", p),
        "ui.connectors.hooks.approve" | "ui.connectors.hooks.revoke" | "ui.connectors.hooks.enable" => hooks(c, &m["ui.connectors.hooks.".len()..], p).map(|v| merge(v, live("hooks", ""))),
        "ui.connectors.hooks.install" => hooks_install(c, p).map(|v| merge(v, live("hooks", ""))),
        // ── Gmail (applied live: the watcher restarts) ──
        "ui.connectors.gmail.status" => gmail(c, &["status".into(), "--json".into()]).map(|(_, out)| serde_json::from_str::<Value>(out.trim()).unwrap_or_else(|_| json!({"configured": false, "text": out.trim()}))),
        "ui.connectors.gmail.setup" => gmail_setup(c, p).map(|v| merge(v, live("gmail", ""))),
        "ui.connectors.gmail.enable" => gmail(c, &[if p["enabled"].as_bool().unwrap_or(true) { "enable" } else { "disable" }.into()]).map(|(_, out)| merge(json!({"ok": true, "text": out.trim()}), live("gmail", ""))),
        "ui.connectors.gmail.reset" => gmail(c, &["reset".into()]).map(|(_, out)| json!({"ok": true, "text": out.trim()})),
        "ui.connectors.gmail.watch" => gmail(c, &["watch".into(), "--json".into()]).map(|(_, out)| serde_json::from_str::<Value>(out.trim()).unwrap_or_else(|_| json!({"ok": true, "text": out.trim()}))),
        // ── MCP pins ──
        "ui.connectors.mcp.pins.diff" => pins_diff(c, &s("name")),
        "ui.connectors.mcp.pins.forget" => need(&s("name"), "name").and_then(|n| {
            valid_name(&n)?;
            let had = seagent_plugin::pins::forget(&c.paths.data, &n).map_err(fail)?;
            Ok(merge(json!({"ok": true, "had_pins": had}), live("mcp", &n)))
        }),
        // ── skill setup / switch ──
        "ui.connectors.skills.setup" => skill_setup(c, &s("name"), None),
        "ui.connectors.skills.setup.save" => skill_setup(c, &s("name"), Some(&p["values"])),
        "ui.connectors.skills.enable" => need(&s("name"), "name").and_then(|n| crate::ops::ui_methods::skill_toggle(&c.paths, &n, p["enabled"].as_bool().unwrap_or(true))).map(|v| merge(v, live("skills.toggle", ""))),
        // ── the plugin MCP catalog ──
        "ui.connectors.plugins.mcps" => Ok(plugin_mcps(&s("q"))),
        "ui.connectors.plugins.mcp.install" => plugin_mcp_install(c, &s("name"), p["consent"].as_bool() == Some(true)),
        // ── devices ──
        "ui.connectors.nodes.setup_code" => setup_code(c, p),
        "ui.connectors.restart" => crate::ops::service::restart_detached(p["drain_secs"].as_u64().unwrap_or(30).min(600)).map(|t| json!({"ok": true, "text": t})).map_err(fail),
        _ => return None,
    })
}

/// A write's own answer plus how it was applied (`connectors_live::applied`).
fn merge(mut v: Value, r: Value) -> Value {
    if let Some(o) = v.as_object_mut() {
        o.insert("applied".into(), r["applied"].clone());
        o.insert("restart".into(), r["restart"].clone());
        o.insert("live".into(), r);
    }
    v
}

fn kernel() -> Result<seagent_kernel::kernel::Kernel, String> {
    crate::ops::connectors_live::get().map(|l| l.kernel()).ok_or_else(|| "installing a hook pack needs the running daemon (its before_install hooks review it)".to_string())
}

fn hooks(c: &ConnCtx, op: &str, p: &Value) -> Res {
    crate::hooks_cli::gui(&c.paths, &c.ws, op, p, &kernel).map_err(bad)
}

/// A hook pack picked on the person's computer (`HOOK.md` + handler): written to a scratch
/// directory under the data dir, then installed by `hooks_cli` exactly as from a directory.
fn hooks_install(c: &ConnCtx, p: &Value) -> Res {
    let files = p["files"].as_array().ok_or_else(|| bad("files is required ([{path, data}] with base64 data)"))?;
    let tmp = seagent_core::tmp::TempDir::new_in(&c.paths.data, "hook-upload");
    let mut total = 0usize;
    let mut rels = vec![];
    for f in files {
        let rel = f["path"].as_str().unwrap_or("").replace('\\', "/");
        let data = f["data"].as_str().unwrap_or("");
        total += data.len();
        if total > 8 * 1024 * 1024 {
            return Err(bad("a hook pack upload is limited to 6 MiB"));
        }
        if rel.is_empty() || rel.starts_with('/') || rel.split('/').any(|x| x == ".." || x.is_empty() || x.contains(':')) {
            return Err(bad(format!("`{rel}` is not a relative path inside the pack")));
        }
        let bytes = seagent_net::crypto::b64_decode(data.split_once("base64,").map(|x| x.1).unwrap_or(data)).ok_or_else(|| bad(format!("{rel}: not base64")))?;
        rels.push((rel, bytes));
    }
    // A folder pick wraps everything in the pack's own directory: strip it like a skill upload.
    let top = rels.iter().find(|(r, _)| r.ends_with("/HOOK.md") && r.matches('/').count() == 1).map(|(r, _)| r.trim_end_matches("HOOK.md").to_string());
    for (rel, bytes) in &rels {
        let rel = top.as_deref().and_then(|t| rel.strip_prefix(t)).unwrap_or(rel);
        let dest = tmp.path().join(rel);
        if let Some(d) = dest.parent() {
            std::fs::create_dir_all(d).map_err(|e| fail(e.to_string()))?;
        }
        std::fs::write(&dest, bytes).map_err(|e| fail(e.to_string()))?;
        // The handler runs as a program: keep it executable the way a checkout would be.
        if rel.starts_with("handler") {
            let _ = crate::ops::hostos::set_mode(&dest, 0o755);
        }
    }
    if !tmp.path().join("HOOK.md").is_file() {
        return Err(bad("no HOOK.md in the upload (pick the hook pack's folder)"));
    }
    // The pack's name comes from HOOK.md's front matter (the scratch dir's name is no name).
    crate::hooks_cli::gui(&c.paths, &c.ws, "install", &json!({"dir": tmp.path().display().to_string(), "yes": p["yes"].as_bool() == Some(true)}), &kernel).map_err(bad)
}

/// `seagent webhook gmail <argv…>`: (exit code, report).
fn gmail(c: &ConnCtx, argv: &[String]) -> Result<(i32, String), (i32, String)> {
    let cfg = fresh(c)?;
    vault(c)?;
    // Read the vault per lookup: `setup` stores the credentials it is given, then resolves them.
    let secrets = |s: &str| seagent_kernel::vault::Vault::load(&c.paths.secrets()).map(|v| v.substitute(s)).unwrap_or_else(|_| s.to_string());
    let mut out = String::new();
    let code = crate::gmail_hook::run(argv, &c.paths, &cfg, &secrets, &mut out).map_err(bad)?;
    Ok((code, out))
}

/// The setup form → `seagent webhook gmail setup --account … --topic …`. Credentials typed in
/// the form go through the CLI's own path, which moves literals into the vault.
fn gmail_setup(c: &ConnCtx, p: &Value) -> Res {
    let mut argv = vec!["setup".to_string(), "--json".to_string()];
    for (k, flag) in [("account", "--account"), ("topic", "--topic"), ("label", "--label"), ("subscription", "--subscription"), ("bind", "--bind"), ("port", "--port"), ("path", "--path"), ("renew_minutes", "--renew-minutes"), ("max_bytes", "--max-bytes"), ("push_token", "--push-token"), ("client_id", "--client-id"), ("client_secret", "--client-secret"), ("refresh_token", "--refresh-token"), ("access_token", "--access-token")] {
        let v = match &p[k] {
            Value::Number(n) => n.to_string(),
            v => v.as_str().unwrap_or("").trim().to_string(),
        };
        if !v.is_empty() {
            argv.extend([flag.to_string(), v]);
        }
    }
    if p["include_body"].as_bool() == Some(false) {
        argv.push("--no-body".into());
    }
    let (_, out) = gmail(c, &argv)?;
    Ok(serde_json::from_str::<Value>(out.trim()).unwrap_or_else(|_| json!({"ok": true, "text": out.trim()})))
}

/// `seagent mcp pins diff <server>`: what changed in each tool since it was approved.
fn pins_diff(c: &ConnCtx, name: &str) -> Res {
    valid_name(name)?;
    let cfg = fresh(c)?;
    let (cfgs, _) = crate::ext::mcp_configs(&cfg);
    let sc = cfgs.get(name).cloned().ok_or_else(|| bad(format!("no MCP server `{name}`")))?;
    let v = Arc::new(vault(c)?);
    let reg = seagent_plugin::Registry::load(&BTreeMap::from([(name.to_string(), sc)]), &c.paths.data.join("mcp-cache"), crate::ext::secrets_fn(&v));
    let defs = reg.catalog_tools(name);
    reg.shutdown();
    let defs = defs.ok_or_else(|| fail(format!("{name}: no catalog (test the server first)")))?;
    let rows: Vec<Value> = seagent_plugin::pins::diff(&c.paths.data, name, &defs).into_iter().map(|(tool, was, now)| json!({"tool": tool, "state": if was.is_null() { "new" } else { "changed" }, "approved": was, "now": now})).collect();
    Ok(json!({"server": name, "changes": rows, "pinned": seagent_plugin::pins::load(&c.paths.data).servers.get(name).map(|t| t.len()).unwrap_or(0)}))
}

/// `seagent skills setup <name>`: what the skill needs (`values` = None) or store the typed
/// values in the vault through `setup::capture`, the function the CLI prompt feeds.
fn skill_setup(c: &ConnCtx, name: &str, values: Option<&Value>) -> Res {
    use seagent_skills::core::{invoke, settings::Settings, setup};
    need(name, "name")?;
    let cfg = fresh(c)?;
    let cat = invoke::catalog_loadable(&cfg, &c.paths, &c.ws, &Settings::load(&cfg));
    let k = invoke::resolve(&cat, name).ok_or_else(|| bad(format!("no skill `{name}`")))?;
    let reqs = setup::required_env(&k.front);
    let v = vault(c)?;
    let mut remaining = vec![];
    if let Some(vals) = values {
        remaining = setup::capture(&reqs, &v, |r| vals[&r.name].as_str().map(String::from)).map_err(fail)?;
    }
    let names = v.names();
    Ok(json!({
        "name": k.name,
        "ready": setup::readiness(&k.front, &names).0.as_str(),
        "remaining": remaining,
        "env": reqs.iter().map(|r| json!({"name": r.name, "prompt": r.prompt, "help": r.help, "optional": r.optional, "required_for": r.required_for, "set": setup::is_set(&r.name, &names)})).collect::<Vec<_>>(),
    }))
}

/// `seagent plugins mcps [query]`.
fn plugin_mcps(q: &str) -> Value {
    let q = q.to_lowercase();
    json!(seagent_skills::hub::plugins::mcp_catalog()
        .into_iter()
        .filter(|m| q.is_empty() || format!("{} {}", m["name"].as_str().unwrap_or(""), m["description"].as_str().unwrap_or("")).to_lowercase().contains(&q))
        .map(|m| json!({"name": m["name"], "description": m["description"], "transport": m["transport"]["type"].as_str().unwrap_or(if m["transport"]["url"].is_string() { "http" } else { "" }), "url": m["transport"]["url"], "command": m["transport"]["command"], "args": m["transport"]["args"], "auth": m["auth"]["type"]}))
        .collect::<Vec<_>>())
}

/// `seagent plugins mcp-install <name>`. A stdio entry runs a program once it is live, so it
/// needs the same consent as any stdio server first.
fn plugin_mcp_install(c: &ConnCtx, name: &str, consent: bool) -> Res {
    need(name, "name")?;
    let entry = seagent_skills::hub::plugins::mcp_catalog().into_iter().find(|e| e["name"].as_str() == Some(name)).ok_or_else(|| bad(format!("no optional MCP `{name}`")))?;
    if entry["transport"]["type"] == "stdio" && !consent {
        let args: Vec<String> = entry["transport"]["args"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(String::from)).collect();
        let cfg = seagent_plugin::McpServerConfig { command: entry["transport"]["command"].as_str().map(String::from), args, enabled: true, ..Default::default() };
        return Ok(json!({"ok": false, "consent_required": true, "consent": crate::mcp_cli::stdio_consent(name, &cfg)}));
    }
    let cfg = fresh(c)?;
    let text = seagent_skills::hub::plugins::Plugins::new(&cfg, &c.paths).install_mcp(name).map_err(fail)?;
    Ok(merge(json!({"ok": true, "name": name, "text": text}), crate::ops::connectors_live::applied("mcp", name)))
}

/// `seagent nodes setup-code`: a one-time code (and its QR code) a device joins with.
fn setup_code(c: &ConnCtx, p: &Value) -> Res {
    let cfg = fresh(c)?;
    let app = seagent_app::AppConfig::parse(&cfg.app).map_err(fail)?;
    let (url, fp) = match p["url"].as_str().map(str::trim).filter(|u| !u.is_empty()) {
        Some(u) => (u.to_string(), None),
        None => crate::ops::controlcmds::pairing_url(&cfg, &c.paths.data).map_err(fail)?,
    };
    let ttl = p["ttl_min"].as_u64().unwrap_or(10).clamp(1, 60) * 60_000;
    let mut q = json!({"url": url, "ttlMs": ttl});
    if let Some(f) = fp {
        q["tlsFingerprint"] = json!(f);
    }
    let f = seagent_app::node::methods();
    let r = f("node.setup.create", &q).ok_or_else(|| fail("node pairing is not available in this daemon"))?.map_err(|e| fail(e.1))?;
    let code = r["code"].as_str().unwrap_or("").to_string();
    Ok(json!({
        "code": code,
        "url": r["url"],
        "ttl_min": ttl / 60_000,
        "nodes_enabled": app.nodes,
        "qr_svg": seagent_app::qr::Qr::encode(code.as_bytes()).map(|q| q.svg(2)),
        "command": format!("seagent node --setup-code {code}"),
    }))
}
