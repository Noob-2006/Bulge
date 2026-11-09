//! ARP methods behind Settings → Connections (`ui/web/connectors.js`): every connector the CLI
//! sets up, done from the console instead of a terminal —
//!
//! - MCP servers: `seagent mcp add|rm|test|login|logout|pins accept|presets`, per-tool on/off
//!   (`exclude_tools` / `tools`), and an importer for Claude / Cursor / VS Code / Windsurf
//!   `mcp.json` files (the `seagent migrate` converter);
//! - skills: `seagent skills search|browse|install|uninstall|check|update|tap`, the bundled
//!   set, and installing an uploaded folder or ZIP through the hub's own quarantine and scan;
//! - plugins: `seagent plugins search|install|uninstall|update|inspect|marketplace` and
//!   `[plugins.<name>]` process plugins (the MCP superset of `docs/plugins.md`);
//! - ACP agents (`[acp.agents.*]`, what `seagent acp-client` drives), A2A peers and remote
//!   agents (`[app.a2a]`) and webhook subscriptions (`seagent webhook …`).
//!
//! Chat channels have their own module (`ops::channels_setup`).
//!
//! There is no second implementation here: each method calls what the CLI command calls
//! (`mcp_cli::save_server`, `Registry::refresh`, `hub::cli::run`, `hub::plugins::Plugins`,
//! `seagent_channel::webhook`), and every config write goes through `confcli::put_table` /
//! `confcli::set` — validated before it lands, audited, and backed up so the Config page's
//! "previous versions" restores it. A secret typed into a form goes to the vault and the config
//! only gets its `{{secret:NAME}}` reference; no method returns a secret value. Writes apply
//! on the next daemon start, like every other config page.

use seagent_kernel::config::{project_config, Config, Paths};
use seagent_kernel::daemon::MethodExt;
use seagent_kernel::vault::Vault;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Method names exposed to the app server (WebSocket/HTTP ARP) in addition to the daemon's own.
pub const METHODS: &[&str] = &[
    "ui.connectors.overview",
    "ui.connectors.mcp.list", "ui.connectors.mcp.get", "ui.connectors.mcp.save", "ui.connectors.mcp.remove", "ui.connectors.mcp.test", "ui.connectors.mcp.tool",
    "ui.connectors.mcp.presets", "ui.connectors.mcp.preset.add", "ui.connectors.mcp.import", "ui.connectors.mcp.login", "ui.connectors.mcp.login.status", "ui.connectors.mcp.logout",
    "ui.connectors.mcp.pins.accept", "ui.connectors.mcp.enable",
    "ui.connectors.skills.search", "ui.connectors.skills.install", "ui.connectors.skills.upload", "ui.connectors.skills.uninstall", "ui.connectors.skills.check",
    "ui.connectors.skills.update", "ui.connectors.skills.bundled", "ui.connectors.skills.taps", "ui.connectors.skills.tap",
    "ui.connectors.plugins.search", "ui.connectors.plugins.install", "ui.connectors.plugins.uninstall", "ui.connectors.plugins.update", "ui.connectors.plugins.inspect",
    "ui.connectors.plugins.marketplace", "ui.connectors.plugins.process.get", "ui.connectors.plugins.process.save", "ui.connectors.plugins.process.remove", "ui.connectors.plugins.process.test",
    "ui.connectors.acp.list", "ui.connectors.acp.save", "ui.connectors.acp.remove",
    "ui.connectors.a2a.list", "ui.connectors.a2a.enable", "ui.connectors.a2a.agent.save", "ui.connectors.a2a.agent.remove", "ui.connectors.a2a.agent.test",
    "ui.connectors.a2a.peer.save", "ui.connectors.a2a.peer.remove",
    "ui.connectors.webhooks.list", "ui.connectors.webhooks.subscribe", "ui.connectors.webhooks.remove", "ui.connectors.webhooks.test",
];

pub(crate) type Res = Result<Value, (i32, String)>;

pub(crate) fn bad(e: impl Into<String>) -> (i32, String) {
    (-32602, e.into())
}
pub(crate) fn fail(e: impl Into<String>) -> (i32, String) {
    (-32000, e.into())
}

/// An OAuth sign-in running in the background (`ui.connectors.mcp.login`).
#[derive(Clone, Default)]
struct Login {
    state: &'static str,
    url: Option<String>,
    user_code: Option<String>,
    verification_uri: Option<String>,
    error: Option<String>,
}

pub struct ConnCtx {
    pub paths: Paths,
    /// Workspace whose `.seagent/config.toml` layers over the user config.
    pub ws: PathBuf,
    /// What the running daemon actually started: MCP server → (tools, running).
    live_mcp: BTreeMap<String, (usize, bool)>,
    live_plugins: Vec<String>,
    logins: Arc<Mutex<BTreeMap<String, Login>>>,
    /// `HOME` / `%APPDATA%` for the mcp.json importer (injected so tests never read the real ones).
    home: PathBuf,
    appdata: Option<PathBuf>,
}

impl ConnCtx {
    pub fn new(paths: &Paths, ws: &Path) -> ConnCtx {
        ConnCtx {
            paths: paths.clone(),
            ws: ws.to_path_buf(),
            live_mcp: BTreeMap::new(),
            live_plugins: vec![],
            logins: Default::default(),
            home: seagent_core::layout::home(),
            appdata: std::env::var_os("APPDATA").map(PathBuf::from).filter(|p| p.is_absolute()),
        }
    }
}

pub fn methods(paths: &Paths, k: &seagent_kernel::kernel::Kernel, ext: Option<&crate::ext::Ext>) -> MethodExt {
    let ws = k.cfg.app.get("workspace").and_then(|v| v.as_str()).map(PathBuf::from).or_else(|| std::env::current_dir().ok()).unwrap_or_else(|| PathBuf::from("."));
    let mut c = ConnCtx::new(paths, &ws);
    if let Some(e) = ext {
        c.live_mcp = e.registry.status().into_iter().map(|(n, t, r)| (n, (t, r))).collect();
        c.live_plugins = e.plugins.iter().map(|p| p.name.clone()).collect();
    }
    let c = Arc::new(c);
    Arc::new(move |m: &str, p: &Value| call(&c, m, p))
}

pub fn call(c: &ConnCtx, m: &str, p: &Value) -> Option<Res> {
    let r = dispatch(c, m, p)?;
    Some(r.map(|v| apply_live(m, p, v)))
}

/// After a successful write, apply it to the running daemon (`connectors_live`) and say so:
/// `{"applied": true}` when it took effect now, `{"restart": true, "why"}` when only a
/// restart applies it.
fn apply_live(m: &str, p: &Value, mut v: Value) -> Value {
    if v["ok"] == false || v.get("consent_required").is_some() || (m == "ui.connectors.mcp.import" && v["applied"] != true) {
        return v;
    }
    let name = |k: &str| p[k].as_str().unwrap_or("").trim().to_string();
    let live = crate::ops::connectors_live::applied;
    let r = match m {
        "ui.connectors.mcp.save" => {
            if let Some(o) = p["original"].as_str().filter(|o| !o.trim().is_empty() && o.trim() != name("name")) {
                live("mcp", o.trim());
            }
            live("mcp", &name("name"))
        }
        "ui.connectors.mcp.remove" | "ui.connectors.mcp.tool" | "ui.connectors.mcp.logout" | "ui.connectors.mcp.pins.accept" | "ui.connectors.mcp.enable" => live("mcp", &name("name")),
        "ui.connectors.mcp.preset.add" => live("mcp", v["name"].as_str().unwrap_or("")),
        "ui.connectors.mcp.import" => {
            let names: Vec<String> = v["servers"].as_array().into_iter().flatten().filter(|r| r["imported"] == true).filter_map(|r| r["name"].as_str().map(String::from)).collect();
            let all: Vec<Value> = names.iter().map(|n| live("mcp", n)).collect();
            json!({"applied": all.iter().all(|a| a["applied"] == true), "restart": all.iter().any(|a| a["restart"] == true), "each": all})
        }
        "ui.connectors.plugins.install" | "ui.connectors.plugins.uninstall" | "ui.connectors.plugins.update" | "ui.connectors.plugins.process.save" | "ui.connectors.plugins.process.remove" => live("plugins", ""),
        "ui.connectors.acp.save" | "ui.connectors.acp.remove" => live("acp", ""),
        // A listener that had no token or subscription starts once it has one.
        "ui.connectors.webhooks.subscribe" | "ui.connectors.webhooks.remove" => live("channels", ""),
        "ui.connectors.a2a.enable" | "ui.connectors.a2a.agent.save" | "ui.connectors.a2a.agent.remove" | "ui.connectors.a2a.peer.save" | "ui.connectors.a2a.peer.remove" => live("a2a", ""),
        _ => return v,
    };
    if let Some(o) = v.as_object_mut() {
        o.insert("applied".into(), r["applied"].clone());
        o.insert("restart".into(), r["restart"].clone());
        o.insert("live".into(), r);
    }
    v
}

fn dispatch(c: &ConnCtx, m: &str, p: &Value) -> Option<Res> {
    let s = |k: &str| p[k].as_str().unwrap_or("").trim().to_string();
    let b = |k: &str| p[k].as_bool().unwrap_or(false);
    Some(match m {
        "ui.connectors.overview" => overview(c),
        // ── MCP ──
        "ui.connectors.mcp.list" => mcp_list(c),
        "ui.connectors.mcp.get" => mcp_get(c, &s("name")),
        "ui.connectors.mcp.save" => mcp_save(c, "mcp", p),
        "ui.connectors.mcp.remove" => need(&s("name"), "name").and_then(|n| crate::mcp_cli::remove_server(&c.paths, "mcp", &n).map_err(fail)).map(|_| json!({"ok": true, "restart": true})),
        "ui.connectors.mcp.test" => mcp_test(c, p),
        "ui.connectors.mcp.tool" => mcp_tool(c, &s("name"), &s("tool"), p["enabled"].as_bool().unwrap_or(true)),
        "ui.connectors.mcp.presets" => Ok(mcp_presets(&s("q"))),
        "ui.connectors.mcp.preset.add" => mcp_preset_add(c, p),
        "ui.connectors.mcp.import" => mcp_import(c, p),
        "ui.connectors.mcp.login" => mcp_login(c, &s("name"), &s("mode")),
        "ui.connectors.mcp.login.status" => Ok(login_status(c, &s("name"))),
        "ui.connectors.mcp.logout" => need(&s("name"), "name").map(|n| {
            let store = seagent_plugin::oauth::Store::new(&c.paths.data, &n);
            let had = store.has_tokens();
            store.clear();
            json!({"ok": true, "had_tokens": had})
        }),
        "ui.connectors.mcp.pins.accept" => mcp_pins_accept(c, &s("name")),
        // The list's on/off switch, applied live (the Plugins page's `ui.mcp.set` only writes).
        "ui.connectors.mcp.enable" => need(&s("name"), "name").and_then(|n| {
            valid_name(&n)?;
            user_table(c, &format!("mcp.{n}")).ok_or_else(|| bad(format!("no [mcp.{n}] in the user config")))?;
            crate::ops::confcli::set(&c.paths, &format!("mcp.{n}.enabled"), if b("enabled") { "true" } else { "false" }).map_err(fail)?;
            Ok(json!({"ok": true, "name": n, "enabled": b("enabled")}))
        }),
        // ── skills (`seagent skills …`, the same `hub::cli::run`) ──
        "ui.connectors.skills.search" => skills_search(c, &s("q"), &s("source"), p["limit"].as_u64().unwrap_or(25)),
        "ui.connectors.skills.install" => need(&s("id"), "id").and_then(|id| {
            let mut argv = vec!["install".to_string(), id];
            for (flag, k) in [("--name", "name"), ("--category", "category"), ("--version", "version")] {
                if !s(k).is_empty() {
                    argv.extend([flag.to_string(), s(k)]);
                }
            }
            if b("force") {
                argv.push("--force".into());
            }
            skills_cli(c, &argv)
        }),
        "ui.connectors.skills.upload" => skills_upload(c, p),
        "ui.connectors.skills.uninstall" => need(&s("name"), "name").and_then(|n| skills_cli(c, &["uninstall".into(), n])),
        "ui.connectors.skills.check" => skills_cli(c, &["check".into()]),
        "ui.connectors.skills.update" => {
            let mut argv = vec!["update".to_string()];
            if !s("name").is_empty() {
                argv.push(s("name"));
            }
            if b("force") {
                argv.push("--force".into());
            }
            skills_cli(c, &argv)
        }
        "ui.connectors.skills.bundled" => skills_bundled(c),
        "ui.connectors.skills.taps" => skills_cli(c, &["tap".into(), "list".into()]),
        "ui.connectors.skills.tap" => match s("action").as_str() {
            a @ ("add" | "remove") => need(&s("repo"), "repo").and_then(|r| skills_cli(c, &["tap".into(), a.into(), r])),
            _ => Err(bad("action is add or remove")),
        },
        // ── plugins (`seagent plugins …`, the same `hub::plugins::Plugins`) ──
        "ui.connectors.plugins.search" => fresh(c).map(|cfg| json!(seagent_skills::hub::plugins::Plugins::new(&cfg, &c.paths).search(&s("q"), 25))),
        "ui.connectors.plugins.install" => need(&s("spec"), "spec").and_then(|spec| plugins(c, |pm| pm.install(&spec, b("force")))),
        "ui.connectors.plugins.uninstall" => need(&s("name"), "name").and_then(|n| plugins(c, |pm| pm.uninstall(&n))),
        "ui.connectors.plugins.update" => {
            let n = s("name");
            plugins(c, |pm| pm.update((!n.is_empty()).then_some(n.as_str()), b("force")))
        }
        "ui.connectors.plugins.inspect" => need(&s("name"), "name").and_then(|n| {
            let cfg = fresh(c)?;
            seagent_skills::hub::plugins::Plugins::new(&cfg, &c.paths).inspect(&n).ok_or_else(|| bad(format!("no plugin `{n}`")))
        }),
        "ui.connectors.plugins.marketplace" => need(&s("source"), "source").and_then(|src| {
            let cfg = fresh(c)?;
            let (name, list, _) = seagent_skills::hub::plugins::Plugins::new(&cfg, &c.paths).marketplace(&src).map_err(fail)?;
            Ok(json!({"name": name, "plugins": list}))
        }),
        "ui.connectors.plugins.process.get" => process_get(c, &s("name")),
        "ui.connectors.plugins.process.save" => mcp_save(c, "plugins", p),
        "ui.connectors.plugins.process.remove" => need(&s("name"), "name").and_then(|n| crate::mcp_cli::remove_server(&c.paths, "plugins", &n).map_err(fail)).map(|_| json!({"ok": true, "restart": true})),
        "ui.connectors.plugins.process.test" => process_test(c, p),
        // ── ACP agents / A2A ──
        "ui.connectors.acp.list" => acp_list(c),
        "ui.connectors.acp.save" => acp_save(c, p),
        "ui.connectors.acp.remove" => need(&s("name"), "name").and_then(|n| remove_table(c, &format!("acp.agents.{n}"))),
        "ui.connectors.a2a.list" => a2a_list(c),
        "ui.connectors.a2a.enable" => crate::ops::confcli::set(&c.paths, "app.a2a.enabled", if b("enabled") { "true" } else { "false" }).map(|m| json!({"ok": true, "message": m, "restart": true})).map_err(fail),
        "ui.connectors.a2a.agent.save" => a2a_agent_save(c, p),
        "ui.connectors.a2a.agent.remove" => need(&s("name"), "name").and_then(|n| remove_table(c, &format!("app.a2a.agents.{n}"))),
        "ui.connectors.a2a.agent.test" => a2a_agent_test(c, &s("name")),
        "ui.connectors.a2a.peer.save" => a2a_peer_save(c, &s("name"), p["token"].as_str().unwrap_or("")),
        "ui.connectors.a2a.peer.remove" => need(&s("name"), "name").and_then(|n| crate::ops::confcli::unset(&c.paths, &format!("app.a2a.peers.{n}")).map_err(fail)).map(|_| json!({"ok": true, "restart": true})),
        // ── webhooks (`seagent webhook …`) ──
        "ui.connectors.webhooks.list" => webhooks_list(c),
        "ui.connectors.webhooks.subscribe" => webhooks_subscribe(c, &s("channel"), &s("route"), p),
        "ui.connectors.webhooks.remove" => webhook_file(c, &s("channel")).and_then(|f| need(&s("route"), "route").and_then(|r| seagent_channel::webhook::unsubscribe(&f, &r).map_err(fail))).map(|removed| json!({"ok": true, "removed": removed})),
        "ui.connectors.webhooks.test" => webhooks_test(c, &s("channel"), &s("route"), p["payload"].as_str()),
        _ => return crate::ops::connectors_extra::call(c, m, p),
    })
}

// ───────────────────────── shared helpers ─────────────────────────

pub(crate) fn need(v: &str, what: &str) -> Result<String, (i32, String)> {
    if v.is_empty() {
        Err(bad(format!("{what} is required")))
    } else {
        Ok(v.to_string())
    }
}

pub(crate) fn valid_name(n: &str) -> Result<(), (i32, String)> {
    if n.is_empty() || n.len() > 40 || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') || n.contains("__") {
        return Err(bad(format!("name `{n}`: letters, digits, _ and - only (at most 40, no `__`)")));
    }
    Ok(())
}

pub(crate) fn fresh(c: &ConnCtx) -> Result<Config, (i32, String)> {
    Config::load(Some(&c.paths.user_config()), Some(&project_config(&c.ws)), &[]).map_err(fail)
}

pub(crate) fn vault(c: &ConnCtx) -> Result<Vault, (i32, String)> {
    Vault::load(&c.paths.secrets()).map_err(fail)
}

/// The user config file as a table (the only layer the console writes).
pub(crate) fn user_root(c: &ConnCtx) -> toml::Table {
    std::fs::read_to_string(c.paths.user_config()).ok().and_then(|t| t.parse().ok()).unwrap_or_default()
}

pub(crate) fn user_table(c: &ConnCtx, key: &str) -> Option<toml::Table> {
    crate::ops::confcli::get_in(&user_root(c), key).and_then(|v| v.as_table()).cloned()
}

pub(crate) fn remove_table(c: &ConnCtx, key: &str) -> Res {
    if !crate::ops::confcli::put_table(&c.paths, key, None).map_err(fail)? {
        return Err(bad(format!("no [{key}] in {}", c.paths.user_config().display())));
    }
    Ok(json!({"ok": true, "restart": true}))
}

/// `{{secret:NAME}}` → `NAME`.
pub(crate) fn secret_ref(v: &str) -> Option<&str> {
    v.trim().strip_prefix("{{secret:")?.strip_suffix("}}")
}

/// A vault name for a form field: `MCP_GITHUB_API_TOKEN`.
pub(crate) fn vault_name(parts: &[&str]) -> String {
    parts.iter().map(|p| p.to_ascii_uppercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect::<String>()).collect::<Vec<_>>().join("_")
}

/// Values a form wants stored in the vault, written only after the config validated.
#[derive(Default)]
pub(crate) struct Pending(pub(crate) Vec<(String, String)>);

impl Pending {
    /// The config value for one secret field: a reference the user typed stays as is, a
    /// literal goes to the vault under `name` and becomes a reference.
    pub(crate) fn value(&mut self, name: String, raw: &str) -> String {
        if secret_ref(raw).is_some() {
            return raw.trim().to_string();
        }
        let r = format!("{{{{secret:{name}}}}}");
        self.0.push((name, raw.to_string()));
        r
    }
    /// The vault plus the values not stored yet (a draft test runs before anything is saved).
    pub(crate) fn secrets(&self, v: Arc<Vault>) -> seagent_plugin::Secrets {
        let pend = self.0.clone();
        Arc::new(move |s: &str| {
            let mut s = s.to_string();
            for (n, val) in &pend {
                s = s.replace(&format!("{{{{secret:{n}}}}}"), val);
            }
            v.substitute(&s)
        })
    }
    pub(crate) fn store(&self, c: &ConnCtx) -> Result<Vec<String>, (i32, String)> {
        if self.0.is_empty() {
            return Ok(vec![]);
        }
        let v = vault(c)?;
        for (n, val) in &self.0 {
            v.set(n, val).map_err(|e| fail(format!("vault: {e}")))?;
        }
        Ok(self.0.iter().map(|(n, _)| n.clone()).collect())
    }
}

/// Key/value rows (`env`, `headers`) from a form: `{key, value, secret, keep}`. `keep` means
/// "unchanged": the old value (possibly a literal secret the form never saw) is copied over.
pub(crate) fn kv_rows(rows: &Value, old: Option<&toml::Table>, prefix: &[&str], pend: &mut Pending) -> Result<toml::Table, (i32, String)> {
    let mut t = toml::Table::new();
    for r in rows.as_array().into_iter().flatten() {
        let k = r["key"].as_str().unwrap_or("").trim();
        if k.is_empty() {
            continue;
        }
        if k.chars().any(|c| c.is_whitespace() || c == '=') {
            return Err(bad(format!("`{k}` is not a valid name")));
        }
        let raw = r["value"].as_str().unwrap_or("");
        if r["keep"].as_bool() == Some(true) {
            if let Some(v) = old.and_then(|o| o.get(k)) {
                t.insert(k.into(), v.clone());
                continue;
            }
        }
        let v = if r["secret"].as_bool() == Some(true) && !raw.is_empty() {
            let mut parts = prefix.to_vec();
            parts.push(k);
            pend.value(vault_name(&parts), raw)
        } else {
            raw.to_string()
        };
        t.insert(k.into(), toml::Value::String(v));
    }
    Ok(t)
}

/// The rows a form shows for an `env` / `headers` table: literal secret values are never
/// sent back (`keep` marks them so a save leaves them alone).
fn kv_view(t: Option<&toml::Value>, vault: &Option<Vault>) -> Value {
    let Some(t) = t.and_then(|v| v.as_table()) else { return json!([]) };
    json!(t
        .iter()
        .map(|(k, v)| {
            let raw = v.as_str().map(String::from).unwrap_or_else(|| v.to_string());
            match secret_ref(&raw) {
                Some(n) => json!({"key": k, "value": raw, "secret": true, "ref": n, "set": vault.as_ref().is_some_and(|vt| vt.names().iter().any(|x| x == n))}),
                None if crate::mcp_cli::secret_name(k) => json!({"key": k, "value": "", "secret": true, "keep": true, "stored": "literal"}),
                None => json!({"key": k, "value": raw, "secret": false}),
            }
        })
        .collect::<Vec<_>>())
}

/// Where a configured program resolves, the way the stdio transport will start it
/// (`platform::layout::program_command`: `PATHEXT` and the `python3` / `bash` substitutes on
/// Windows, a plain `PATH` search elsewhere). `None` = nothing would start.
pub fn resolve_program(cmd: &str) -> Option<PathBuf> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return None;
    }
    let p = Path::new(cmd);
    if p.is_absolute() || cmd.contains('/') || cmd.contains('\\') {
        return p.is_file().then(|| p.to_path_buf());
    }
    let prog = PathBuf::from(seagent_core::platform::layout::program_command(cmd).get_program());
    if prog.is_absolute() && prog.is_file() {
        return Some(prog);
    }
    seagent_core::platform::layout::which(cmd)
}

pub(crate) fn not_found(cmd: &str) -> String {
    format!("`{cmd}` was not found on this machine's PATH{} — install it, or give the full path to the program", if cfg!(windows) { " (searched with PATHEXT: .exe, .cmd, .bat…)" } else { "" })
}

// ───────────────────────── overview ─────────────────────────

fn overview(c: &ConnCtx) -> Res {
    let cfg = fresh(c)?;
    let skills = seagent_skills::skill::discover(&seagent_skills::skill::roots(&c.paths, &c.ws, &[])).len();
    let pm = seagent_skills::hub::plugins::Plugins::new(&cfg, &c.paths);
    let webhooks = cfg.channels.values().filter(|t| t.get("kind").and_then(|v| v.as_str()) == Some("webhook")).count();
    let acp = seagent_app::acp_client::AcpConfig::parse(&cfg.acp).map(|a| a.agents.len()).unwrap_or(0);
    let a2a = seagent_app::AppConfig::parse(&cfg.app).map(|a| (a.a2a.enabled, a.a2a.agents.len(), a.a2a.peers.len())).unwrap_or((false, 0, 0));
    Ok(json!({
        "mcp": {"configured": cfg.mcp.len(), "running": c.live_mcp.values().filter(|(_, r)| *r).count(), "live": c.live_mcp.len()},
        "skills": {"installed": skills},
        "plugins": {"installed": pm.list().len(), "live": c.live_plugins.len()},
        "channels": {"configured": cfg.channels.len()},
        "webhooks": {"channels": webhooks},
        "acp": {"configured": acp},
        "a2a": {"enabled": a2a.0, "agents": a2a.1, "peers": a2a.2},
        "live": crate::ops::connectors_live::get().is_some(),
        "pending_restart": crate::ops::connectors_live::get().map(|l| l.pending_restart()).unwrap_or_default(),
    }))
}

// ───────────────────────── MCP ─────────────────────────

fn transport_of(t: &toml::Table) -> &'static str {
    if t.get("url").is_some() {
        if t.get("transport").and_then(|v| v.as_str()) == Some("sse") {
            "sse"
        } else {
            "http"
        }
    } else {
        "stdio"
    }
}

fn mcp_list(c: &ConnCtx) -> Res {
    let cfg = fresh(c)?;
    let user = user_root(c);
    let (_, warnings) = crate::ext::mcp_configs(&cfg);
    let mut out = vec![];
    for (name, t) in &cfg.mcp {
        let error = crate::mcp_cli::server_config(name, t).err();
        let target = match t.get("url").and_then(|v| v.as_str()) {
            Some(u) => u.to_string(),
            None => {
                let cmd = t.get("command").and_then(|v| v.as_str()).unwrap_or("");
                let args: Vec<String> = t.get("args").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default();
                crate::mcp_cli::server_config(name, t).map(|cfg| crate::mcp_cli::stdio_consent(name, &cfg)).ok().and_then(|line| line.split(" · argv=[").nth(1).and_then(|r| r.split("] · ").next()).map(|a| a.replace(", ", " "))).unwrap_or_else(|| format!("{cmd} {}", args.join(" ")))
            }
        };
        let hot = crate::ops::connectors_live::get().filter(|l| l.mcp_touched(name)).and_then(|l| l.mcp_status(name));
        let live = hot.as_ref().or_else(|| c.live_mcp.get(name));
        out.push(json!({
            "name": name,
            "transport": transport_of(t),
            "target": target,
            "enabled": t.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
            "running": live.map(|l| l.1).unwrap_or(false),
            "live": live.is_some(),
            "tools": live.map(|l| l.0).unwrap_or(0),
            "auth": t.get("auth").and_then(|v| v.as_str()).unwrap_or(""),
            "logged_in": seagent_plugin::oauth::Store::new(&c.paths.data, name).has_tokens(),
            "exclude_tools": t.get("exclude_tools").cloned().unwrap_or(toml::Value::Array(vec![])),
            "allow_tools": t.get("tools").cloned(),
            "editable": crate::ops::confcli::get_in(&user, &format!("mcp.{name}")).is_some(),
            "error": error,
        }));
    }
    Ok(json!({"servers": out, "warnings": warnings}))
}

fn mcp_get(c: &ConnCtx, name: &str) -> Res {
    valid_name(name)?;
    let t = user_table(c, &format!("mcp.{name}")).ok_or_else(|| bad(format!("no [mcp.{name}] in {} (servers from a project config are edited there)", c.paths.user_config().display())))?;
    Ok(spec_view(name, &t, &vault(c).ok()))
}

fn process_get(c: &ConnCtx, name: &str) -> Res {
    valid_name(name)?;
    let t = user_table(c, &format!("plugins.{name}")).ok_or_else(|| bad(format!("no [plugins.{name}] in {}", c.paths.user_config().display())))?;
    Ok(spec_view(name, &t, &vault(c).ok()))
}

/// The form view of an `[mcp.<name>]` / `[plugins.<name>]` table.
fn spec_view(name: &str, t: &toml::Table, v: &Option<Vault>) -> Value {
    let strs = |k: &str| t.get(k).and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>()).unwrap_or_default();
    json!({
        "name": name,
        "transport": transport_of(t),
        "command": t.get("command").and_then(|x| x.as_str()).unwrap_or(""),
        "args": strs("args"),
        "env": kv_view(t.get("env"), v),
        "cwd": t.get("cwd").and_then(|x| x.as_str()).unwrap_or(""),
        "url": t.get("url").and_then(|x| x.as_str()).unwrap_or(""),
        "headers": kv_view(t.get("headers"), v),
        "auth": t.get("auth").and_then(|x| x.as_str()).unwrap_or("none"),
        "enabled": t.get("enabled").and_then(|x| x.as_bool()).unwrap_or(true),
        "timeout_secs": t.get("timeout_secs").and_then(|x| x.as_integer()),
        "trust": t.get("trust").and_then(|x| x.as_str()).unwrap_or("full"),
        "exclude_tools": strs("exclude_tools"),
        "advanced": t.keys().filter(|k| !MANAGED.contains(&k.as_str()) && !matches!(k.as_str(), "exclude_tools" | "tools")).cloned().collect::<Vec<_>>(),
    })
}

/// Keys the MCP form owns; everything else in the table (sampling, roots, tool costs…) is kept.
const MANAGED: &[&str] = &["command", "args", "env", "cwd", "url", "transport", "headers", "auth", "enabled", "timeout_secs", "trust"];

/// Form spec → table (secrets as references, pending vault writes in `pend`).
fn spec_table(name: &str, spec: &Value, base: Option<&toml::Table>, section: &str, pend: &mut Pending) -> Result<toml::Table, (i32, String)> {
    let mut t = base.cloned().unwrap_or_default();
    for k in MANAGED {
        t.remove(*k);
    }
    let str_of = |k: &str| spec[k].as_str().unwrap_or("").trim().to_string();
    let prefix = if section == "plugins" { "PLUGIN" } else { "MCP" };
    match spec["transport"].as_str().unwrap_or("stdio") {
        "stdio" => {
            let cmd = str_of("command");
            if cmd.is_empty() {
                return Err(bad("command is required for a stdio server (for example npx, uvx, python3 or a full path)"));
            }
            t.insert("command".into(), cmd.into());
            let args: Vec<toml::Value> = match &spec["args"] {
                Value::Array(a) => a.iter().filter_map(|x| x.as_str()).map(|x| toml::Value::String(x.to_string())).collect(),
                Value::String(s) => split_args(s).into_iter().map(toml::Value::String).collect(),
                _ => vec![],
            };
            if !args.is_empty() {
                t.insert("args".into(), toml::Value::Array(args));
            }
            let env = kv_rows(&spec["env"], base.and_then(|b| b.get("env")).and_then(|v| v.as_table()), &[prefix, name], pend)?;
            if !env.is_empty() {
                t.insert("env".into(), toml::Value::Table(env));
            }
            if !str_of("cwd").is_empty() {
                t.insert("cwd".into(), str_of("cwd").into());
            }
        }
        tr @ ("http" | "sse") => {
            let url = str_of("url");
            if url.is_empty() {
                return Err(bad("url is required for an HTTP server"));
            }
            t.insert("url".into(), url.into());
            if tr == "sse" {
                t.insert("transport".into(), "sse".into());
            }
            let h = kv_rows(&spec["headers"], base.and_then(|b| b.get("headers")).and_then(|v| v.as_table()), &[prefix, name], pend)?;
            if !h.is_empty() {
                t.insert("headers".into(), toml::Value::Table(h));
            }
            if spec["auth"].as_str() == Some("oauth") {
                t.insert("auth".into(), "oauth".into());
            }
        }
        other => return Err(bad(format!("transport `{other}`: stdio, http or sse"))),
    }
    if spec["enabled"].as_bool() == Some(false) {
        t.insert("enabled".into(), false.into());
    }
    if let Some(n) = spec["timeout_secs"].as_u64().filter(|n| *n > 0) {
        t.insert("timeout_secs".into(), toml::Value::Integer(n.min(86_400) as i64));
    }
    if let Some(tr) = spec["trust"].as_str().filter(|t| *t == "untrusted") {
        t.insert("trust".into(), tr.into());
    }
    Ok(t)
}

/// `"-y @scope/pkg --root \"/my dir\""` → argv (double or single quotes group; no escapes).
fn split_args(s: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut any = false;
    for ch in s.chars() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '"' | '\'') => {
                quote = Some(ch);
                any = true;
            }
            (None, c) if c.is_whitespace() => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                any = false;
            }
            (None, c) => cur.push(c),
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Save an MCP server or a process plugin from the form. A stdio server first comes back with
/// `consent_required` and the exact argv/env/cwd line `seagent mcp add` prints; the page shows
/// it and saves again with `consent: true`.
fn mcp_save(c: &ConnCtx, section: &str, p: &Value) -> Res {
    let name = p["name"].as_str().unwrap_or("").trim().to_string();
    valid_name(&name)?;
    let original = p["original"].as_str().map(str::trim).filter(|o| !o.is_empty()).map(String::from);
    if let Some(o) = &original {
        valid_name(o)?;
    }
    let base = original.as_deref().and_then(|o| user_table(c, &format!("{section}.{o}")));
    let mut pend = Pending::default();
    let t = spec_table(&name, &p["spec"], base.as_ref(), section, &mut pend)?;
    let cfg = crate::mcp_cli::server_config(&name, &t).map_err(bad)?;
    if cfg.url.is_none() && p["consent"].as_bool() != Some(true) {
        return Ok(consent_needed(&name, &cfg));
    }
    let renamed = original.as_deref().is_some_and(|o| o != name);
    crate::mcp_cli::save_server(&c.paths, section, &name, &t, original.is_some() && !renamed).map_err(bad)?;
    let stored = pend.store(c)?;
    if renamed {
        crate::mcp_cli::remove_server(&c.paths, section, original.as_deref().unwrap_or("")).map_err(fail)?;
    }
    Ok(json!({"ok": true, "name": name, "restart": true, "secrets": stored, "message": format!("saved [{section}.{name}] in {}", c.paths.user_config().display())}))
}

/// The stdio consent answer: the exact line `seagent mcp add` prints, plus where the program
/// resolves (or that it does not).
fn consent_needed(name: &str, cfg: &seagent_plugin::McpServerConfig) -> Value {
    let cmd = cfg.command.as_deref().unwrap_or("");
    let resolved = resolve_program(cmd);
    json!({"ok": false, "consent_required": true, "consent": crate::mcp_cli::stdio_consent(name, cfg), "warning": resolved.is_none().then(|| not_found(cmd)), "resolved": resolved.map(|p| p.display().to_string())})
}

/// `seagent mcp test <name>` for a saved server, or a draft from the form (`spec`) before it is
/// saved. Failures come back as `{ok: false, stage, error}` so the page can say what broke.
fn mcp_test(c: &ConnCtx, p: &Value) -> Res {
    let draft = p["spec"].is_object();
    let name = match p["name"].as_str().map(str::trim).filter(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None if draft => "draft".to_string(),
        None => return Err(bad("name is required")),
    };
    valid_name(&name)?;
    let v = Arc::new(vault(c)?);
    let mut pend = Pending::default();
    let mut cfg = if draft {
        let base = user_table(c, &format!("mcp.{name}"));
        let t = spec_table(&name, &p["spec"], base.as_ref(), "mcp", &mut pend)?;
        crate::mcp_cli::server_config(&name, &t).map_err(bad)?
    } else {
        let all = fresh(c)?;
        let t = all.mcp.get(&name).ok_or_else(|| bad(format!("no MCP server `{name}`")))?;
        match crate::mcp_cli::server_config(&name, t) {
            Ok(x) => x,
            Err(e) => return Ok(json!({"ok": false, "stage": "config", "error": e})),
        }
    };
    cfg.enabled = true;
    // A draft stdio server runs a program the person typed: show the same consent line
    // `seagent mcp add` prints and start it only once they confirmed.
    if draft && cfg.url.is_none() && p["consent"].as_bool() != Some(true) {
        return Ok(consent_needed(&name, &cfg));
    }
    let mut resolved = None;
    if let Some(cmd) = cfg.command.clone() {
        match resolve_program(&cmd) {
            Some(p) => resolved = Some(p.display().to_string()),
            None => return Ok(json!({"ok": false, "stage": "command", "error": not_found(&cmd)})),
        }
    }
    // A draft runs in a scratch data dir: its catalog cache and first-load pins must not
    // land under a name that may never be saved.
    let scratch = draft.then(|| seagent_core::tmp::TempDir::new_in(&c.paths.data, "mcp-draft"));
    let cache = match &scratch {
        Some(d) => d.path().join("mcp-cache"),
        None => c.paths.data.join("mcp-cache"),
    };
    let t0 = Instant::now();
    let mut reg = seagent_plugin::Registry::load(&BTreeMap::from([(name.clone(), cfg.clone())]), &cache, pend.secrets(v));
    let r = if draft && reg.catalog_tools(&name).is_some() { Ok(0) } else { reg.refresh(&name) };
    let ms = t0.elapsed().as_millis() as u64;
    let out = match r {
        Ok(_) => {
            let tools: Vec<Value> = reg
                .catalog_tools(&name)
                .unwrap_or_default()
                .iter()
                .map(|t| json!({"name": t.name, "description": t.description.chars().take(300).collect::<String>(), "read_only": t.read_only, "destructive": t.destructive, "exposed": cfg.exposes(&t.name)}))
                .collect();
            let withheld: Vec<Value> = reg.withheld().get(&name).into_iter().flatten().map(|(t, why)| json!({"tool": t, "why": why})).collect();
            json!({"ok": true, "ms": ms, "tools": tools, "withheld": withheld, "resolved": resolved, "warnings": reg.warnings()})
        }
        Err(e) => json!({"ok": false, "stage": "connect", "ms": ms, "error": e, "resolved": resolved, "hint": if cfg.uses_oauth() { "this server signs in with OAuth: use Sign in first" } else { "" }}),
    };
    reg.shutdown();
    Ok(out)
}

/// Turn one tool on or off: `exclude_tools`, or the `tools` allow list when the server has one.
fn mcp_tool(c: &ConnCtx, name: &str, tool: &str, enabled: bool) -> Res {
    valid_name(name)?;
    need(tool, "tool")?;
    let mut t = user_table(c, &format!("mcp.{name}")).ok_or_else(|| bad(format!("no [mcp.{name}] in the user config")))?;
    let list = |t: &toml::Table, k: &str| t.get(k).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect::<Vec<_>>());
    let arr = |v: Vec<String>| toml::Value::Array(v.into_iter().map(toml::Value::String).collect());
    if let Some(mut allow) = list(&t, "tools") {
        allow.retain(|x| x != tool);
        if enabled {
            allow.push(tool.to_string());
        }
        t.insert("tools".into(), arr(allow));
    } else {
        let mut ex = list(&t, "exclude_tools").unwrap_or_default();
        ex.retain(|x| x != tool);
        if !enabled {
            ex.push(tool.to_string());
        }
        if ex.is_empty() {
            t.remove("exclude_tools");
        } else {
            t.insert("exclude_tools".into(), arr(ex));
        }
    }
    let cfg = crate::mcp_cli::save_server(&c.paths, "mcp", name, &t, true).map_err(bad)?;
    Ok(json!({"ok": true, "tool": tool, "enabled": cfg.exposes(tool), "restart": true}))
}

fn mcp_presets(q: &str) -> Value {
    let list: Vec<&crate::mcp_presets::Preset> = if q.is_empty() { crate::mcp_presets::catalog().iter().collect() } else { crate::mcp_presets::search(q) };
    json!(list
        .iter()
        .map(|p| json!({"name": p.name, "description": p.description, "url": p.url, "auth": p.auth, "source": p.source, "keywords": p.keywords,
            "env": p.env.iter().map(|e| json!({"name": e.name, "prompt": e.prompt, "secret": e.secret, "required": e.required})).collect::<Vec<_>>()}))
        .collect::<Vec<_>>())
}

/// `seagent mcp add <name> --preset P --env K=V`, with the preset's secrets taken from the
/// form into the vault (the CLI asks for `seagent secrets set` instead).
fn mcp_preset_add(c: &ConnCtx, p: &Value) -> Res {
    let pn = p["preset"].as_str().unwrap_or("");
    let preset = crate::mcp_presets::get(pn).ok_or_else(|| bad(format!("no preset `{pn}`")))?;
    let name = p["name"].as_str().map(str::trim).filter(|n| !n.is_empty()).unwrap_or(&preset.name).to_string();
    valid_name(&name)?;
    let known = vault(c)?.names();
    let mut vals = BTreeMap::new();
    let mut secrets = vec![];
    for e in &preset.env {
        let v = p["env"][&e.name].as_str().unwrap_or("").trim().to_string();
        if e.secret {
            if !v.is_empty() {
                secrets.push((e.name.clone(), v));
            } else if e.required && !known.contains(&e.name) {
                return Err(bad(format!("{} is required ({})", e.name, e.prompt)));
            }
        } else if !v.is_empty() {
            vals.insert(e.name.clone(), v);
        }
    }
    let block = crate::mcp_presets::config_block(&name, preset, &vals).map_err(bad)?;
    let root: toml::Table = block.parse().map_err(|e| fail(format!("preset block: {e}")))?;
    let t = root.get("mcp").and_then(|m| m.get(&name)).and_then(|v| v.as_table()).cloned().unwrap_or_default();
    crate::mcp_cli::save_server(&c.paths, "mcp", &name, &t, false).map_err(bad)?;
    let stored = Pending(secrets).store(c)?;
    Ok(json!({"ok": true, "name": name, "oauth": preset.auth == "oauth", "secrets": stored, "notes": crate::mcp_presets::notes(preset), "restart": true}))
}

/// Known `mcp.json` locations of other MCP clients, as `(label, path)`; only existing files.
/// Every platform's location is listed on every platform (a file that is not there is just
/// skipped), so there is no per-OS branch to drift.
fn import_candidates(home: &Path, appdata: Option<&Path>, ws: &Path) -> Vec<(String, PathBuf)> {
    let mut v: Vec<(&str, PathBuf)> = vec![
        ("Claude Code", home.join(".claude.json")),
        ("Claude Desktop", home.join("Library/Application Support/Claude/claude_desktop_config.json")),
        ("Claude Desktop", home.join(".config/Claude/claude_desktop_config.json")),
        ("Cursor", home.join(".cursor/mcp.json")),
        ("Cursor (project)", ws.join(".cursor/mcp.json")),
        ("VS Code", home.join("Library/Application Support/Code/User/mcp.json")),
        ("VS Code", home.join(".config/Code/User/mcp.json")),
        ("VS Code (project)", ws.join(".vscode/mcp.json")),
        ("Windsurf", home.join(".codeium/windsurf/mcp_config.json")),
        ("Project .mcp.json", ws.join(".mcp.json")),
    ];
    if let Some(a) = appdata {
        v.push(("Claude Desktop", a.join("Claude").join("claude_desktop_config.json")));
        v.push(("VS Code", a.join("Code").join("User").join("mcp.json")));
    }
    let mut out: Vec<(String, PathBuf)> = vec![];
    for (l, p) in v {
        if p.is_file() && !out.iter().any(|(_, q)| q == &p) {
            out.push((l.to_string(), p));
        }
    }
    out
}

/// The servers object of any of the shapes: `mcpServers` (Claude, Cursor, Windsurf),
/// `servers` (VS Code `mcp.json`) or `mcp.servers` (VS Code `settings.json`).
fn import_servers(text: &str) -> Result<serde_json::Map<String, Value>, String> {
    let v = crate::ops::migrate::json5(text).map_err(|e| format!("not JSON: {e}"))?;
    v.get("mcpServers")
        .or_else(|| v.get("servers"))
        .or_else(|| v.get("mcp").and_then(|m| m.get("servers")))
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(|| "no `mcpServers` / `servers` object in this file".to_string())
}

/// Preview (`apply` false) or import the servers of an `mcp.json`: pasted `text`, an uploaded
/// file's text, or one of the detected `candidate` paths (only those: no arbitrary reads).
/// Credential-looking env values move to the vault like `seagent migrate` does.
fn mcp_import(c: &ConnCtx, p: &Value) -> Res {
    let cands = import_candidates(&c.home, c.appdata.as_deref(), &c.ws);
    let text = match (p["text"].as_str().filter(|t| !t.trim().is_empty()), p["candidate"].as_str().filter(|x| !x.is_empty())) {
        (Some(t), _) => t.to_string(),
        (None, Some(path)) => {
            let (_, f) = cands.iter().find(|(_, f)| f.display().to_string() == path).ok_or_else(|| bad("that file is not one of the detected MCP client configs"))?;
            std::fs::read_to_string(f).map_err(|e| fail(format!("{}: {e}", f.display())))?
        }
        (None, None) => return Ok(json!({"candidates": cands.iter().map(|(l, f)| json!({"label": l, "path": f.display().to_string(), "servers": std::fs::read_to_string(f).ok().and_then(|t| import_servers(&t).ok()).map(|s| s.len()).unwrap_or(0)})).collect::<Vec<_>>()})),
    };
    let servers = import_servers(&text).map_err(bad)?;
    let existing = fresh(c)?.mcp;
    let pick: Option<Vec<String>> = p["names"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect());
    let apply = p["apply"].as_bool() == Some(true);
    let overwrite = p["overwrite"].as_bool() == Some(true);
    let mut rows = vec![];
    for (n, s) in &servers {
        let mut acts = vec![];
        crate::ops::migrate::mcp(&mut acts, n, s);
        let mut table = None;
        let mut secrets = vec![];
        for a in acts {
            match a {
                crate::ops::migrate::Act::Config(k, toml::Value::Table(t)) => table = Some((k.trim_start_matches("mcp.").to_string(), t)),
                crate::ops::migrate::Act::Secret(k, v) => secrets.push((k, v)),
                _ => {}
            }
        }
        let Some((name, t)) = table else {
            rows.push(json!({"name": n, "error": "neither `command` nor `url`"}));
            continue;
        };
        let check = crate::mcp_cli::server_config(&name, &t);
        let mut row = json!({"name": name, "transport": transport_of(&t), "exists": existing.contains_key(&name), "secrets": secrets.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            "target": t.get("url").and_then(|v| v.as_str()).map(String::from).unwrap_or_else(|| format!("{} {}", t.get("command").and_then(|v| v.as_str()).unwrap_or(""), t.get("args").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" ")).unwrap_or_default())),
            "error": check.as_ref().err(), "placeholders": toml::to_string(&t).unwrap_or_default().contains("${")});
        if apply && check.is_ok() && pick.as_ref().is_none_or(|p| p.contains(&name)) {
            if existing.contains_key(&name) && !overwrite {
                row["skipped"] = json!("already configured");
            } else {
                match crate::mcp_cli::save_server(&c.paths, "mcp", &name, &t, overwrite).map_err(bad).and_then(|_| Pending(secrets).store(c)) {
                    Ok(_) => row["imported"] = json!(true),
                    Err(e) => row["error"] = json!(e.1),
                }
            }
        }
        rows.push(row);
    }
    Ok(json!({"servers": rows, "applied": apply}))
}

/// Records what the OAuth flow wants the person to see; the page polls `login.status`.
struct ShowLogin {
    name: String,
    logins: Arc<Mutex<BTreeMap<String, Login>>>,
}

impl seagent_plugin::oauth::Prompter for ShowLogin {
    fn open(&self, url: &str) {
        if let Some(l) = self.logins.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&self.name) {
            l.url = Some(url.to_string());
        }
    }
    fn device(&self, uri: &str, code: &str, complete: Option<&str>) {
        if let Some(l) = self.logins.lock().unwrap_or_else(|e| e.into_inner()).get_mut(&self.name) {
            l.verification_uri = Some(complete.unwrap_or(uri).to_string());
            l.user_code = Some(code.to_string());
        }
    }
}

/// `seagent mcp login <name> [--device]` in the background. Browser mode listens on this
/// machine's loopback for the redirect (open the URL on this machine); device mode works from
/// any browser (the server must support the device grant).
fn mcp_login(c: &ConnCtx, name: &str, mode: &str) -> Res {
    valid_name(name)?;
    let cfg = fresh(c)?;
    let (cfgs, _) = crate::ext::mcp_configs(&cfg);
    let sc = cfgs.get(name).cloned().ok_or_else(|| bad(format!("no MCP server `{name}` in config")))?;
    let url = sc.url.clone().ok_or_else(|| bad("OAuth applies to HTTP servers (`url`), not stdio"))?;
    {
        let mut l = c.logins.lock().unwrap_or_else(|e| e.into_inner());
        if l.get(name).is_some_and(|x| x.state == "waiting") {
            return Ok(login_status(c, name));
        }
        l.insert(name.to_string(), Login { state: "waiting", ..Default::default() });
    }
    let (logins, data, n, device) = (c.logins.clone(), c.paths.data.clone(), name.to_string(), mode == "device");
    let name_done = n.clone();
    std::thread::spawn(move || {
        let show = ShowLogin { name: n.clone(), logins: logins.clone() };
        let challenge = seagent_plugin::oauth::probe_challenge(&url);
        let wait = Duration::from_secs(600);
        let r = if device { seagent_plugin::oauth::login_device(&url, challenge.as_deref(), &sc.oauth, &show, wait) } else { seagent_plugin::oauth::login_browser(&url, challenge.as_deref(), &sc.oauth, &show, wait) };
        let r = r.and_then(|t| seagent_plugin::oauth::Store::new(&data, &n).save(t));
        let ok = r.is_ok();
        {
            let mut l = logins.lock().unwrap_or_else(|e| e.into_inner());
            let e = l.entry(n).or_default();
            match r {
                Ok(()) => e.state = "done",
                Err(err) => {
                    e.state = "error";
                    e.error = Some(format!("login failed: {err}"));
                }
            }
        }
        // Signed in: restart the server with its new token.
        if ok {
            crate::ops::connectors_live::applied("mcp", &name_done);
        }
    });
    // Give the flow a moment to produce its URL or device code, so one round trip usually does.
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(5) {
        let l = login_status(c, name);
        if l["url"].is_string() || l["user_code"].is_string() || l["state"] != "waiting" {
            return Ok(l);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(login_status(c, name))
}

fn login_status(c: &ConnCtx, name: &str) -> Value {
    let l = c.logins.lock().unwrap_or_else(|e| e.into_inner()).get(name).cloned();
    let logged_in = valid_name(name).is_ok() && seagent_plugin::oauth::Store::new(&c.paths.data, name).has_tokens();
    match l {
        Some(l) => json!({"state": l.state, "url": l.url, "user_code": l.user_code, "verification_uri": l.verification_uri, "error": l.error, "logged_in": logged_in}),
        None => json!({"state": "idle", "logged_in": logged_in}),
    }
}

/// `seagent mcp pins accept <name>`: re-approve a server whose tools changed.
fn mcp_pins_accept(c: &ConnCtx, name: &str) -> Res {
    valid_name(name)?;
    let cfg = fresh(c)?;
    let (cfgs, _) = crate::ext::mcp_configs(&cfg);
    let sc = cfgs.get(name).cloned().ok_or_else(|| bad(format!("no MCP server `{name}`")))?;
    let v = Arc::new(vault(c)?);
    let mut reg = seagent_plugin::Registry::load(&BTreeMap::from([(name.to_string(), sc)]), &c.paths.data.join("mcp-cache"), crate::ext::secrets_fn(&v));
    let r = reg.accept_pins(name);
    reg.shutdown();
    r.map(|n| json!({"ok": true, "accepted": n, "restart": true})).map_err(fail)
}

// ───────────────────────── skills ─────────────────────────

/// `seagent skills <argv…>`: the very function the CLI prints.
fn skills_cli(c: &ConnCtx, argv: &[String]) -> Res {
    let cfg = fresh(c)?;
    let ctx = seagent_skills::hub::cli::Ctx { cfg: &cfg, paths: &c.paths, ws: &c.ws, ask: None };
    seagent_skills::hub::cli::run(&ctx, argv).map(|text| json!({"ok": true, "text": text})).map_err(fail)
}

fn skills_search(c: &ConnCtx, q: &str, source: &str, limit: u64) -> Res {
    let mut argv = if q.is_empty() { vec!["browse".to_string()] } else { vec!["search".to_string(), q.to_string()] };
    argv.extend(["--json".into(), "--source".into(), if source.is_empty() { "all".into() } else { source.into() }, "--limit".into(), limit.clamp(1, 100).to_string()]);
    let r = skills_cli(c, &argv)?;
    let text = r["text"].as_str().unwrap_or("[]");
    let list: Value = serde_json::from_str(text).unwrap_or_else(|_| json!([]));
    Ok(json!({"results": list}))
}

/// Skills shipped with SE Agent (`share/skills`), marked when the catalog already has them.
fn skills_bundled(c: &ConnCtx) -> Res {
    let Some(dir) = seagent_skills::hub::sync::bundled_dir() else { return Ok(json!({"dir": null, "skills": []})) };
    let have: Vec<String> = seagent_skills::skill::discover(&seagent_skills::skill::roots(&c.paths, &c.ws, &[])).into_iter().map(|s| s.name).collect();
    let list = seagent_skills::skill::discover(&[(dir.clone(), seagent_skills::skill::Source::Bundled)]);
    Ok(json!({"dir": dir.display().to_string(), "skills": list.iter().map(|s| json!({"name": s.name, "description": s.description, "category": s.category, "installed": have.contains(&s.name)})).collect::<Vec<_>>()}))
}

/// 25 MiB is the hub's own bundle cap; base64 costs a third more on the wire.
const MAX_UPLOAD: usize = 34 * 1024 * 1024;

/// A skill picked on the person's computer — a folder (every file, relative paths), one
/// `SKILL.md`, or a `.zip` — installed through `Hub::install_bundle`: the same quarantine,
/// size caps, signature/capability gates and scanner as `seagent skills install`.
fn skills_upload(c: &ConnCtx, p: &Value) -> Res {
    let files = p["files"].as_array().ok_or_else(|| bad("files is required ([{path, data}] with base64 data)"))?;
    let mut total = 0usize;
    let mut raw: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for f in files {
        let path = f["path"].as_str().unwrap_or("").replace('\\', "/");
        let data = f["data"].as_str().unwrap_or("");
        let data = data.split_once("base64,").map(|x| x.1).unwrap_or(data);
        total += data.len();
        if total > MAX_UPLOAD {
            return Err(bad("the upload is larger than the 25 MiB skill bundle limit"));
        }
        let bytes = seagent_net::crypto::b64_decode(data).ok_or_else(|| bad(format!("{path}: not base64")))?;
        if path.to_ascii_lowercase().ends_with(".zip") && files.len() == 1 {
            raw = seagent_skills::hub::zip::members(&bytes, seagent_skills::hub::install::Hub::MAX_BUNDLE_FILE_BYTES).ok_or_else(|| bad("not a readable ZIP archive"))?;
        } else {
            raw.insert(path.trim_start_matches('/').to_string(), bytes);
        }
    }
    let files = bundle_root(raw).ok_or_else(|| bad("no SKILL.md in the upload (pick the skill's folder, its SKILL.md or a ZIP of it)"))?;
    let label = p["label"].as_str().unwrap_or("upload").to_string();
    let mut b = seagent_skills::hub::model::SkillBundle { name: String::new(), files, source: "local".into(), identifier: format!("upload:{label}"), trust_level: "community".into(), metadata: Default::default() };
    let cfg = fresh(c)?;
    let st = seagent_skills::core::settings::Store::new(&c.paths);
    let hub = seagent_skills::hub::install::Hub::new(&seagent_skills::core::settings::Settings::load(&cfg), &st);
    let force = p["force"].as_bool() == Some(true);
    let o = seagent_skills::hub::install::InstallOpts { category: p["category"].as_str().unwrap_or("").trim().into(), name: p["name"].as_str().unwrap_or("").trim().into(), force, user_force: force };
    let i = hub.install_bundle(&mut b, &o).map_err(fail)?;
    Ok(json!({"ok": true, "name": i.name, "path": i.path.display().to_string(), "text": format!("{}\nInstalled '{}' → {}{}", i.report, i.name, i.path.display(), if i.advisory.is_empty() { String::new() } else { format!("\n{}", i.advisory) })}))
}

/// The files with `SKILL.md` at the root: a folder pick or a ZIP usually wraps everything in
/// one top directory (`my-skill/SKILL.md`), which is stripped.
fn bundle_root(files: BTreeMap<String, Vec<u8>>) -> Option<BTreeMap<String, Vec<u8>>> {
    if files.contains_key("SKILL.md") {
        return Some(files);
    }
    let top = files.keys().filter(|k| k.ends_with("/SKILL.md") && k.matches('/').count() == 1).map(|k| k.trim_end_matches("SKILL.md").to_string()).next()?;
    Some(files.into_iter().filter_map(|(k, v)| k.strip_prefix(&top).map(|r| (r.to_string(), v))).collect())
}

// ───────────────────────── plugins ─────────────────────────

fn plugins(c: &ConnCtx, f: impl FnOnce(&seagent_skills::hub::plugins::Plugins) -> Result<String, String>) -> Res {
    let cfg = fresh(c)?;
    let pm = seagent_skills::hub::plugins::Plugins::new(&cfg, &c.paths);
    f(&pm).map(|text| json!({"ok": true, "text": text, "restart": true})).map_err(fail)
}

/// Start a process plugin once and report what it declares (`seagent plugins` shows the same).
fn process_test(c: &ConnCtx, p: &Value) -> Res {
    let name = p["name"].as_str().unwrap_or("").trim().to_string();
    valid_name(&name)?;
    let v = Arc::new(vault(c)?);
    let mut pend = Pending::default();
    let cfg = if p["spec"].is_object() {
        let base = user_table(c, &format!("plugins.{name}"));
        let t = spec_table(&name, &p["spec"], base.as_ref(), "plugins", &mut pend)?;
        crate::mcp_cli::server_config(&name, &t).map_err(bad)?
    } else {
        let t = fresh(c)?.plugins.get(&name).cloned().ok_or_else(|| bad(format!("no [plugins.{name}]")))?;
        crate::mcp_cli::server_config(&name, &t).map_err(bad)?
    };
    if p["spec"].is_object() && p["consent"].as_bool() != Some(true) {
        return Ok(consent_needed(&name, &cfg));
    }
    if let Some(cmd) = cfg.command.as_deref() {
        if resolve_program(cmd).is_none() {
            return Ok(json!({"ok": false, "stage": "command", "error": not_found(cmd)}));
        }
    }
    let t0 = Instant::now();
    match seagent_plugin::PluginHost::start(&name, &cfg, pend.secrets(v)) {
        Ok(h) => Ok(json!({"ok": true, "ms": t0.elapsed().as_millis() as u64, "declares": crate::plugin_json(&Arc::new(h))})),
        Err(e) => Ok(json!({"ok": false, "stage": "start", "error": e})),
    }
}

// ───────────────────────── ACP agents ─────────────────────────

fn acp_list(c: &ConnCtx) -> Res {
    use seagent_app::acp_client::{command_line, AcpConfig, PRESETS};
    let cfg = fresh(c)?;
    let acp = AcpConfig::parse(&cfg.acp).map_err(fail)?;
    let user = user_root(c);
    let mut out = vec![];
    for n in acp.names() {
        let Ok(spec) = acp.agent(&n) else { continue };
        out.push(json!({
            "name": n,
            "command": spec.command,
            "args": spec.args,
            "command_line": command_line(&spec),
            "description": spec.description,
            "permission_mode": spec.permission_mode,
            "env": spec.env.keys().collect::<Vec<_>>(),
            "preset": PRESETS.iter().any(|p| p.0 == n),
            "configured": acp.agents.contains_key(&n),
            "editable": crate::ops::confcli::get_in(&user, &format!("acp.agents.{n}")).is_some(),
            "resolved": resolve_program(&spec.command).map(|p| p.display().to_string()),
        }));
    }
    Ok(json!({"agents": out, "permission_mode": acp.permission_mode, "timeout_secs": acp.timeout_secs}))
}

/// `[acp.agents.<name>]`: an external agent `seagent acp-client <name>` (and delegation) drives.
fn acp_save(c: &ConnCtx, p: &Value) -> Res {
    let name = p["name"].as_str().unwrap_or("").trim().to_string();
    valid_name(&name)?;
    let base = user_table(c, &format!("acp.agents.{name}"));
    let mut pend = Pending::default();
    let mut t = toml::Table::new();
    let cmd = p["command"].as_str().unwrap_or("").trim();
    if cmd.is_empty() {
        return Err(bad("command is required"));
    }
    t.insert("command".into(), cmd.into());
    let args = match &p["args"] {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
        Value::String(s) => split_args(s),
        _ => vec![],
    };
    if !args.is_empty() {
        t.insert("args".into(), toml::Value::Array(args.into_iter().map(toml::Value::String).collect()));
    }
    let env = kv_rows(&p["env"], base.as_ref().and_then(|b| b.get("env")).and_then(|v| v.as_table()), &["ACP", &name], &mut pend)?;
    if !env.is_empty() {
        t.insert("env".into(), toml::Value::Table(env));
    }
    for k in ["permission_mode", "description"] {
        if let Some(v) = p[k].as_str().map(str::trim).filter(|v| !v.is_empty()) {
            t.insert(k.into(), v.into());
        }
    }
    // Validate as the agent table `seagent acp-client` would parse.
    let cfg = fresh(c)?;
    let mut acp = cfg.acp.clone();
    let agents = acp.entry("agents").or_insert_with(|| toml::Value::Table(toml::Table::new()));
    if let Some(a) = agents.as_table_mut() {
        a.insert(name.clone(), toml::Value::Table(t.clone()));
    }
    let parsed = seagent_app::acp_client::AcpConfig::parse(&acp).map_err(bad)?;
    if let Some(m) = parsed.agents.get(&name).and_then(|a| a.permission_mode.as_deref()) {
        seagent_app::acp_client::PermissionMode::parse(m).map_err(bad)?;
    }
    crate::ops::confcli::put_table(&c.paths, &format!("acp.agents.{name}"), Some(&t)).map_err(fail)?;
    let stored = pend.store(c)?;
    Ok(json!({"ok": true, "name": name, "secrets": stored, "resolved": resolve_program(cmd).map(|p| p.display().to_string()), "warning": resolve_program(cmd).is_none().then(|| not_found(cmd))}))
}

// ───────────────────────── A2A ─────────────────────────

fn a2a_config(c: &ConnCtx) -> Result<(bool, seagent_app::a2a::A2aConfig), (i32, String)> {
    let cfg = fresh(c)?;
    let app = seagent_app::AppConfig::parse(&cfg.app).map_err(fail)?;
    Ok((app.enabled, app.a2a))
}

fn a2a_list(c: &ConnCtx) -> Res {
    let (app_on, a) = a2a_config(c)?;
    let names = vault(c).map(|v| v.names()).unwrap_or_default();
    Ok(json!({
        "app_enabled": app_on,
        "enabled": a.enabled,
        "name": a.name,
        "public_url": a.public_url,
        "peers": a.peers.iter().map(|(n, t)| json!({"name": n, "ref": secret_ref(t), "set": secret_ref(t).is_none_or(|r| names.iter().any(|x| x == r))})).collect::<Vec<_>>(),
        "agents": a.agents.iter().map(|(n, r)| json!({"name": n, "url": r.url, "capabilities": r.capabilities, "token": r.token.is_some()})).collect::<Vec<_>>(),
    }))
}

/// `[app.a2a.agents.<name>]`: a remote agent the `a2a_*` tools may call.
fn a2a_agent_save(c: &ConnCtx, p: &Value) -> Res {
    let name = p["name"].as_str().unwrap_or("").trim().to_string();
    valid_name(&name)?;
    let url = p["url"].as_str().unwrap_or("").trim();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(bad("url must start with https:// (or http:// on a trusted network)"));
    }
    let mut t = toml::Table::new();
    t.insert("url".into(), url.into());
    let mut pend = Pending::default();
    let tok = p["token"].as_str().unwrap_or("").trim();
    if !tok.is_empty() {
        t.insert("token".into(), pend.value(vault_name(&["A2A", &name, "TOKEN"]), tok).into());
    } else if let Some(old) = user_table(c, &format!("app.a2a.agents.{name}")).and_then(|o| o.get("token").cloned()) {
        t.insert("token".into(), old);
    }
    let caps: Vec<toml::Value> = p["capabilities"].as_array().into_iter().flatten().filter_map(|x| x.as_str()).map(|x| x.trim()).filter(|x| !x.is_empty()).map(|x| toml::Value::String(x.into())).collect();
    if !caps.is_empty() {
        t.insert("capabilities".into(), toml::Value::Array(caps));
    }
    toml::Value::Table(t.clone()).try_into::<seagent_app::a2a::RemoteAgent>().map_err(|e| bad(format!("[app.a2a.agents.{name}]: {}", e.message())))?;
    crate::ops::confcli::put_table(&c.paths, &format!("app.a2a.agents.{name}"), Some(&t)).map_err(fail)?;
    let stored = pend.store(c)?;
    Ok(json!({"ok": true, "name": name, "secrets": stored, "restart": true}))
}

/// Fetch the remote agent's card (`/.well-known/agent-card.json`), as `a2a_discover` does.
fn a2a_agent_test(c: &ConnCtx, name: &str) -> Res {
    valid_name(name)?;
    let (_, a) = a2a_config(c)?;
    let r = a.agents.get(name).ok_or_else(|| bad(format!("no remote agent `{name}`")))?;
    let url = format!("{}/.well-known/agent-card.json", r.url.trim_end_matches('/'));
    let agent: ureq::Agent = seagent_net::http::builder().http_status_as_error(false).timeout_global(Some(Duration::from_secs(10))).build().into();
    let mut req = agent.get(&url);
    let tok;
    if let Some(t) = &r.token {
        tok = vault(c)?.substitute(t);
        req = req.header("authorization", &format!("Bearer {tok}"));
    }
    match req.call() {
        Ok(mut resp) => {
            let status = resp.status().as_u16();
            let body: Value = resp.body_mut().read_to_string().ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
            if (200..300).contains(&status) && body.is_object() {
                Ok(json!({"ok": true, "status": status, "agent": body["name"], "description": body["description"], "skills": body["skills"].as_array().map(|s| s.len()).unwrap_or(0)}))
            } else {
                Ok(json!({"ok": false, "status": status, "error": format!("{url} answered HTTP {status} without an agent card")}))
            }
        }
        Err(e) => Ok(json!({"ok": false, "error": format!("{url}: {e}")})),
    }
}

/// `[app.a2a.peers] <name> = "{{secret:…}}"`: a client allowed to call this agent.
fn a2a_peer_save(c: &ConnCtx, name: &str, token: &str) -> Res {
    valid_name(name)?;
    let token = token.trim();
    if token.len() < 16 && secret_ref(token).is_none() {
        return Err(bad("the peer token must be at least 16 characters (or a {{secret:NAME}} reference)"));
    }
    let mut pend = Pending::default();
    let r = pend.value(vault_name(&["A2A_PEER", name]), token);
    let stored = pend.store(c)?;
    crate::ops::confcli::set(&c.paths, &format!("app.a2a.peers.{name}"), &toml::Value::String(r).to_string()).map_err(fail)?;
    Ok(json!({"ok": true, "name": name, "secrets": stored, "restart": true}))
}

// ───────────────────────── webhooks ─────────────────────────

fn webhook_file(c: &ConnCtx, channel: &str) -> Result<PathBuf, (i32, String)> {
    valid_name(channel)?;
    let cfg = fresh(c)?;
    match cfg.channels.get(channel).and_then(|t| t.get("kind")).and_then(|v| v.as_str()) {
        Some("webhook") => Ok(seagent_channel::webhook::subscriptions_path(&c.paths.data.join("channels"), channel)),
        Some(k) => Err(bad(format!("channel `{channel}` is a {k} channel, not a webhook listener"))),
        None => Err(bad(format!("no channel `{channel}` (add a webhook channel under Chat channels first)"))),
    }
}

fn webhooks_list(c: &ConnCtx) -> Res {
    let cfg = fresh(c)?;
    let mut out = vec![];
    for (n, t) in cfg.channels.iter().filter(|(_, t)| t.get("kind").and_then(|v| v.as_str()) == Some("webhook")) {
        let f = seagent_channel::webhook::subscriptions_path(&c.paths.data.join("channels"), n);
        let subs = seagent_channel::webhook::list_subscriptions(&f).unwrap_or_default();
        out.push(json!({
            "channel": n,
            "listen": t.get("listen").and_then(|v| v.as_str()),
            "static_routes": t.get("routes").and_then(|v| v.as_table()).map(|r| r.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
            "subscriptions": subs.iter().map(|(name, r)| json!({"route": name, "path": r["path"].as_str().map(String::from).unwrap_or(format!("/webhooks/{name}")), "deliver": r["deliver"].as_str().unwrap_or("reply"), "cron_job": r["cron_job"], "prompt": r["prompt"], "enabled": r["enabled"] != json!(false)})).collect::<Vec<_>>(),
        }));
    }
    Ok(json!({"channels": out}))
}

/// `seagent webhook subscribe <channel> <route> [json]`; the signing secret is shown once.
fn webhooks_subscribe(c: &ConnCtx, channel: &str, route: &str, p: &Value) -> Res {
    let f = webhook_file(c, channel)?;
    need(route, "route")?;
    let spec = if p["spec"].is_object() { p["spec"].clone() } else { json!({}) };
    let r = seagent_channel::webhook::subscribe(&f, route, spec).map_err(bad)?;
    Ok(json!({"ok": true, "route": route, "path": r["path"].as_str().map(String::from).unwrap_or(format!("/webhooks/{route}")), "secret": r["secret"]}))
}

/// `seagent webhook test <channel> <route>`: a signed POST to the running listener.
fn webhooks_test(c: &ConnCtx, channel: &str, route: &str, payload: Option<&str>) -> Res {
    webhook_file(c, channel)?;
    need(route, "route")?;
    let cfg = fresh(c)?;
    let v = vault(c)?;
    let (url, secret) = crate::hooks_cli::route_target(&cfg, &c.paths, channel, route, &|s: &str| v.substitute(s)).map_err(bad)?;
    let payload = payload.filter(|x| !x.trim().is_empty()).unwrap_or(crate::hooks_cli::DEFAULT_TEST_PAYLOAD);
    serde_json::from_str::<Value>(payload).map_err(|e| bad(format!("payload is not JSON: {e}")))?;
    match crate::hooks_cli::webhook_test(&url, &secret, payload) {
        Ok((status, body)) => Ok(json!({"ok": (200..300).contains(&status), "url": url, "status": status, "body": body.chars().take(2000).collect::<String>()})),
        Err(e) => Ok(json!({"ok": false, "url": url, "error": e})),
    }
}

#[cfg(test)]
mod tests;
