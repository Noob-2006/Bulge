//! Hot apply for the Connections page: a change saved in the console takes effect in the
//! running daemon instead of waiting for a restart.
//!
//! - **MCP servers** (add, edit, remove, enable, per-tool switch, sign-in, re-approved pins):
//!   the server's old client is stopped and a new one loaded with the daemon's own options
//!   (roots, sampling, elicitation); its `mcp__<name>__*` tools are swapped in the kernel
//!   (`Runtime::set_live_tools`) for turns that start from then on.
//! - **Chat channels** (add, edit, remove, enable): the channel loops stop, adapters whose
//!   table did not change are kept as they are (a listener keeps its port), changed and new
//!   ones are built with `ext::build_channels`, and the loops start again on the new set;
//!   `channel_send` / `message` follow the new set.
//! - **Webhook subscriptions** need nothing: the listener re-reads its subscription file.
//! - **Skills** installed, uploaded or removed are found on disk by the next skill index; a
//!   skill switched on or off refreshes the index's settings (running sessions get the usual
//!   per-turn delta) and rebuilds the `skill` tool.
//! - **Hooks** (shell hooks, packs, bundled, outbound): reloaded from the config and swapped
//!   in the kernel by name (`Runtime::replace_hooks`).
//! - **Gmail**: the watcher stops and starts again with the new setup.
//! - **ACP agents**: `acp_delegate` is rebuilt with the new agent list.
//! - **Process plugins** that only contribute tools start (or stop) live.
//!
//! What cannot be swapped in place is listed by [`RESTART_ONLY`] and reported to the page,
//! which offers the one-click restart (`ops::service::restart_detached`, the same helper as
//! `/restart`): plugins that bring hooks, channels, routes, providers, services or UI (or that
//! were started with the daemon), plugin packages, and A2A (part of the app server).

use crate::ext::{self, Ext};
use seagent_core::Cancel;
use seagent_kernel::config::{project_config, Config, Paths};
use seagent_kernel::kernel::Kernel;
use seagent_plugin::Registry;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Change kinds that only a daemon restart applies, with the reason shown in the page.
pub const RESTART_ONLY: &[(&str, &str)] = &[
    ("plugins", "this plugin brings hooks, channels, routes, providers, services or UI, which register when the daemon starts"),
    ("a2a", "A2A is part of the app server, which binds at start"),
];

struct Loops {
    /// The leader's cancel token (`None` while this node does not lead).
    parent: Option<Cancel>,
    child: Option<Cancel>,
    handles: Vec<std::thread::JoinHandle<()>>,
}

pub struct Live {
    k: Kernel,
    paths: Paths,
    ws: PathBuf,
    /// The extensions the channel loops run on now (the startup set until the first reload).
    ext: Mutex<Option<Arc<Ext>>>,
    loops: Mutex<Loops>,
    /// Startup registry: its client is stopped when the server is reloaded.
    startup_mcp: Option<Arc<Registry>>,
    /// MCP servers loaded since start, by name.
    mcp: Mutex<BTreeMap<String, Arc<Registry>>>,
    /// Restart-only changes made since start (keys of `RESTART_ONLY`).
    pending: Mutex<BTreeSet<String>>,
    /// Why channels failed to build on the last reload (shown as their status).
    channel_errors: Mutex<BTreeMap<String, String>>,
    /// Names of the hooks `hooks_ext::load` contributed (what a hook reload replaces).
    hook_names: Mutex<Vec<String>>,
    /// The Gmail watcher: leader token, its own token, its threads.
    gmail: Mutex<Loops>,
    /// Process plugins started since the daemon started (tools only).
    plugins: Mutex<BTreeMap<String, Arc<seagent_plugin::PluginHost>>>,
}

static LIVE: OnceLock<Arc<Live>> = OnceLock::new();

/// Called once by `seagent daemon run`; later calls return the first instance.
pub fn install(k: Kernel, paths: Paths, ws: PathBuf, ext: Option<Arc<Ext>>) -> Arc<Live> {
    LIVE.get_or_init(|| Arc::new(Live::new(k, paths, ws, ext))).clone()
}

/// The running daemon's hot-apply hub; `None` in the CLI and in tests that do not set one up.
pub fn get() -> Option<Arc<Live>> {
    LIVE.get().cloned()
}

impl Live {
    pub fn new(k: Kernel, paths: Paths, ws: PathBuf, ext: Option<Arc<Ext>>) -> Live {
        let startup_mcp = ext.as_ref().map(|e| e.registry.clone());
        // The hooks the daemon started from `[[hooks]]` / `[hooks_extra]` (same loader, same names).
        let slot = ext.as_ref().map(|e| e.kernel.clone()).unwrap_or_default();
        let startup_hooks: Vec<String> = crate::hooks_ext::load(&k.cfg, &paths, &ws, &slot, ext::secrets_fn(&k.vault)).0.iter().map(|h| h.name()).collect();
        let live = Live::with(k, paths, ws, ext, startup_mcp);
        *live.hook_names.lock().unwrap_or_else(|e| e.into_inner()) = startup_hooks;
        live
    }

    fn with(k: Kernel, paths: Paths, ws: PathBuf, ext: Option<Arc<Ext>>, startup_mcp: Option<Arc<Registry>>) -> Live {
        Live { k, paths, ws, ext: Mutex::new(ext), loops: Mutex::new(Loops { parent: None, child: None, handles: vec![] }), startup_mcp, mcp: Default::default(), pending: Default::default(), channel_errors: Default::default(), hook_names: Mutex::new(vec![]), gmail: Mutex::new(Loops { parent: None, child: None, handles: vec![] }), plugins: Default::default() }
    }

    /// The daemon's kernel (hook installs run its `before_install` hooks).
    pub fn kernel(&self) -> Kernel {
        self.k.clone()
    }

    fn fresh(&self) -> Result<Config, String> {
        Config::load(Some(&self.paths.user_config()), Some(&project_config(&self.ws)), &[])
    }

    // ───────────── channels ─────────────

    /// Start the channel loops under `parent` (the leader's token). Returns how many run.
    pub fn start_channels(&self, parent: Cancel) -> usize {
        let mut l = self.loops.lock().unwrap_or_else(|e| e.into_inner());
        stop_loops(&mut l);
        l.parent = Some(parent);
        self.spawn(&mut l)
    }

    fn spawn(&self, l: &mut Loops) -> usize {
        let Some(parent) = l.parent.clone().filter(|p| !p.is_cancelled()) else { return 0 };
        let Some(e) = self.ext.lock().unwrap_or_else(|e| e.into_inner()).clone() else { return 0 };
        let child = parent.child();
        l.handles = ext::spawn_channel_loops(self.k.clone(), &e, self.ws.clone(), child.clone());
        l.child = Some(child);
        e.channels.len()
    }

    /// The adapters the daemon runs now.
    pub fn channels(&self) -> BTreeMap<String, Arc<dyn seagent_channel::Channel>> {
        self.ext.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|e| ext::channel_map(e)).unwrap_or_default()
    }

    /// Re-read `[channels.*]` and run exactly that set: unchanged adapters stay, changed and
    /// new ones are built, removed ones stop.
    pub fn reload_channels(&self) -> Result<Value, String> {
        let cfg = self.fresh()?;
        let mut l = self.loops.lock().unwrap_or_else(|e| e.into_inner());
        let Some(cur) = self.ext.lock().unwrap_or_else(|e| e.into_inner()).clone() else { return Err("this daemon runs without extensions".into()) };
        // Stop first: a changed listener has to give its port back before it is rebuilt.
        stop_loops(&mut l);
        let mut keep = BTreeMap::new();
        let mut rebuild = cfg.clone();
        rebuild.channels.clear();
        for (n, t) in &cfg.channels {
            let parsed = seagent_channel::config::parse_config(n, &serde_json::to_value(t).unwrap_or(Value::Null));
            match (cur.channels.get(n), parsed) {
                (Some((ch, old)), Ok(new)) if *old == new => {
                    keep.insert(n.clone(), (ch.clone(), new));
                }
                _ => {
                    rebuild.channels.insert(n.clone(), t.clone());
                }
            }
        }
        for (n, (ch, _)) in &cur.channels {
            if !keep.contains_key(n) {
                ch.stop();
                ext::channel_states().lock().unwrap_or_else(|e| e.into_inner()).remove(n);
            }
        }
        let vault = Arc::new(seagent_kernel::vault::Vault::load(&self.paths.secrets())?);
        let mut warnings = vec![];
        let built = ext::build_channels(&rebuild, &self.paths, &ext::secrets_fn(&vault), &cur.plugins, true, &mut warnings);
        let (kept, started): (Vec<String>, Vec<String>) = (keep.keys().cloned().collect(), built.keys().cloned().collect());
        // A changed or new channel that did not build: say which and why.
        let failed: BTreeMap<String, String> = rebuild.channels.keys().filter(|n| !built.contains_key(*n)).map(|n| (n.clone(), warnings.iter().find(|w| w.contains(&format!("channel {n}:")) || w.contains(&format!("[channels.{n}]"))).cloned().unwrap_or_else(|| "did not build".into()))).collect();
        *self.channel_errors.lock().unwrap_or_else(|e| e.into_inner()) = failed.clone();
        keep.extend(built);
        let next = Arc::new(Ext { kernel: cur.kernel.clone(), registry: cur.registry.clone(), plugins: cur.plugins.clone(), channels: keep, commands: cur.commands.clone(), warnings: warnings.clone() });
        self.channel_tools(&next);
        *self.ext.lock().unwrap_or_else(|e| e.into_inner()) = Some(next);
        let running = self.spawn(&mut l);
        Ok(json!({"applied": failed.is_empty(), "kept": kept, "started": started, "failed": failed, "running": running, "leader": l.parent.is_some(), "warnings": warnings}))
    }

    /// Why `name` did not build on the last reload, if it did not.
    pub fn channel_error(&self, name: &str) -> Option<String> {
        self.channel_errors.lock().unwrap_or_else(|e| e.into_inner()).get(name).cloned()
    }

    /// `channel_send` and `message` reach the channels that run now.
    fn channel_tools(&self, e: &Ext) {
        let targets = e.channels.iter().map(|(n, (ch, c))| (n.clone(), seagent_channel::tool::Target { channel: ch.clone(), default_chat: c.default_chat().map(String::from) })).collect();
        let msg: seagent_channel::message_tool::Targets = e.channels.iter().map(|(n, (ch, c))| (n.clone(), (ch.clone(), c.default_chat().map(String::from)))).collect();
        type Tools = Vec<Arc<dyn seagent_core::Tool>>;
        let (send, message): (Tools, Tools) = if e.channels.is_empty() {
            (vec![], vec![])
        } else {
            (vec![Arc::new(seagent_channel::tool::ChannelSend::new(targets))], vec![Arc::new(seagent_channel::message_tool::MessageTool::new(msg))])
        };
        self.k.set_live_tools("channel_send", send);
        self.k.set_live_tools("message", message);
    }

    // ───────────── MCP ─────────────

    /// Stop server `name` and load it again from the config (or leave it stopped when it was
    /// removed or disabled); its tools are swapped for the next turn.
    pub fn reload_mcp(&self, name: &str) -> Result<Value, String> {
        let cfg = self.fresh()?;
        let (cfgs, _) = ext::mcp_configs(&cfg);
        if let Some(c) = self.startup_mcp.as_ref().and_then(|r| r.client(name)) {
            c.shutdown();
        }
        if let Some(old) = self.mcp.lock().unwrap_or_else(|e| e.into_inner()).remove(name) {
            old.shutdown();
        }
        let prefix = format!("mcp__{name}__");
        let Some(sc) = cfgs.get(name).filter(|c| c.enabled).cloned() else {
            self.k.set_live_tools(&prefix, vec![]);
            return Ok(json!({"applied": true, "running": false, "tools": 0, "state": if cfgs.contains_key(name) { "disabled" } else { "removed" }}));
        };
        let vault = Arc::new(seagent_kernel::vault::Vault::load(&self.paths.secrets())?);
        let slot = self.ext.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|e| e.kernel.clone()).unwrap_or_default();
        let opts = seagent_plugin::LoadOpts { roots: vec![self.ws.clone()], sampler: Some(ext::mcp_sampler(slot.clone())), elicitor: Some(ext::mcp_elicitor(slot)) };
        let reg = Registry::load_with(&BTreeMap::from([(name.to_string(), sc)]), &self.paths.data.join("mcp-cache"), ext::secrets_fn(&vault), &opts);
        let tools = reg.tools();
        let n = tools.len();
        self.k.set_live_tools(&prefix, tools);
        let warnings: Vec<String> = reg.warnings().to_vec();
        self.mcp.lock().unwrap_or_else(|e| e.into_inner()).insert(name.to_string(), Arc::new(reg));
        Ok(json!({"applied": true, "running": n > 0, "tools": n, "warnings": warnings}))
    }

    /// `(tools, running)` of a server loaded since start; `None` = the startup state holds.
    pub fn mcp_status(&self, name: &str) -> Option<(usize, bool)> {
        let m = self.mcp.lock().unwrap_or_else(|e| e.into_inner());
        m.get(name).map(|r| r.status().into_iter().find(|(n, _, _)| n == name).map(|(_, t, r)| (t, r)).unwrap_or((0, false)))
    }

    /// Whether `name` was reloaded or removed since start (its startup status is stale).
    pub fn mcp_touched(&self, name: &str) -> bool {
        self.mcp.lock().unwrap_or_else(|e| e.into_inner()).contains_key(name)
    }

    // ───────────── skills, hooks, Gmail, ACP, plugins ─────────────

    fn vault(&self) -> Result<Arc<seagent_kernel::vault::Vault>, String> {
        seagent_kernel::vault::Vault::load(&self.paths.secrets()).map(Arc::new)
    }

    /// `[skills]` changed (a skill switched on or off): new settings for the skills index and a
    /// rebuilt `skill` tool.
    pub fn reload_skills(&self) -> Result<Value, String> {
        let cfg = self.fresh()?;
        seagent_skills::core::index::shared(&cfg, &self.paths).set_settings(seagent_skills::core::settings::Settings::load(&cfg));
        self.k.set_live_tools("skill", seagent_skills::core::tools(&cfg, &self.paths, &self.ws));
        Ok(json!({"applied": true}))
    }

    /// Shell hooks, packs, bundled and outbound hooks reloaded from the config (consent included).
    pub fn reload_hooks(&self) -> Result<Value, String> {
        let cfg = self.fresh()?;
        let slot = self.ext.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(|e| e.kernel.clone()).unwrap_or_default();
        let (hooks, warnings) = crate::hooks_ext::load(&cfg, &self.paths, &self.ws, &slot, ext::secrets_fn(&self.vault()?));
        let names: Vec<String> = hooks.iter().map(|h| h.name()).collect();
        let mut old = self.hook_names.lock().unwrap_or_else(|e| e.into_inner());
        self.k.replace_hooks(&old, hooks);
        *old = names.clone();
        Ok(json!({"applied": true, "hooks": names, "warnings": warnings}))
    }

    /// Start the Gmail watcher under `parent` (the leader's token).
    pub fn start_gmail(&self, parent: Cancel) -> usize {
        let mut g = self.gmail.lock().unwrap_or_else(|e| e.into_inner());
        stop_loops(&mut g);
        g.parent = Some(parent);
        self.spawn_gmail(&mut g, &self.k.cfg.clone(), self.k.vault.clone())
    }

    fn spawn_gmail(&self, g: &mut Loops, cfg: &Config, vault: Arc<seagent_kernel::vault::Vault>) -> usize {
        let Some(parent) = g.parent.clone().filter(|p| !p.is_cancelled()) else { return 0 };
        let child = parent.child();
        g.handles = crate::hooks_ext::start_gmail(&self.k, cfg, vault, child.clone());
        g.child = Some(child);
        g.handles.len()
    }

    /// The Gmail setup changed: stop the watcher (its push listener frees its port) and start
    /// it again from the config.
    pub fn reload_gmail(&self) -> Result<Value, String> {
        let cfg = self.fresh()?;
        let vault = self.vault()?;
        let mut g = self.gmail.lock().unwrap_or_else(|e| e.into_inner());
        stop_loops(&mut g);
        let n = self.spawn_gmail(&mut g, &cfg, vault);
        Ok(json!({"applied": true, "running": n > 0, "leader": g.parent.is_some()}))
    }

    /// `[acp]` changed: `acp_delegate` with the new agent list.
    pub fn reload_acp(&self) -> Result<Value, String> {
        let cfg = self.fresh()?;
        let acp = seagent_app::acp_client::AcpConfig::parse(&cfg.acp)?;
        let names = acp.names();
        self.k.set_live_tools("acp_delegate", vec![Arc::new(seagent_app::acp_client::AcpDelegate { cfg: acp, gate: cfg.gate.clone(), vault: self.vault()? })]);
        Ok(json!({"applied": true, "agents": names}))
    }

    /// A process plugin saved or removed: one that only contributes tools starts (or stops)
    /// now; one the daemon started, or that brings more than tools, waits for a restart.
    pub fn reload_plugin(&self, name: &str) -> Result<Value, String> {
        if self.ext.lock().unwrap_or_else(|e| e.into_inner()).as_ref().is_some_and(|e| e.plugins.iter().any(|p| p.name == name)) {
            return Ok(json!({"applied": false, "restart": true, "why": "the daemon started this plugin; a restart replaces it"}));
        }
        let prefix = format!("mcp__{name}__");
        self.plugins.lock().unwrap_or_else(|e| e.into_inner()).remove(name);
        let cfg = self.fresh()?;
        let Some(t) = cfg.plugins.get(name) else {
            self.k.set_live_tools(&prefix, vec![]);
            return Ok(json!({"applied": true, "state": "removed"}));
        };
        let pc = crate::mcp_cli::server_config(name, t)?;
        if !pc.enabled {
            self.k.set_live_tools(&prefix, vec![]);
            return Ok(json!({"applied": true, "state": "disabled"}));
        }
        let mut warnings = vec![];
        let host = ext::start_guarded(&cfg, &self.paths.data, name, &pc, ext::secrets_fn(&self.vault()?), &mut warnings)?;
        let mut more = vec![];
        for (what, n) in [("hooks", host.hooks().len()), ("channels", host.channels().len()), ("commands", host.commands.len()), ("routes", host.routes.len()), ("providers", host.providers.len()), ("services", host.services.len()), ("CLI commands", host.cli.len()), ("middleware", host.middleware_kinds().len()), ("node commands", host.node_commands.len()), ("UI panels", host.ui.len()), ("backends", host.backends.len())] {
            if n > 0 {
                more.push(what);
            }
        }
        if host.context_engine.is_some() {
            more.push("a context engine");
        }
        if host.memory {
            more.push("a memory provider");
        }
        if host.dashboard_auth.is_some() {
            more.push("dashboard sign-in");
        }
        if !more.is_empty() {
            return Ok(json!({"applied": false, "restart": true, "why": format!("this plugin also brings {}, which register when the daemon starts", more.join(", "))}));
        }
        let mut taken: std::collections::HashSet<String> = self.k.tools_now().iter().map(|t| t.spec().name).filter(|n| !n.starts_with(&prefix)).collect();
        let tools = host.tools(&mut taken)?;
        let n = tools.len();
        self.k.set_live_tools(&prefix, tools);
        self.plugins.lock().unwrap_or_else(|e| e.into_inner()).insert(name.to_string(), Arc::new(host));
        Ok(json!({"applied": true, "tools": n, "warnings": warnings}))
    }

    // ───────────── restart-only changes ─────────────

    pub fn mark_restart(&self, kind: &str) {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).insert(kind.to_string());
    }

    pub fn pending_restart(&self) -> Vec<Value> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|k| json!({"kind": k, "why": RESTART_ONLY.iter().find(|(n, _)| n == k).map(|(_, w)| *w).unwrap_or("")})).collect()
    }
}

/// Cancel the running loops and wait (bounded) for them: channel polls return within about
/// 100 ms of a cancel; a stuck one is left to finish on its own.
fn stop_loops(l: &mut Loops) {
    if let Some(c) = l.child.take() {
        c.cancel();
    }
    let until = Instant::now() + Duration::from_secs(5);
    while l.handles.iter().any(|h| !h.is_finished()) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(25));
    }
    for h in std::mem::take(&mut l.handles) {
        if h.is_finished() {
            let _ = h.join();
        }
    }
}

/// What the page reports after a write: applied now, or waiting for a restart.
pub fn applied(kind: &str, name: &str) -> Value {
    let Some(live) = get() else { return json!({"applied": false, "restart": true, "why": "no running daemon to apply it to (it applies on the next start)"}) };
    let r = match kind {
        "mcp" => live.reload_mcp(name),
        "channels" => live.reload_channels(),
        "skills.toggle" => live.reload_skills(),
        "hooks" => live.reload_hooks(),
        "gmail" => live.reload_gmail(),
        "acp" => live.reload_acp(),
        "plugin.process" => match live.reload_plugin(name) {
            Ok(v) if v["restart"] == true => {
                live.mark_restart("plugins");
                return json!({"applied": false, "restart": true, "why": v["why"], "live": v});
            }
            r => r,
        },
        _ => {
            live.mark_restart(kind);
            return json!({"applied": false, "restart": true, "why": RESTART_ONLY.iter().find(|(n, _)| *n == kind).map(|(_, w)| *w).unwrap_or("")});
        }
    };
    match r {
        Ok(v) if v["applied"] == false => {
            let why = v["failed"].as_object().map(|f| f.values().filter_map(|x| x.as_str()).collect::<Vec<_>>().join("; ")).unwrap_or_default();
            json!({"applied": false, "restart": false, "why": why, "live": v})
        }
        Ok(v) => json!({"applied": true, "restart": false, "live": v}),
        Err(e) => json!({"applied": false, "restart": true, "why": e}),
    }
}
