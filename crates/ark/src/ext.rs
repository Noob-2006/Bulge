//! Extensions: MCP servers (connectors), plugins, channels, hooks and custom
//! commands, assembled from config into tools + hooks for the kernel.

use ark_channel::router::{Action, Command, Router};
use ark_channel::{Channel, ChannelError, ChannelErrorKind, Inbound, Outbound};
use ark_core::{Cancel, Tool};
use ark_kernel::commands::{self, CommandDef, Expanded};
use ark_kernel::config::{Config, Paths};
use ark_kernel::hooks::{self, Hook, HookDecision, HookEvent};
use ark_kernel::kernel::{Kernel, KernelError, RunOpts};
use ark_kernel::vault::Vault;
use ark_plugin::{McpServerConfig, PluginHost, Registry};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Inbox = Arc<Mutex<Option<Receiver<(String, Value)>>>>;

/// Extensions plus the tools and hooks they contribute.
pub type Loaded = (Ext, Vec<Arc<dyn Tool>>, Vec<Arc<dyn Hook>>);

pub struct Ext {
    pub registry: Registry,
    pub plugins: Vec<Arc<PluginHost>>,
    pub channels: BTreeMap<String, (Arc<dyn Channel>, ark_channel::config::ChannelConfig)>,
    pub commands: Vec<CommandDef>,
    pub warnings: Vec<String>,
}

pub fn secrets_fn(v: &Arc<Vault>) -> Arc<dyn Fn(&str) -> String + Send + Sync> {
    let v = v.clone();
    Arc::new(move |s: &str| v.substitute(s))
}

fn parse<T: serde::de::DeserializeOwned>(kind: &str, name: &str, t: &toml::Table) -> Result<T, String> {
    toml::Value::Table(t.clone()).try_into().map_err(|e: toml::de::Error| format!("[{kind}.{name}]: {}", e.message()))
}

pub fn mcp_configs(cfg: &Config) -> (BTreeMap<String, McpServerConfig>, Vec<String>) {
    let mut ok = BTreeMap::new();
    let mut warn = Vec::new();
    for (n, t) in &cfg.mcp {
        match parse::<McpServerConfig>("mcp", n, t).and_then(|c| c.validate(n).map(|_| c)) {
            Ok(c) if is_self(&c) => warn.push(format!("[mcp.{n}] is ark itself (`ark mcp serve`); its tools are already built in, skipping the duplicate")),
            Ok(c) => {
                ok.insert(n.clone(), c);
            }
            Err(e) => warn.push(e),
        }
    }
    (ok, warn)
}

/// An MCP entry that runs this very binary's `mcp serve` would only mirror
/// the builtin tools: twice the index tokens and a confused model.
fn is_self(c: &McpServerConfig) -> bool {
    let (Some(cmd), Ok(me)) = (c.command.as_deref(), std::env::current_exe()) else { return false };
    let same = Path::new(cmd).canonicalize().ok().is_some_and(|p| p == me) || (cmd == "ark" && me.file_name().is_some_and(|f| f == "ark"));
    same && c.args.first().map(String::as_str) == Some("mcp") && c.args.get(1).map(String::as_str) == Some("serve")
}

/// Load everything. Never fails: a broken extension becomes a warning so one
/// bad server can't take the agent down. `channels` = also build channels.
pub fn load(cfg: &Config, paths: &Paths, vault: &Arc<Vault>, ws: &Path, with_channels: bool) -> Loaded {
    let secrets = secrets_fn(vault);
    let (mcp, mut warnings) = mcp_configs(cfg);
    let registry = Registry::load(&mcp, &paths.data.join("mcp-cache"), secrets.clone());
    warnings.extend(registry.warnings().iter().cloned());
    let mut tools = registry.tools();
    let mut taken: HashSet<String> = tools.iter().map(|t| t.spec().name).collect();
    let mut hooks: Vec<Arc<dyn Hook>> = Vec::new();
    match hooks::shell_hooks(&cfg.hooks) {
        Ok(h) => hooks.extend(h),
        Err(e) => warnings.push(format!("hooks: {e}")),
    }

    let mut plugins = Vec::new();
    for (n, t) in &cfg.plugins {
        let started = parse::<McpServerConfig>("plugins", n, t).and_then(|c| PluginHost::start(n, &c, secrets.clone()));
        match started {
            Ok(p) => {
                let p = Arc::new(p);
                match p.tools(&mut taken) {
                    Ok(t) => tools.extend(t),
                    Err(e) => warnings.push(format!("plugin {n}: {e}")),
                }
                if !p.hooks().is_empty() {
                    hooks.push(Arc::new(PluginHook(p.clone())));
                }
                plugins.push(p);
            }
            Err(e) => warnings.push(format!("plugin {n}: {e}")),
        }
    }

    let mut channels = BTreeMap::new();
    if with_channels || !cfg.channels.is_empty() {
        let state = paths.data.join("channels");
        let _ = std::fs::create_dir_all(&state);
        for (n, t) in &cfg.channels {
            let json = serde_json::to_value(t).unwrap_or(Value::Null);
            let built = ark_channel::config::parse_config(n, &json).and_then(|c| {
                let ch: Result<Arc<dyn Channel>, String> = match &c {
                    ark_channel::config::ChannelConfig::Plugin { plugin, .. } => match plugins.iter().find(|p| &p.name == plugin) {
                        Some(p) if p.channels().iter().any(|c| c == n) => Ok(Arc::new(PluginChannel::new(n, p.clone())) as Arc<dyn Channel>),
                        Some(_) => Err(format!("[channels.{n}]: plugin `{plugin}` does not offer a channel named `{n}`")),
                        None => Err(format!("[channels.{n}]: no plugin `{plugin}` is configured")),
                    },
                    // Building a webhook binds its port: only the daemon listens.
                    ark_channel::config::ChannelConfig::Webhook { listen: Some(_), .. } if !with_channels => Err(String::new()),
                    other => ark_channel::config::build(n, other, &state, &secrets),
                };
                ch.map(|ch| (ch, c))
            });
            match built {
                Ok(x) => {
                    channels.insert(n.clone(), x);
                }
                Err(e) if e.is_empty() => {}
                Err(e) => warnings.push(e),
            }
        }
    }
    if !channels.is_empty() {
        let targets = channels.iter().map(|(n, (ch, c))| (n.clone(), ark_channel::tool::Target { channel: ch.clone(), default_chat: c.default_chat().map(String::from) })).collect();
        tools.push(Arc::new(ark_channel::tool::ChannelSend::new(targets)));
    }
    let commands = commands::discover(&commands::dirs(&paths.data, ws));
    (Ext { registry, plugins, channels, commands, warnings }, tools, hooks)
}

/// MCP server instructions, appended (capped) to the identity segment.
pub fn instructions(ext: &Ext) -> String {
    ext.registry.instructions().iter().map(|(s, t)| format!("MCP server `{s}`: {}", t.chars().take(800).collect::<String>())).collect::<Vec<_>>().join("\n")
}

impl Ext {
    /// `/command args` → text, including MCP prompts as `/mcp__server__prompt k=v …`.
    pub fn expand(&self, input: &str) -> Result<String, String> {
        let extra = |name: &str, args: &str| -> Option<Result<String, String>> {
            let rest = name.strip_prefix("mcp__")?;
            let (server, prompt) = rest.split_once("__")?;
            let info = self.registry.prompts().into_iter().find(|p| p.server == server && p.name == prompt)?;
            let parts = commands::split_args(args);
            let mut map = BTreeMap::new();
            for (i, part) in parts.iter().enumerate() {
                match part.split_once('=') {
                    Some((k, v)) => map.insert(k.to_string(), v.to_string()),
                    // Positional: fill declared arguments in order.
                    None => info.arguments.get(i).map(|(k, _)| map.insert(k.clone(), part.clone())).unwrap_or(None),
                };
            }
            Some(self.registry.get_prompt(server, prompt, &map))
        };
        match commands::expand(input, &self.commands, &extra) {
            Expanded::Plain => Ok(input.to_string()),
            Expanded::Text(t) => Ok(t),
            Expanded::Error(e) => Err(e),
        }
    }
}

// ───────────────────────── plugin adapters ─────────────────────────

struct PluginHook(Arc<PluginHost>);

impl Hook for PluginHook {
    fn name(&self) -> String {
        format!("plugin:{}", self.0.name)
    }
    fn wants(&self, event: HookEvent, _: Option<&str>) -> bool {
        let n = serde_json::to_value(event).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        self.0.hooks().contains(&n)
    }
    fn run(&self, event: HookEvent, payload: &Value) -> Result<HookDecision, String> {
        let n = serde_json::to_value(event).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
        let mut p = payload.clone();
        // The plugin protocol names the modifiable part `input`.
        p["input"] = payload.get("tool_input").or_else(|| payload.get("prompt")).cloned().unwrap_or(Value::Null);
        match self.0.hook(&n, p)? {
            ark_plugin::plugin::HookDecision::Allow => Ok(HookDecision::Allow),
            ark_plugin::plugin::HookDecision::Deny(r) => Ok(HookDecision::Block(r)),
            ark_plugin::plugin::HookDecision::Modify(v) => Ok(HookDecision::Modify(v)),
        }
    }
}

/// A channel served by a plugin process (inbound notifications are fanned out
/// per channel name, since one plugin may serve several).
struct PluginChannel {
    id: String,
    host: Arc<PluginHost>,
    rx: Inbox,
    backlog: Mutex<Vec<(String, Value)>>,
}

static PLUGIN_RX: Mutex<Vec<(String, Inbox)>> = Mutex::new(Vec::new());

impl PluginChannel {
    fn new(id: &str, host: Arc<PluginHost>) -> Self {
        let mut all = PLUGIN_RX.lock().unwrap();
        let rx = match all.iter().find(|(n, _)| *n == host.name) {
            Some((_, rx)) => rx.clone(),
            None => {
                let rx = Arc::new(Mutex::new(host.take_inbound()));
                all.push((host.name.clone(), rx.clone()));
                rx
            }
        };
        PluginChannel { id: id.into(), host, rx, backlog: Mutex::new(Vec::new()) }
    }
}

impl Channel for PluginChannel {
    fn id(&self) -> &str {
        &self.id
    }
    fn poll(&self, cancel: &Cancel) -> Result<Vec<Inbound>, ChannelError> {
        let mut out = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut backlog = self.backlog.lock().unwrap();
        while out.is_empty() && std::time::Instant::now() < deadline && !cancel.is_cancelled() {
            let got = {
                let rx = self.rx.lock().unwrap();
                match rx.as_ref() {
                    Some(r) => r.recv_timeout(Duration::from_millis(100)).ok(),
                    None => return Err(ChannelError::new(ChannelErrorKind::Fatal, "plugin inbound stream already taken")),
                }
            };
            backlog.extend(got);
            let (mine, rest): (Vec<_>, Vec<_>) = backlog.drain(..).partition(|(c, _)| *c == self.id);
            *backlog = rest;
            for (_, m) in mine {
                let s = |k: &str| m.get(k).and_then(Value::as_str).unwrap_or("").to_string();
                out.push(Inbound { channel: self.id.clone(), chat: s("chat"), sender: s("sender"), sender_name: s("sender_name"), text: s("text"), message_id: s("id"), ts: 0 });
            }
        }
        Ok(out)
    }
    fn send(&self, out: &Outbound) -> Result<(), ChannelError> {
        self.host.channel_send(&self.id, json!({"chat": out.chat, "text": out.text, "reply_to": out.reply_to})).map(|_| ()).map_err(|e| ChannelError::new(ChannelErrorKind::Network, e))
    }
}

// ───────────────────────── channel router (daemon) ─────────────────────────

/// Poll every channel; route messages into sessions; reply when runs finish.
pub fn spawn_channel_loops(k: Kernel, ext: &Ext, ws: PathBuf, cancel: Cancel) -> Vec<std::thread::JoinHandle<()>> {
    if ext.channels.is_empty() {
        return vec![];
    }
    let cfgs: HashMap<String, _> = ext.channels.iter().map(|(n, (_, c))| (n.clone(), c.router())).collect();
    let router = Arc::new(Router::open(k.paths.data.join("channels/routes.json"), cfgs));
    if let Some(w) = &router.load_warning {
        eprintln!("arkd: channels: {w}");
    }
    let commands = Arc::new(ext.commands.clone());
    ext.channels
        .iter()
        .map(|(name, (ch, _))| {
            let (k, ch, router, ws, cancel, name, commands) = (k.clone(), ch.clone(), router.clone(), ws.clone(), cancel.clone(), name.clone(), commands.clone());
            std::thread::spawn(move || channel_loop(&k, &name, ch, &router, &ws, &cancel, &commands))
        })
        .collect()
}

fn channel_loop(k: &Kernel, name: &str, ch: Arc<dyn Channel>, router: &Arc<Router>, ws: &Path, cancel: &Cancel, commands: &Arc<Vec<CommandDef>>) {
    let mut backoff = 1u64;
    while !cancel.is_cancelled() {
        let msgs = match ch.poll(cancel) {
            Ok(m) => {
                backoff = 1;
                m
            }
            Err(e) => {
                if matches!(e.kind, ChannelErrorKind::Auth | ChannelErrorKind::Fatal) {
                    eprintln!("arkd: channel {name} stopped: {}", e.message);
                    return;
                }
                let wait = match e.kind {
                    ChannelErrorKind::RateLimited { retry_after: Some(d) } => d.as_secs().max(1),
                    _ => backoff,
                };
                eprintln!("arkd: channel {name}: {} (retry in {wait}s)", e.message);
                backoff = (backoff * 2).min(60);
                sleep_cancellable(Duration::from_secs(wait), cancel);
                continue;
            }
        };
        for m in msgs {
            handle_inbound(k, &ch, router, ws, commands, m);
        }
    }
}

fn sleep_cancellable(d: Duration, c: &Cancel) {
    let until = std::time::Instant::now() + d;
    while std::time::Instant::now() < until && !c.is_cancelled() {
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn reply(ch: &Arc<dyn Channel>, chat: &str, text: &str, to: Option<&str>) {
    let out = Outbound { chat: chat.into(), text: if text.trim().is_empty() { "(no reply)".into() } else { text.into() }, reply_to: to.map(String::from) };
    if let Err(e) = ch.send(&out) {
        eprintln!("arkd: channel {}: reply failed: {}", ch.id(), e.message);
    }
}

fn handle_inbound(k: &Kernel, ch: &Arc<dyn Channel>, router: &Arc<Router>, ws: &Path, commands: &Arc<Vec<CommandDef>>, m: Inbound) {
    let chat = m.chat.clone();
    let mid = Some(m.message_id.as_str()).filter(|s| !s.is_empty()).map(String::from);
    match router.route(&m) {
        Action::Ignore { reason } => eprintln!("arkd: channel {}: ignored message from {}: {reason}", m.channel, m.sender),
        Action::Command { cmd, session, .. } => {
            let text = match cmd {
                Command::New => "Started fresh: your next message opens a new session.".to_string(),
                Command::Stop => match session {
                    Some(s) if k.interrupt(&s) => "Stopping.".into(),
                    _ => "Nothing is running.".into(),
                },
                Command::Status => match session {
                    Some(s) => format!("session {s} · {}", if k.is_running(&s) { "running" } else { "idle" }),
                    None => "no session yet".into(),
                },
                Command::Help => {
                    let mut h = ark_channel::router::HELP.to_string();
                    for c in commands.iter() {
                        h.push_str(&format!("\n/{} — {}", c.name, c.description));
                    }
                    h
                }
            };
            reply(ch, &chat, &text, mid.as_deref());
        }
        Action::Submit { key, session, text } => {
            let sid = match session {
                Some(s) if k.store.open(&s).is_ok() => s,
                _ => match k.create_session(ws, None, None, Some(&format!("{} · {}", key.channel, m.sender_name))) {
                    Ok(s) => {
                        router.bind(&key, &s);
                        s
                    }
                    Err(e) => return reply(ch, &chat, &format!("error: {e}"), mid.as_deref()),
                },
            };
            let text = match commands::expand(&text, commands, &|_, _| None) {
                Expanded::Text(t) => t,
                Expanded::Error(e) => return reply(ch, &chat, &e, mid.as_deref()),
                Expanded::Plain => text,
            };
            if let Err(e) = k.submit(&sid, &text, &format!("channel:{}", key.channel)) {
                return reply(ch, &chat, &format!("error: {e}"), mid.as_deref());
            }
            if k.is_running(&sid) {
                return; // steers the running turn; its reply covers this message
            }
            let (k, ch) = (k.clone(), ch.clone());
            std::thread::spawn(move || match k.run(&sid, RunOpts::default()) {
                Ok(o) => {
                    let t = if o.reason.ok() { o.text } else { format!("{}\n\n[{}]", o.text, o.reason.label()) };
                    reply(&ch, &chat, &t, mid.as_deref());
                }
                Err(KernelError::AlreadyRunning(_)) => {}
                Err(e) => reply(&ch, &chat, &format!("error: {e}"), mid.as_deref()),
            });
        }
    }
}
