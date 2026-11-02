//! Extensions: MCP servers (connectors), plugins, channels, hooks and custom
//! commands, assembled from config into tools + hooks for the kernel.

use ark_channel::access::Pairing;
use ark_channel::deliver::{Deliverer, Stream};
use ark_channel::router::{Action, Command, Router};
use ark_channel::{Channel, ChannelError, ChannelErrorKind, Inbound, Outbound};
use ark_core::{Cancel, Tool};
use ark_kernel::commands::{self, CommandDef, Expanded};
use ark_kernel::config::{Config, Paths};
use ark_kernel::hooks::{self, Hook, HookDecision, HookEvent};
use ark_kernel::kernel::{Kernel, KernelError, RunOpts};
use ark_kernel::vault::Vault;
use ark_plugin::{CommandReply, McpServerConfig, PluginHost, Registry};
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
    /// Set once the kernel exists; MCP sampling and elicitation go through it.
    pub kernel: Arc<std::sync::OnceLock<Kernel>>,
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
    let kernel: Arc<std::sync::OnceLock<Kernel>> = Arc::default();
    let opts = ark_plugin::LoadOpts { roots: vec![ws.to_path_buf()], sampler: Some(mcp_sampler(kernel.clone())), elicitor: Some(mcp_elicitor(kernel.clone())) };
    let registry = Registry::load_with(&mcp, &paths.data.join("mcp-cache"), secrets.clone(), &opts);
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
                if !p.hooks().is_empty() || !p.middleware_kinds().is_empty() {
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
                let ch: Result<Arc<dyn Channel>, String> = if c.is_plugin() {
                    let plugin = c.plugin.clone().unwrap_or_default();
                    match plugins.iter().find(|p| p.name == plugin) {
                        Some(p) if p.channels().iter().any(|c| c == n) => Ok(Arc::new(PluginChannel::new(n, p.clone())) as Arc<dyn Channel>),
                        Some(_) => Err(format!("[channels.{n}]: plugin `{plugin}` does not offer a channel named `{n}`")),
                        None => Err(format!("[channels.{n}]: no plugin `{plugin}` is configured")),
                    }
                } else if c.listens() && !with_channels {
                    // Building a listening channel binds its port: only the daemon listens.
                    Err(String::new())
                } else {
                    ark_channel::config::build(n, &c, &state, &secrets)
                };
                ch.map(|ch| (ch, c))
            });
            match built {
                Ok(x) => {
                    use ark_channel::access::{DmPolicy, GroupPolicy};
                    let p = &x.1.policy;
                    let public = matches!(p.dm_policy, DmPolicy::Open | DmPolicy::Pairing) || p.group_policy == GroupPolicy::Open;
                    if public && x.1.privacy_notice.is_none() {
                        warnings.push(format!("[channels.{n}] accepts people you have not listed but has no `privacy_notice` (個資法第 8 條告知義務; see docs/compliance-tw.md)"));
                    }
                    if x.1.kind == "whatsapp_cloud" {
                        warnings.push(format!("[channels.{n}] WhatsApp Business terms (2026-01-15) bar general-purpose AI assistants; scope this bot to a specific business use"));
                    }
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
        tools.extend(channels.values().flat_map(|(ch, _)| ch.tools()));
    }
    let commands = commands::discover(&commands::dirs(&paths.data, ws));
    (Ext { kernel, registry, plugins, channels, commands, warnings }, tools, hooks)
}

/// MCP server instructions, appended (capped) to the identity segment.
/// MCP `sampling/createMessage` → one completion with ark's model (aux model by default).
/// With `tools`, the model may answer with `tool_use` blocks (stopReason `toolUse`);
/// the server runs them and sends the results back in the next request.
fn mcp_sampler(slot: Arc<std::sync::OnceLock<Kernel>>) -> ark_plugin::mcp::Sampler {
    Arc::new(move |p: &Value| {
        let k = slot.get().ok_or("agent not ready")?;
        let (msgs, tools, system, max, model) = sampling_request(p)?;
        let (reply, used, stop) = k.sample(model.as_deref(), &system, msgs, tools, max, &Cancel::new())?;
        Ok(sampling_result(&reply, &used, stop, p.get("tools").is_some_and(|t| !t.is_null())))
    })
}

type Sampling = (Vec<ark_core::Message>, Vec<ark_core::ToolSchema>, String, u32, Option<String>);

/// CreateMessageRequest params → ark messages, tool schemas, system prompt, max tokens, model.
pub fn sampling_request(p: &Value) -> Result<Sampling, String> {
    use ark_core::{Block, Message, Role};
    let mut msgs = Vec::new();
    for m in p["messages"].as_array().into_iter().flatten() {
        // Content may be one block or a list.
        let blocks: Vec<&Value> = match &m["content"] {
            Value::Array(a) => a.iter().collect(),
            c => vec![c],
        };
        let content: Vec<Block> = blocks
            .iter()
            .map(|b| match b["type"].as_str() {
                Some("text") => Block::text(b["text"].as_str().unwrap_or("")),
                Some("tool_use") => Block::ToolUse { id: b["id"].as_str().unwrap_or("").into(), name: b["name"].as_str().unwrap_or("").into(), input: b["input"].clone() },
                Some("tool_result") => Block::ToolResult {
                    tool_use_id: b["toolUseId"].as_str().unwrap_or("").into(),
                    content: ark_plugin::mcp::render_content(&serde_json::json!({"content": b["content"], "structuredContent": b["structuredContent"]})),
                    is_error: b["isError"].as_bool().unwrap_or(false),
                },
                Some(t) => Block::text(format!("[{t} content omitted]")),
                None => Block::text(""),
            })
            .collect();
        msgs.push(Message { role: if m["role"] == "assistant" { Role::Assistant } else { Role::User }, content });
    }
    if msgs.is_empty() {
        return Err("sampling request has no messages".into());
    }
    let mut system = p["systemPrompt"].as_str().unwrap_or("").to_string();
    let mode = p["toolChoice"]["mode"].as_str().unwrap_or("auto");
    let tools: Vec<ark_core::ToolSchema> = if mode == "none" {
        vec![]
    } else {
        p["tools"].as_array().into_iter().flatten().map(|t| ark_core::ToolSchema { name: t["name"].as_str().unwrap_or("").into(), description: t["description"].as_str().unwrap_or("").into(), input_schema: ark_plugin::bridge::sanitize_schema(&t["inputSchema"]) }).collect()
    };
    if mode == "required" && !tools.is_empty() {
        system.push_str("\n\nRespond by calling one of the provided tools.");
    }
    let max = p["maxTokens"].as_u64().unwrap_or(1024) as u32;
    Ok((msgs, tools, system.trim().to_string(), max, p["_arkModel"].as_str().map(str::to_string)))
}

/// ark's reply → CreateMessageResult (`content` is a list when tools were offered).
pub fn sampling_result(reply: &ark_core::Message, model: &str, stop: ark_core::StopReason, with_tools: bool) -> Value {
    use ark_core::Block;
    let blocks: Vec<Value> = reply
        .content
        .iter()
        .filter_map(|b| match b {
            Block::Text { text } if !text.is_empty() => Some(serde_json::json!({"type": "text", "text": text})),
            Block::ToolUse { id, name, input } => Some(serde_json::json!({"type": "tool_use", "id": id, "name": name, "input": input})),
            _ => None,
        })
        .collect();
    let stop = match stop {
        ark_core::StopReason::ToolUse if blocks.iter().any(|b| b["type"] == "tool_use") => "toolUse",
        ark_core::StopReason::MaxTokens => "maxTokens",
        _ => "endTurn",
    };
    let content = if with_tools { Value::Array(blocks) } else { blocks.into_iter().next().unwrap_or(serde_json::json!({"type": "text", "text": ""})) };
    serde_json::json!({"role": "assistant", "content": content, "model": model, "stopReason": stop})
}

/// MCP `elicitation/create` → ask the human through the session's approver. Form mode
/// collects `field: value` lines; URL mode shows the full URL for the user to open
/// themselves (never opened automatically) and accepts once they confirm. Headless
/// sessions decline, as the spec allows.
fn mcp_elicitor(slot: Arc<std::sync::OnceLock<Kernel>>) -> ark_plugin::mcp::Elicitor {
    Arc::new(move |server: &str, p: &Value| {
        let k = slot.get().ok_or("agent not ready")?;
        if p["mode"].as_str() == Some("url") {
            let Some(q) = url_question(server, p) else { return Ok(serde_json::json!({"action": "decline"})) };
            return Ok(match k.approver.ask(&format!("mcp:{server}"), &q) {
                Ok(a) if url_answer_accepts(&a) => serde_json::json!({"action": "accept"}),
                Ok(_) => serde_json::json!({"action": "decline"}),
                Err(_) => serde_json::json!({"action": "cancel"}),
            });
        }
        let props = p["requestedSchema"]["properties"].as_object().cloned().unwrap_or_default();
        let mut q = format!("MCP server `{server}` asks: {}", p["message"].as_str().unwrap_or(""));
        if !props.is_empty() {
            q.push_str("\nAnswer as `field: value` lines:");
            for (name, s) in &props {
                q.push_str(&format!("\n- {name} ({}){}", s["type"].as_str().unwrap_or("string"), s["description"].as_str().map(|d| format!(": {d}")).unwrap_or_default()));
            }
        }
        q.push_str("\n(reply `decline` to refuse)");
        let answer = match k.approver.ask(&format!("mcp:{server}"), &q) {
            Ok(a) => a,
            Err(_) => return Ok(serde_json::json!({"action": "decline"})),
        };
        if answer.trim().eq_ignore_ascii_case("decline") || answer.trim().is_empty() {
            return Ok(serde_json::json!({"action": "decline"}));
        }
        let mut content = serde_json::Map::new();
        for line in answer.lines() {
            if let Some((k2, v)) = line.split_once(':') {
                let key = k2.trim().trim_start_matches("- ");
                if let Some(schema) = props.get(key) {
                    let v = v.trim();
                    let val = match schema["type"].as_str() {
                        Some("boolean") => Value::Bool(matches!(v.to_lowercase().as_str(), "true" | "yes" | "y" | "是")),
                        Some("integer") => v.parse::<i64>().map(Value::from).unwrap_or(Value::String(v.into())),
                        Some("number") => v.parse::<f64>().map(Value::from).unwrap_or(Value::String(v.into())),
                        _ => Value::String(v.into()),
                    };
                    content.insert(key.to_string(), val);
                }
            }
        }
        // A single free-text field may be answered without the `field:` prefix.
        if content.is_empty() && props.len() == 1 {
            content.insert(props.keys().next().unwrap().clone(), Value::String(answer.trim().into()));
        }
        Ok(serde_json::json!({"action": "accept", "content": content}))
    })
}

/// The prompt for a URL-mode elicitation; None when the URL is not plain http(s).
pub fn url_question(server: &str, p: &Value) -> Option<String> {
    let url = p["url"].as_str().filter(|u| (u.starts_with("https://") || u.starts_with("http://")) && !u.chars().any(char::is_control))?;
    let host = url.split("://").nth(1).and_then(|r| r.split(['/', '?', '#']).next()).unwrap_or("");
    Some(format!(
        "MCP server `{server}` asks you to open a page in your browser ({}):\n{url}\n(site: {host})\nOpen it yourself only if you trust it, then reply `done`; reply `decline` to refuse.",
        p["message"].as_str().unwrap_or("no reason given")
    ))
}

pub fn url_answer_accepts(a: &str) -> bool {
    let a = a.trim().to_lowercase();
    !a.is_empty() && !matches!(a.as_str(), "decline" | "no" | "n" | "cancel" | "deny" | "否" | "拒絕")
}

pub fn instructions(ext: &Ext) -> String {
    ext.registry.instructions().iter().map(|(s, t)| format!("MCP server `{s}`: {}", t.chars().take(800).collect::<String>())).collect::<Vec<_>>().join("\n")
}

impl Ext {
    /// The plugin serving `/name`, if any.
    pub fn plugin_command(&self, name: &str) -> Option<&Arc<PluginHost>> {
        self.plugins.iter().find(|p| p.commands.iter().any(|c| c.name == name))
    }

    /// Run `line` if it is a plugin slash command (`None` otherwise). `context` tells the
    /// plugin where it was typed: `{"surface": "chat" | "tui" | "channel", "session", …}`.
    pub fn run_command(&self, line: &str, context: Value) -> Option<Result<CommandReply, String>> {
        run_plugin_command(&self.plugins, line, context)
    }

    /// Plugin commands as (name, description) for help listings.
    pub fn plugin_commands(&self) -> Vec<(String, String)> {
        self.plugins.iter().flat_map(|p| p.commands.iter().map(|c| (c.name.clone(), if c.args.is_empty() { c.description.clone() } else { format!("{} — {}", c.args, c.description) }))).collect()
    }

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

fn run_plugin_command(plugins: &[Arc<PluginHost>], line: &str, context: Value) -> Option<Result<CommandReply, String>> {
    let rest = line.trim().strip_prefix('/')?;
    let (name, args) = rest.split_once(char::is_whitespace).map(|(a, b)| (a, b.trim())).unwrap_or((rest, ""));
    let name = name.split('@').next().unwrap_or(name);
    let p = plugins.iter().find(|p| p.commands.iter().any(|c| c.name == name))?;
    Some(p.command(name, args, context))
}

// ───────────────────────── plugin adapters ─────────────────────────

struct PluginHook(Arc<PluginHost>);

impl PluginHook {
    /// The name the plugin subscribed under (it may use an upstream alias such as `before_tool_call`).
    fn listed(&self, event: HookEvent) -> Option<&String> {
        self.0.hooks().iter().find(|h| HookEvent::parse(h) == Some(event))
    }
    fn middleware(&self, event: HookEvent) -> bool {
        event.is_middleware() && self.0.middleware_kinds().iter().any(|m| *m == event.name())
    }
}

/// Middleware events → `ark/middleware`: the payload in Hermes' names, the answer as a modify.
fn run_middleware(host: &PluginHost, event: HookEvent, payload: &Value) -> Result<HookDecision, String> {
    let phase = payload["phase"].as_str();
    let mut p = json!({"session_id": payload["session_id"], "tool_name": payload["tool_name"], "model": payload["model"]});
    match event {
        HookEvent::ToolRequest | HookEvent::ToolExecution => {
            p["args"] = payload["tool_input"].clone();
            if phase == Some("result") {
                p["result"] = payload["tool_response"].clone();
            }
        }
        _ => {
            p["request"] = payload["request"].clone();
            if phase == Some("result") {
                p["response"] = payload["response"].clone();
            }
        }
    }
    Ok(match host.middleware(&event.name(), phase, p)? {
        Some(v) => HookDecision::Modify(v),
        None => HookDecision::Allow,
    })
}

impl Hook for PluginHook {
    fn name(&self) -> String {
        format!("plugin:{}", self.0.name)
    }
    fn wants(&self, event: HookEvent, _: Option<&str>) -> bool {
        self.listed(event).is_some() || self.middleware(event)
    }
    fn run(&self, event: HookEvent, payload: &Value) -> Result<HookDecision, String> {
        if self.middleware(event) {
            return run_middleware(&self.0, event, payload);
        }
        let Some(n) = self.listed(event).cloned() else { return Ok(HookDecision::Allow) };
        let mut p = payload.clone();
        // The plugin protocol names the modifiable part `input`.
        let field = match event {
            HookEvent::TransformToolResult => "result",
            HookEvent::TransformTerminalOutput => "output",
            HookEvent::TransformLlmOutput => "text",
            HookEvent::TransformApiError => "classification",
            _ if payload.get("tool_input").is_some() => "tool_input",
            _ => "prompt",
        };
        p["input"] = payload.get(field).cloned().unwrap_or(Value::Null);
        match self.0.hook(&n, p)? {
            ark_plugin::plugin::HookDecision::Allow => Ok(HookDecision::Allow),
            ark_plugin::plugin::HookDecision::Deny(r) => Ok(HookDecision::Block(r)),
            ark_plugin::plugin::HookDecision::Modify(v) => Ok(HookDecision::Modify(v)),
        }
    }
}

/// `context_engine = "<plugin>"` → the kernel's [`ContextEngine`](ark_kernel::engine::ContextEngine).
pub struct PluginEngine {
    host: Arc<PluginHost>,
    /// Sessions the engine has seen (the first assemble carries `bootstrap: true`, OC `bootstrap`).
    seen: Mutex<HashSet<String>>,
}

impl ark_kernel::engine::ContextEngine for PluginEngine {
    fn name(&self) -> String {
        format!("plugin:{}", self.host.name)
    }
    fn owns_compaction(&self) -> bool {
        self.host.context_engine.as_ref().is_some_and(|e| e.owns_compaction)
    }
    fn ingest(&self, session: &str, message: &ark_core::Message) {
        self.host.context_ingest(session, json!(message));
    }
    fn assemble(&self, session: &str, workspace: &str, messages: &[ark_core::Message], budget: u64, model: &str, prompt: &str) -> Result<Option<ark_kernel::engine::Assembled>, String> {
        let first = self.seen.lock().unwrap().insert(session.to_string());
        let r = self.host.context("assemble", json!({"session": session, "workspace": workspace, "messages": messages, "token_budget": budget, "model": model, "prompt": prompt, "bootstrap": first}));
        if r.is_err() {
            self.seen.lock().unwrap().remove(session);
        }
        let r = r?;
        let add = r["system_prompt_addition"].as_str().map(str::to_string);
        Ok(match r.get("messages").filter(|m| !m.is_null()) {
            Some(m) => Some(ark_kernel::engine::Assembled { messages: serde_json::from_value(m.clone()).map_err(|e| format!("bad messages: {e}"))?, system_addition: add }),
            None if add.is_some() => Some(ark_kernel::engine::Assembled { messages: messages.to_vec(), system_addition: add }),
            None => None,
        })
    }
    fn compact(&self, session: &str, messages: &[ark_core::Message], budget: u64, current: u64, force: bool) -> Result<Option<ark_kernel::engine::Compacted>, String> {
        let r = self.host.context("compact", json!({"session": session, "messages": messages, "token_budget": budget, "current_tokens": current, "force": force}))?;
        if r["compacted"] != true {
            return Ok(None);
        }
        let summary = r["summary"].as_str().filter(|s| !s.trim().is_empty()).ok_or("compacted without a `summary`")?;
        Ok(Some(ark_kernel::engine::Compacted { summary: summary.to_string(), keep_messages: r["keep_messages"].as_u64().map(|n| n as usize) }))
    }
}

/// The context engine and memory tool the config selects (`None` = ark's own).
pub type Selected = (Option<Arc<PluginEngine>>, Option<Arc<dyn Tool>>);

/// The context engine and memory tool the config selects from the loaded plugins.
pub fn selected(cfg: &Config, ext: &Ext) -> Result<Selected, String> {
    let find = |name: &str, what: &str, has: &dyn Fn(&PluginHost) -> bool| -> Result<Arc<PluginHost>, String> {
        match ext.plugins.iter().find(|p| p.name == name) {
            Some(p) if has(p) => Ok(p.clone()),
            Some(_) => Err(format!("plugin `{name}` does not declare a {what}")),
            None => Err(format!("{what} `{name}`: no such plugin is running (see `ark plugin list`)")),
        }
    };
    let engine = match cfg.context_engine.trim() {
        "" | "legacy" | "ark" => None,
        n => Some(Arc::new(PluginEngine { host: find(n, "context engine", &|p| p.context_engine.is_some())?, seen: Mutex::default() })),
    };
    let memory = match cfg.memory.provider.trim() {
        "" | "builtin" => None,
        n => Some(Arc::new(ark_plugin::PluginMemory(find(n, "memory provider", &|p| p.memory)?)) as Arc<dyn Tool>),
    };
    Ok((engine, memory))
}

/// The plugin serving `ark <name>` on the command line.
pub fn cli_owner<'a>(plugins: &'a [Arc<PluginHost>], name: &str) -> Option<&'a Arc<PluginHost>> {
    plugins.iter().find(|p| p.cli.iter().any(|c| c.name == name))
}

/// Start only the configured plugins (CLI dispatch and help need nothing else).
pub fn start_plugins(cfg: &Config, vault: &Arc<Vault>) -> (Vec<Arc<PluginHost>>, Vec<String>) {
    let secrets = secrets_fn(vault);
    let mut out = Vec::new();
    let mut warn = Vec::new();
    for (n, t) in &cfg.plugins {
        match parse::<McpServerConfig>("plugins", n, t).and_then(|c| PluginHost::start(n, &c, secrets.clone())) {
            Ok(p) => out.push(Arc::new(p)),
            Err(e) => warn.push(format!("plugin {n}: {e}")),
        }
    }
    (out, warn)
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
                // Plugins send the full Inbound shape; `id` is accepted for message_id.
                let mut m = m.clone();
                if m.get("message_id").is_none() {
                    m["message_id"] = m.get("id").cloned().unwrap_or(Value::String(String::new()));
                }
                for k in ["chat", "sender", "text"] {
                    if m.get(k).is_none() {
                        m[k] = Value::String(String::new());
                    }
                }
                m["channel"] = Value::String(self.id.clone());
                if let Ok(i) = serde_json::from_value::<Inbound>(m) {
                    out.push(i);
                }
            }
        }
        Ok(out)
    }
    fn send(&self, out: &Outbound) -> Result<ark_channel::Sent, ChannelError> {
        let r = self.host.channel_send(&self.id, serde_json::to_value(out).unwrap_or_default()).map_err(|e| ChannelError::new(ChannelErrorKind::Network, e))?;
        let id = r.get("message_id").and_then(|v| v.as_str().map(str::to_string).or_else(|| v.as_i64().map(|n| n.to_string())));
        Ok(ark_channel::Sent { ids: id.into_iter().collect() })
    }
}

// ───────────────────────── channel router (daemon) ─────────────────────────

/// Poll every channel; route messages into sessions; reply when runs finish.
/// Shared state of the daemon's channel loops.
struct Hub {
    k: Kernel,
    router: Arc<Router>,
    deliver: Arc<Deliverer>,
    ws: PathBuf,
    commands: Arc<Vec<CommandDef>>,
    plugins: Vec<Arc<PluginHost>>,
    /// Channels whose replies stream while the model writes (`stream = true` and caps allow).
    stream: HashSet<String>,
}

/// Appended to channel replies under `[compliance] profile = "government"` unless `ai_label` is set
/// (`ai_label = ""` turns it off).
pub const DEFAULT_AI_LABEL: &str = "— 本訊息由 AI 生成";

/// Delete one person's channel data: the sessions routed to them (by sender or chat id in
/// `who`), the attachments they sent into the workspace inbox, and their pairing approval.
/// Shared by `ark data delete` and the `/forget` channel command. Returns (sessions, files, revoked).
pub fn forget(store: &ark_kernel::store::Store, router: &Router, pairing: Option<&Pairing>, channel: &str, who: &[&str]) -> (usize, usize, bool) {
    let routes = forget_routes(router, channel, who);
    let mut files_to_remove = Vec::new();
    for r in &routes {
        for e in store.read(&r.session).unwrap_or_default() {
            let text = serde_json::to_string(&e).unwrap_or_default();
            for part in text.split("[附件 ").skip(1) {
                if let Some(p) = part.split(": ").nth(1).and_then(|x| x.split(']').next()) {
                    if p.contains("/.ark/inbox/") {
                        files_to_remove.push(PathBuf::from(p));
                    }
                }
            }
        }
    }
    let mut n = 0;
    for r in &routes {
        if store.remove(&r.session).is_ok() {
            n += 1;
        }
        router.reset(&r.key);
    }
    // Revoke every id given (no short-circuit).
    let revoked = pairing.is_some_and(|p| who.iter().map(|w| p.revoke(channel, w)).filter(|r| *r).count() > 0);
    let files = files_to_remove.iter().filter(|p| std::fs::remove_file(p).is_ok()).count();
    (n, files, revoked)
}

pub fn forget_routes(router: &Router, channel: &str, who: &[&str]) -> Vec<ark_channel::Route> {
    router.routes().into_iter().filter(|r| r.key.channel == channel && who.iter().any(|w| r.key.sender.as_deref() == Some(*w) || r.key.chat == *w || r.key.chat.starts_with(&format!("{w}:thread:")))).collect()
}

pub fn spawn_channel_loops(k: Kernel, ext: &Ext, ws: PathBuf, cancel: Cancel) -> Vec<std::thread::JoinHandle<()>> {
    if ext.channels.is_empty() {
        return vec![];
    }
    let dir = k.paths.data.join("channels");
    let gov = k.cfg.compliance.profile == "government";
    let cfgs: HashMap<String, _> = ext
        .channels
        .iter()
        .map(|(n, (_, c))| {
            let mut r = c.router();
            if gov && r.ai_label.is_none() {
                r.ai_label = Some(DEFAULT_AI_LABEL.into());
            }
            (n.clone(), r)
        })
        .collect();
    let stream = ext.channels.iter().filter(|(_, (ch, c))| c.stream && ch.caps().streaming != ark_channel::Streaming::None).map(|(n, _)| n.clone()).collect();
    let pairing = Arc::new(Pairing::open(dir.join("pairing.json")));
    let router = Arc::new(Router::open(dir.join("routes.json"), cfgs).with_pairing(pairing));
    if let Some(w) = &router.load_warning {
        eprintln!("arkd: channels: {w}");
    }
    // Webhook routes deliver replies to other channels and fire cron jobs.
    let kc = k.clone();
    let wiring = ark_channel::Wiring {
        peers: ext.channels.iter().map(|(n, (ch, c))| (n.clone(), Arc::downgrade(ch), c.default_chat().map(String::from))).collect(),
        cron: Some(Arc::new(move |id: &str, context: &str| {
            use ark_kernel::automation::{jobs_path, read_list, run_job, Job};
            let mut job = read_list::<Job>(&jobs_path(&kc.paths.data))?.into_iter().find(|j| j.id == id).ok_or_else(|| format!("no cron job `{id}`"))?;
            if !context.is_empty() {
                job.prompt = format!("{}\n\n{context}", job.prompt);
            }
            let k = kc.clone();
            std::thread::spawn(move || run_job(&k, &job));
            Ok(())
        })),
    };
    ext.channels.values().for_each(|(ch, _)| ch.wire(&wiring));
    let hub = Arc::new(Hub { k, router, deliver: Arc::new(Deliverer::new(Some(dir.join("outbox.json")))), ws, commands: Arc::new(ext.commands.clone()), plugins: ext.plugins.clone(), stream });
    let mut handles: Vec<std::thread::JoinHandle<()>> = ext
        .channels
        .iter()
        .map(|(name, (ch, _))| {
            let (hub, ch, cancel, name) = (hub.clone(), ch.clone(), cancel.clone(), name.clone());
            std::thread::spawn(move || channel_loop(&hub, &name, ch, &cancel))
        })
        .collect();
    // Outbox sweeper: resend parked replies once channels recover.
    let all: HashMap<String, Arc<dyn Channel>> = ext.channels.iter().map(|(n, (c, _))| (n.clone(), c.clone())).collect();
    let (h, c) = (hub.clone(), cancel.clone());
    handles.push(std::thread::spawn(move || {
        while !c.is_cancelled() {
            sleep_cancellable(Duration::from_secs(15), &c);
            let (ok, gone) = h.deliver.sweep(&|id| all.get(id).cloned());
            if ok + gone > 0 {
                eprintln!("arkd: channels: outbox resent {ok}, abandoned {gone}");
            }
        }
    }));
    handles
}

fn channel_loop(hub: &Arc<Hub>, name: &str, ch: Arc<dyn Channel>, cancel: &Cancel) {
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
            handle_inbound(hub, &ch, m);
        }
    }
    ch.stop();
}

fn sleep_cancellable(d: Duration, c: &Cancel) {
    let until = std::time::Instant::now() + d;
    while std::time::Instant::now() < until && !c.is_cancelled() {
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Where a reply goes: same chat, same thread, quoting the triggering message.
#[derive(Clone)]
struct ReplyTo {
    chat: String,
    thread: Option<String>,
    message: Option<String>,
}

fn hook_payload(ch: &Arc<dyn Channel>, chat: &str, text: &str) -> Value {
    json!({"session_id": "", "cwd": "", "channel": ch.id(), "chat": chat, "prompt": text})
}

/// Final reply text: the `message_sending` hook may rewrite or stop it; the AI label is appended.
fn outgoing(hub: &Hub, ch: &Arc<dyn Channel>, to: &ReplyTo, text: &str) -> Option<String> {
    let mut text = if text.trim().is_empty() { "(no reply)".to_string() } else { text.to_string() };
    match hub.k.emit(HookEvent::MessageSending, hook_payload(ch, &to.chat, &text), "prompt") {
        (Some(b), _) => {
            eprintln!("arkd: channel {}: reply withheld by {b}", ch.id());
            return None;
        }
        (None, Some(Value::String(t))) => text = t,
        _ => {}
    }
    if let Some(l) = hub.router.config(ch.id()).and_then(|c| c.ai_label.clone()).filter(|l| !l.trim().is_empty()) {
        text = format!("{text}\n\n{l}");
    }
    Some(text)
}

fn base_out(to: &ReplyTo) -> Outbound {
    Outbound { chat: to.chat.clone(), reply_to: to.message.clone(), thread: to.thread.clone(), format: ark_channel::TextFormat::Markdown, ..Default::default() }
}

fn reply(hub: &Hub, ch: &Arc<dyn Channel>, to: &ReplyTo, text: &str) {
    let Some(text) = outgoing(hub, ch, to, text) else { return };
    let out = Outbound { text, ..base_out(to) };
    match hub.deliver.send(ch.as_ref(), &out) {
        Ok(_) => sent_hook(hub, ch, to, &out.text),
        Err(e) => eprintln!("arkd: channel {}: reply failed: {}", ch.id(), e.message),
    }
}

fn sent_hook(hub: &Hub, ch: &Arc<dyn Channel>, to: &ReplyTo, text: &str) {
    hub.k.emit(HookEvent::MessageSent, hook_payload(ch, &to.chat, text), "");
}

/// Download inbound attachments into the workspace so the agent can read them.
fn stash_media(hub: &Hub, ch: &Arc<dyn Channel>, m: &Inbound) -> Vec<String> {
    let dir = hub.ws.join(".ark").join("inbox");
    let mut lines = Vec::new();
    for (i, media) in m.media.iter().enumerate() {
        let safe: String = media.name.chars().filter(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_')).collect();
        let fname = format!("{}-{}-{i}-{}", m.channel, m.message_id.chars().filter(|c| c.is_alphanumeric()).collect::<String>(), if safe.is_empty() { "file".into() } else { safe });
        match ch.fetch_media(media) {
            Ok(bytes) => {
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join(&fname);
                if std::fs::write(&path, &bytes).is_ok() {
                    lines.push(format!("[附件 {:?} {} bytes: {}]", media.kind, bytes.len(), path.display()));
                }
            }
            Err(e) => lines.push(format!("[附件 {:?} 無法下載: {}]", media.kind, e.message)),
        }
    }
    lines
}

fn handle_inbound(hub: &Arc<Hub>, ch: &Arc<dyn Channel>, m: Inbound) {
    let k = &hub.k;
    let to = ReplyTo { chat: m.chat.clone(), thread: m.thread.clone(), message: Some(m.message_id.clone()).filter(|s| !s.is_empty()) };
    match hub.router.route(&m) {
        Action::Ignore { reason } => eprintln!("arkd: channel {}: ignored message from {}: {reason}", m.channel, m.sender),
        Action::Pair { reply: text, .. } => {
            eprintln!("arkd: channel {}: pairing requested by {} ({}); approve with `ark pairing approve {} <code>`", m.channel, m.sender, m.sender_name, m.channel);
            reply(hub, ch, &to, &text);
        }
        Action::Callback { session, callback, .. } => {
            let _ = ch.ack_callback(&callback, None);
            // Button presses resume the conversation as a user message carrying the button data.
            if let Some(sid) = session {
                if let Err(e) = k.submit(&sid, &format!("[按鈕] {}", callback.data), &format!("channel:{}", m.channel)) {
                    reply(hub, ch, &to, &format!("error: {e}"));
                } else if !k.is_running(&sid) {
                    spawn_run(hub, ch, sid, to);
                }
            }
        }
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
                    for c in hub.commands.iter() {
                        h.push_str(&format!("\n/{} — {}", c.name, c.description));
                    }
                    for p in &hub.plugins {
                        for c in &p.commands {
                            h.push_str(&format!("\n/{} — {}", c.name, c.description));
                        }
                    }
                    h
                }
                Command::Forget => {
                    // A DM's chat is the person's own; in groups only their own (per-sender) sessions go.
                    let mut who = vec![m.sender.as_str()];
                    if m.chat_type == ark_channel::ChatType::Direct {
                        who.push(m.chat.as_str());
                    }
                    for r in forget_routes(&hub.router, &m.channel, &who) {
                        k.interrupt(&r.session);
                        k.end_session(&r.session, "forget");
                    }
                    let (n, files, _) = forget(&k.store, &hub.router, hub.router.pairing().map(|p| p.as_ref()), &m.channel, &who);
                    eprintln!("arkd: channel {}: /forget from {} deleted {n} session(s), {files} attachment(s)", m.channel, m.sender);
                    format!("Deleted {n} conversation(s) and {files} attachment(s) of yours here. Shared long-term memory is not split per person; ask the operator if something about you should be removed from it.")
                }
            };
            reply(hub, ch, &to, &text);
        }
        Action::Submit { key, session, text, notice } => {
            let mut text = text;
            let mut p = hook_payload(ch, &m.chat, &text);
            p["sender"] = json!(m.sender);
            p["sender_name"] = json!(m.sender_name);
            p["session_id"] = json!(session.clone().unwrap_or_default());
            match k.emit(HookEvent::MessageReceived, p, "prompt") {
                (Some(b), _) => return eprintln!("arkd: channel {}: message from {} dropped by {b}", m.channel, m.sender),
                (None, Some(Value::String(t))) => text = t,
                _ => {}
            }
            if let Some(n) = notice {
                reply(hub, ch, &ReplyTo { message: None, ..to.clone() }, &n);
            }
            let ctx = json!({"surface": "channel", "channel": m.channel, "chat": m.chat, "sender": m.sender, "session": session});
            match run_plugin_command(&hub.plugins, &text, ctx) {
                Some(Err(e)) => return reply(hub, ch, &to, &format!("error: {e}")),
                Some(Ok(r)) => {
                    if let Some(t) = &r.text {
                        reply(hub, ch, &to, t);
                    }
                    match r.prompt {
                        Some(p) => text = p,
                        None => return,
                    }
                }
                None => {}
            }
            let sid = match session {
                Some(s) if k.store.open(&s).is_ok() => s,
                _ => match k.create_session(&hub.ws, None, None, Some(&format!("{} · {}", key.channel, m.sender_name))) {
                    Ok(s) => {
                        hub.router.bind(&key, &s);
                        s
                    }
                    Err(e) => return reply(hub, ch, &to, &format!("error: {e}")),
                },
            };
            let text = match commands::expand(&text, &hub.commands, &|_, _| None) {
                Expanded::Text(t) => t,
                Expanded::Error(e) => return reply(hub, ch, &to, &e),
                Expanded::Plain => text,
            };
            let mut text = text;
            if let Some(r) = &m.reply {
                if !r.text.is_empty() {
                    text = format!("> {}: {}\n\n{text}", r.author, r.text.chars().take(500).collect::<String>());
                }
            }
            for line in stash_media(hub, ch, &m) {
                text.push('\n');
                text.push_str(&line);
            }
            if let Err(e) = k.submit(&sid, &text, &format!("channel:{}", key.channel)) {
                return reply(hub, ch, &to, &format!("error: {e}"));
            }
            if k.is_running(&sid) {
                return; // steers the running turn; its reply covers this message
            }
            spawn_run(hub, ch, sid, to);
        }
    }
}

fn spawn_run(hub: &Arc<Hub>, ch: &Arc<dyn Channel>, sid: String, to: ReplyTo) {
    let (hub, ch) = (hub.clone(), ch.clone());
    std::thread::spawn(move || {
        // Keep "typing…" alive while the turn runs.
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        if ch.caps().typing {
            let (d, c, chat, thread) = (done.clone(), ch.clone(), to.chat.clone(), to.thread.clone());
            std::thread::spawn(move || {
                while !d.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = c.typing(&chat, thread.as_deref());
                    for _ in 0..40 {
                        if d.load(std::sync::atomic::Ordering::SeqCst) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            });
        }
        // Stream the reply as it is written, where the channel can edit in place.
        let streamer = hub.stream.contains(ch.id()).then(|| {
            let rx = hub.k.bus.subscribe();
            let (d, c, base, s) = (done.clone(), ch.clone(), base_out(&to), sid.clone());
            std::thread::spawn(move || {
                let mut st = Stream::new(c, base);
                let (mut buf, mut fresh) = (String::new(), false);
                loop {
                    // After the run ends, still apply what is already queued, then stop.
                    let msg = if d.load(std::sync::atomic::Ordering::SeqCst) {
                        match rx.try_recv() {
                            Ok(m) => m,
                            Err(_) => break,
                        }
                    } else {
                        match rx.recv_timeout(Duration::from_millis(200)) {
                            Ok(m) => m,
                            Err(_) => continue,
                        }
                    };
                    match msg {
                        ark_kernel::kernel::BusMsg::Delta { session, text, thinking: false } if session == s => {
                            if fresh {
                                buf.clear();
                                fresh = false;
                            }
                            buf.push_str(&text);
                            st.update(&buf);
                        }
                        // The next deltas belong to a new model step: show that message instead.
                        ark_kernel::kernel::BusMsg::Event { session, event } if session == s && matches!(event.kind, ark_kernel::event::EventKind::Message { .. }) => fresh = true,
                        _ => {}
                    }
                }
                st
            })
        });
        let r = hub.k.run(&sid, RunOpts::default());
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut stream = streamer.and_then(|t| t.join().ok());
        match r {
            Ok(o) => {
                let t = if o.reason.ok() { o.text } else { format!("{}\n\n[{}]", o.text, o.reason.label()) };
                match stream.as_mut().filter(|s| s.active()) {
                    Some(st) => match outgoing(&hub, &ch, &to, &t) {
                        Some(final_text) if st.finish(&final_text, &hub.deliver) => sent_hook(&hub, &ch, &to, &final_text),
                        Some(_) => reply(&hub, &ch, &to, &t),
                        None => {
                            st.finish("(withheld)", &hub.deliver);
                        }
                    },
                    None => reply(&hub, &ch, &to, &t),
                }
            }
            Err(KernelError::AlreadyRunning(_)) => {}
            Err(e) => reply(&hub, &ch, &to, &format!("error: {e}")),
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::{Block, Message, Role, StopReason};
    use serde_json::json;

    #[test]
    fn sampling_tool_rounds_translate_both_ways() {
        let p = json!({
            "messages": [
                {"role": "user", "content": {"type": "text", "text": "weather in Taipei?"}},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "lookup", "input": {"city": "Taipei"}}]},
                {"role": "user", "content": [{"type": "tool_result", "toolUseId": "t1", "content": [{"type": "text", "text": "28C"}], "isError": false}]}
            ],
            "tools": [{"name": "lookup", "description": "Look up", "inputSchema": {"properties": {"city": {"type": "string"}}}}],
            "toolChoice": {"mode": "required"}, "systemPrompt": "Be brief.", "maxTokens": 64
        });
        let (msgs, tools, system, max, model) = sampling_request(&p).unwrap();
        assert_eq!((msgs.len(), max, model), (3, 64, None));
        assert!(matches!(&msgs[1].content[0], Block::ToolUse { id, name, .. } if id == "t1" && name == "lookup"));
        assert!(matches!(&msgs[2].content[0], Block::ToolResult { tool_use_id, content, is_error: false } if tool_use_id == "t1" && content == "28C"));
        assert_eq!(tools[0].input_schema["type"], "object", "schemas sanitized for providers");
        assert!(system.starts_with("Be brief.") && system.contains("calling one of the provided tools"));
        let none = sampling_request(&json!({"messages": [{"role": "user", "content": {"type": "text", "text": "x"}}], "tools": [{"name": "a", "inputSchema": {}}], "toolChoice": {"mode": "none"}})).unwrap();
        assert!(none.1.is_empty(), "toolChoice none offers no tools");
        assert!(sampling_request(&json!({"messages": []})).is_err());

        let reply = Message { role: Role::Assistant, content: vec![Block::text("checking"), Block::ToolUse { id: "t2".into(), name: "lookup".into(), input: json!({"city": "Tainan"}) }] };
        let r = sampling_result(&reply, "p/m", StopReason::ToolUse, true);
        assert_eq!(r["stopReason"], "toolUse");
        assert_eq!(r["content"][1], json!({"type": "tool_use", "id": "t2", "name": "lookup", "input": {"city": "Tainan"}}));
        let plain = sampling_result(&Message::assistant("hi"), "p/m", StopReason::EndTurn, false);
        assert_eq!(plain["content"], json!({"type": "text", "text": "hi"}), "single block without tools (older servers)");
    }

    #[test]
    fn url_elicitation_shows_the_full_url_and_needs_consent() {
        let q = url_question("gh", &json!({"mode": "url", "url": "https://github.com/login/device?x=1", "message": "Authorize ark"})).unwrap();
        assert!(q.contains("https://github.com/login/device?x=1") && q.contains("site: github.com") && q.contains("Authorize ark"));
        assert!(url_question("gh", &json!({"url": "javascript:alert(1)"})).is_none());
        assert!(url_question("gh", &json!({"url": "https://a\u{0007}b"})).is_none());
        assert!(url_answer_accepts("done") && !url_answer_accepts("decline") && !url_answer_accepts(" ") && !url_answer_accepts("拒絕"));
    }
}
