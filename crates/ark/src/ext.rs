//! Extensions: MCP servers (connectors), plugins, channels, hooks and custom
//! commands, assembled from config into tools + hooks for the kernel.

use ark_channel::access::Pairing;
use ark_channel::deliver::{Deliverer, Stream};
use ark_channel::router::{Action, Command, Router};
use ark_channel::{Channel, ChannelError, ChannelErrorKind, Inbound, Outbound};
use ark_core::{Cancel, Tool};
use ark_kernel::commands::{self, CommandDef, Expanded};
use ark_kernel::config::{Config, Paths};
use ark_kernel::hooks::{Hook, HookDecision, HookEvent};
use ark_kernel::kernel::{Kernel, KernelError, Resolver, RunOpts};
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

/// Channel name → channel, for tools that post into chats.
pub fn channel_map(ext: &Ext) -> BTreeMap<String, Arc<dyn Channel>> {
    ext.channels.iter().map(|(n, (c, _))| (n.clone(), c.clone())).collect()
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
    let (h, w) = crate::hooks_ext::load(cfg, paths, ws, &kernel, secrets.clone());
    hooks.extend(h);
    warnings.extend(w);
    // Built-in plugins (`[builtin_plugins.<name>]`): disk-cleanup, security-guidance, achievements.
    tools.extend(ark_plugin::builtin::tools(cfg, paths, ws));
    hooks.extend(ark_plugin::builtin::hooks(cfg, paths));

    let mut plugins = Vec::new();
    for (n, t) in &cfg.plugins {
        let started = parse::<McpServerConfig>("plugins", n, t).and_then(|c| start_guarded(cfg, &paths.data, n, &c, secrets.clone(), &mut warnings));
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
        let msg: ark_channel::message_tool::Targets = channels.iter().map(|(n, (ch, c))| (n.clone(), (ch.clone(), c.default_chat().map(String::from)))).collect();
        tools.push(Arc::new(ark_channel::message_tool::MessageTool::new(msg)));
        tools.extend(channels.values().flat_map(|(ch, _)| ch.tools()));
    }
    // `whatsapp_call` speaks a synthesized message: install the `[media.tts]` chain here, where
    // the channels are built (no `[media.tts]` = no hook, and the tool says so).
    crate::telephony::install(cfg, vault);
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
        if let Some(k) = self.kernel.get() {
            let surface = context["surface"].as_str().unwrap_or("cli");
            if let Some(r) = native_command(k, line, context["session"].as_str(), surface) {
                return Some(r);
            }
        }
        run_plugin_command(&self.plugins, line, context)
    }

    /// Is `/name` a native (kernel-registered) or plugin command?
    pub fn has_command(&self, name: &str) -> bool {
        self.plugin_command(name).is_some() || self.kernel.get().is_some_and(|k| k.slash_commands().iter().any(|(n, _)| n == name))
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

/// A native slash command (skills, memory, context, plugins …) as a plugin-style reply.
pub fn native_command(k: &Kernel, line: &str, session: Option<&str>, surface: &str) -> Option<Result<CommandReply, String>> {
    k.run_slash(line, session, surface).map(|r| r.map(|r| CommandReply { text: r.text, prompt: r.prompt }))
}

fn run_plugin_command(plugins: &[Arc<PluginHost>], line: &str, context: Value) -> Option<Result<CommandReply, String>> {
    let rest = line.trim().strip_prefix('/')?;
    let (name, args) = rest.split_once(char::is_whitespace).map(|(a, b)| (a, b.trim())).unwrap_or((rest, ""));
    let name = name.split('@').next().unwrap_or(name);
    let p = plugins.iter().find(|p| p.commands.iter().any(|c| c.name == name))?;
    Some(p.command(name, args, context))
}

// ───────────────────────── plugin stream taps ─────────────────────────

/// Wrap `inner` so every provider's streamed deltas and tool events reach the plugins that
/// declared stream hooks (Hermes `on_stream_*`; see `ark_plugin::stream`). No declared taps = the
/// resolver is returned as is.
pub fn stream_taps(inner: Arc<dyn Resolver>, ext: &Ext) -> Arc<dyn Resolver> {
    let taps: Vec<Arc<ark_plugin::StreamTap>> = ext.plugins.iter().filter_map(|p| ark_plugin::StreamTap::new(p.clone()).map(Arc::new)).collect();
    ark_plugin::stream::tap_resolver(inner, taps)
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
            e if e.result_field().is_some() => e.result_field().unwrap_or("result"),
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

/// Start only the configured plugins (CLI dispatch and help need nothing else), under
/// the `security.plugin_consent` policy.
pub fn start_plugins(cfg: &Config, vault: &Arc<Vault>) -> (Vec<Arc<PluginHost>>, Vec<String>) {
    start_plugins_in(cfg, vault, &Paths::from_env().data, true)
}

fn start_plugins_in(cfg: &Config, vault: &Arc<Vault>, data: &Path, guarded: bool) -> (Vec<Arc<PluginHost>>, Vec<String>) {
    let secrets = secrets_fn(vault);
    let mut out = Vec::new();
    let mut warn = Vec::new();
    for (n, t) in &cfg.plugins {
        let started = parse::<McpServerConfig>("plugins", n, t).and_then(|c| if guarded { start_guarded(cfg, data, n, &c, secrets.clone(), &mut warn) } else { PluginHost::start(n, &c, secrets.clone()) });
        match started {
            Ok(p) => out.push(Arc::new(p)),
            Err(e) => warn.push(format!("plugin {n}: {e}")),
        }
    }
    (out, warn)
}

/// Declared capabilities of a running plugin (consent input; see `plugin_guard::summarize`).
pub fn plugin_caps(p: &PluginHost) -> Value {
    let names = |v: &[ark_plugin::plugin::CommandDecl]| v.iter().map(|c| c.name.clone()).collect::<Vec<_>>();
    let tools: Vec<String> = match p.client().info() {
        Ok(i) if i.pointer("/capabilities/tools").is_some() => p.client().list_tools().map(|d| d.into_iter().map(|t| t.name).collect()).unwrap_or_else(|_| vec!["(unlisted)".into()]),
        _ => vec![],
    };
    json!({
        "tools": tools, "hooks": p.hooks(), "middleware": p.middleware_kinds(), "channels": p.channels(),
        "commands": names(&p.commands), "cli": names(&p.cli),
        "routes": p.routes.iter().map(|r| format!("{}{}", r.path, if r.public { " (public)" } else { "" })).collect::<Vec<_>>(),
        "providers": p.providers.iter().map(|x| x.id.clone()).collect::<Vec<_>>(), "services": p.services.iter().map(|x| x.name.clone()).collect::<Vec<_>>(),
        "node_commands": p.node_commands.iter().map(|x| x.command.clone()).collect::<Vec<_>>(), "ui": p.ui.iter().map(|x| x.id.clone()).collect::<Vec<_>>(),
        "backends": p.backends.iter().map(|b| format!("{}:{}", b.kind, b.id)).collect::<Vec<_>>(),
        "dashboard_auth": p.dashboard_auth.as_ref().map(|a| a.id.clone()),
        "context_engine": p.context_engine.is_some(), "memory": p.memory,
    })
}

/// The local directory a plugin runs from (command or first argument that is an absolute
/// path outside the system dirs), scanned by the plugin guard before it starts.
pub fn plugin_dir(c: &McpServerConfig) -> Option<PathBuf> {
    for cand in c.command.iter().chain(c.args.iter()) {
        let p = ark_core::tool::expand_home(cand);
        if p.is_absolute() && p.exists() && !["/usr", "/bin", "/sbin", "/lib", "/opt/homebrew", "/nix"].iter().any(|s| p.starts_with(s)) {
            return Some(if p.is_dir() { p } else { p.parent().map(Path::to_path_buf).unwrap_or(p) });
        }
    }
    None
}

/// Start a plugin under `security.plugin_consent` (OpenClaw plugin trust consent, Hermes
/// plugin guard): its local directory is scanned first (a `dangerous` verdict refuses it
/// under `require`), then its declared capabilities must match an accepted record
/// (`ark security plugins accept <name>`). `warn` loads it and reports; `off` skips both.
fn start_guarded(cfg: &Config, data: &Path, n: &str, c: &McpServerConfig, secrets: ark_plugin::Secrets, warnings: &mut Vec<String>) -> Result<PluginHost, String> {
    use ark_security::{plugin_guard, Consent};
    let mode = cfg.security.plugin_consent;
    if mode == Consent::Off {
        return PluginHost::start(n, c, secrets);
    }
    if let Some(dir) = plugin_dir(c) {
        let r = plugin_guard::scan_dir(&dir);
        if r.verdict == "dangerous" {
            let report = plugin_guard::format_report(n, &r);
            if mode == Consent::Require {
                return Err(format!("refused by the plugin guard ({}): {report}", dir.display()));
            }
            warnings.push(format!("plugin {n}: {report}"));
        }
    }
    let p = PluginHost::start(n, c, secrets)?;
    let caps = plugin_guard::summarize(&plugin_caps(&p));
    let w = plugin_guard::widened(data, n, &caps);
    if !w.is_empty() {
        let lines = plugin_guard::consent_lines(n, &caps, &w).join("; ");
        if mode == Consent::Require {
            return Err(format!("not started: capabilities not accepted ({lines}). Review, then run `ark security plugins accept {n}`"));
        }
        warnings.push(format!("plugin {n}: capabilities not yet accepted ({lines}); `ark security plugins accept {n}`"));
    }
    Ok(p)
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
    /// For the built-in slash commands (`crate::slash`).
    ext: Arc<Ext>,
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

/// The native chat menu: a handful of everyday commands (interface reduction; the rest is
/// behind `/help`).
pub fn short_menu() -> Vec<(String, String)> {
    const SHORT: [(&str, &str); 6] = [
        ("status", "Current status"),
        ("stop", "Interrupt the running task"),
        ("approve", "Approve a pending action"),
        ("new", "Start a fresh conversation"),
        ("help", "All commands and help"),
        ("sethome", "Make this chat the home chat"),
    ];
    SHORT.iter().map(|(n, d)| (n.to_string(), crate::slash::find(n).map(|x| x.help.to_string()).filter(|h| !h.is_empty()).unwrap_or_else(|| d.to_string()))).collect()
}

pub fn spawn_channel_loops(k: Kernel, ext: &Arc<Ext>, ws: PathBuf, cancel: Cancel) -> Vec<std::thread::JoinHandle<()>> {
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
    // Native command menus (Telegram / Discord) show only the few everyday commands;
    // `/help` expands the rest. Full list stays reachable by typing any slash command.
    let menu = short_menu();
    ark_channel::outfile::load_homes(&dir.join("home.json"));
    ark_channel::outfile::add_root(&ws);
    ark_channel::set_menu(menu);
    let pairing = Arc::new(Pairing::open(dir.join("pairing.json")));
    let router = Arc::new(Router::open(dir.join("routes.json"), cfgs).with_pairing(pairing));
    if let Some(w) = &router.load_warning {
        eprintln!("arkd: channels: {w}");
    }
    // Webhook routes deliver replies to other channels and fire cron jobs.
    let kc = k.clone();
    let origin_router = router.clone();
    let wiring = ark_channel::Wiring {
        session_origin: Some(Arc::new(move |session: &str| origin_router.routes().into_iter().find(|r| r.session == session).map(|r| r.key))),
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
    // The `message` tool answers in the chat the calling session came from.
    let tool_router = router.clone();
    ark_channel::outfile::set_origin(Some(Arc::new(move |session: &str| tool_router.routes().into_iter().find(|r| r.session == session).map(|r| (r.key.channel, r.key.chat)))));
    ext.channels.values().for_each(|(ch, _)| ch.wire(&wiring));
    let hub = Arc::new(Hub { k, router, deliver: Arc::new(Deliverer::new(Some(dir.join("outbox.json")))), ws, commands: Arc::new(ext.commands.clone()), plugins: ext.plugins.clone(), stream, ext: ext.clone() });
    crate::agentcmds::bindings::set_router(hub.router.clone());
    ark_kernel::kernel::set_host_routes(Arc::new(ChannelRoutes { router: hub.router.clone(), deliver: hub.deliver.clone(), paths: hub.k.paths.clone(), channels: ext.channels.iter().map(|(n, (c, _))| (n.clone(), c.clone())).collect() }));
    let mut handles: Vec<std::thread::JoinHandle<()>> = ext
        .channels
        .iter()
        .map(|(name, (ch, _))| {
            let (hub, ch, cancel, name) = (hub.clone(), ch.clone(), cancel.clone(), name.clone());
            std::thread::spawn(move || channel_loop(&hub, &name, ch, &cancel))
        })
        .collect();
    // Pending approvals go to the bound chat / configured targets, with `appr:` buttons.
    let (fh, fc) = (hub.clone(), cancel.clone());
    handles.push(std::thread::spawn(move || forward_loop(fh, fc)));
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

// ───────────────────────── approval forwarding (buttons) ─────────────────────────

/// `channel\u{1f}chat\u{1f}thread\u{1f}id` of every approval already forwarded, so each
/// target receives a pending request once (buses and retries may repeat it).
fn forwarded_seen() -> &'static Mutex<HashSet<String>> {
    static S: std::sync::OnceLock<Mutex<HashSet<String>>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

/// `<chat>:thread:<id>` (how a threaded route is stored, see `ChannelRoutes::origin`).
fn chat_and_thread(chat: &str) -> (String, Option<String>) {
    match chat.split_once(":thread:") {
        Some((c, t)) => (c.to_string(), Some(t.to_string())),
        None => (chat.to_string(), None),
    }
}

/// The text a forwarded approval carries — OpenClaw `exec-approval-forwarder.messages.ts`
/// shape: a title line, the stable `ID:`, the gate's reason and the call summary, then the
/// `/approve` line the chat can type instead of pressing a button.
fn approval_text(req: &ark_kernel::approver::ApprovalRequest) -> String {
    let gate = format!("{:?}", req.gate).to_lowercase();
    let reason: String = req.reason.chars().take(300).collect();
    let summary: String = req.summary.chars().take(300).collect();
    let deferred = req.id.starts_with(ark_kernel::secgate::DEFERRED_PREFIX);
    if req.irreversible() {
        // srv-018: the tier, the impact and that it cannot be undone, before any button.
        return format!(
            "🛑 TIER 3 — irreversible, outside the sandbox: {} ({gate})\nID: {}\n{reason}\n\nImpact: {summary}\n\nOnly the owner can approve this, once, after a second confirmation{}. Nothing is remembered.\nReply with: /approve {} confirm  |  /deny {}",
            req.tool,
            req.id,
            if deferred { " (queued while nobody was there; the rest of the task kept running)" } else { "" },
            req.id,
            req.id
        );
    }
    if deferred {
        return format!("⏸ Queued for the owner ({}, tier {}): {}\nID: {}\n{reason}\n\n{summary}\n\nReply with: /approve {} | /deny {}", req.tool, req.tier, gate, req.id, req.id, req.id);
    }
    format!("🔒 {} approval required ({gate})\nID: {}\n{reason}\n\n{summary}\n\nReply with: /approve {} allow-once|allow-always|deny", req.tool, req.id, req.id)
}

/// Where each forwarded approval went, so an expiry can be announced there (srv-017).
type Target = (String, String, Option<String>);

fn forwarded_to() -> &'static Mutex<HashMap<String, Vec<Target>>> {
    static S: std::sync::OnceLock<Mutex<HashMap<String, Vec<Target>>>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

/// Buttons for a forwarded approval. Tier 3 offers no "Allow Always" (the hard floor is never
/// remembered) and its allow button only opens the second confirmation.
fn approval_buttons(req: &ark_kernel::approver::ApprovalRequest) -> Vec<Vec<ark_channel::Button>> {
    let b = |label: &str, choice: &str| ark_channel::Button { label: label.into(), data: format!("appr:{}:{choice}", req.id), url: None };
    if req.irreversible() {
        return vec![vec![b("Review & Allow Once", "once"), b("Deny", "deny")]];
    }
    if req.id.starts_with(ark_kernel::secgate::DEFERRED_PREFIX) {
        return vec![vec![b("Allow", "once"), b("Deny", "deny")]];
    }
    // OpenClaw labels and decisions: `allow-once` / `allow-always` (a durable grant) /
    // `deny`; the data keeps this tree's `once|always|deny` spelling.
    vec![vec![b("Allow Once", "once"), b("Allow Always", "permanent"), b("Deny", "deny")]]
}

/// Send a pending approval to its session's chat (`mode = "session"`), to the configured
/// targets (`mode = "targets"`) or both, with `appr:<id>:<choice>` buttons where the channel
/// supports them; the receiving chat's peer may then answer it (`allow_forwarded`). A call
/// queued for the owner (cron / unattended, `q-` id) with no such chat goes to the owners'
/// direct chats (`approvals.forward.owners`).
fn forward_approval(hub: &Arc<Hub>, req: &ark_kernel::approver::ApprovalRequest) {
    use ark_security::approvals::ForwardMode;
    let cfg = &hub.k.cfg.approvals.forward;
    if !cfg.enabled {
        return;
    }
    if !cfg.session_filter.is_empty() && !cfg.session_filter.iter().any(|p| req.session.starts_with(p.as_str())) {
        return;
    }
    let mut targets: Vec<(String, String, Option<String>)> = Vec::new();
    if matches!(cfg.mode, ForwardMode::Session | ForwardMode::Both) {
        if let Some(r) = hub.router.routes().into_iter().find(|r| r.session == req.session) {
            let (chat, thread) = chat_and_thread(&r.key.chat);
            targets.push((r.key.channel, chat, thread));
        }
    }
    if matches!(cfg.mode, ForwardMode::Targets | ForwardMode::Both) {
        for t in &cfg.targets {
            targets.push((t.channel.clone(), t.to.clone(), t.thread.clone()));
        }
    }
    if targets.is_empty() && req.id.starts_with(ark_kernel::secgate::DEFERRED_PREFIX) {
        for channel in hub.ext.channels.keys() {
            for o in cfg.owners_of(channel) {
                targets.push((channel.clone(), o, None));
            }
        }
    }
    let text = approval_text(req);
    for (channel, chat, thread) in targets {
        let Some(ch) = hub.ext.channels.get(&channel).map(|(c, _)| c.clone()) else {
            continue;
        };
        let key = format!("{channel}\u{1f}{chat}\u{1f}{}\u{1f}{}", thread.clone().unwrap_or_default(), req.id);
        {
            let mut seen = forwarded_seen().lock().unwrap_or_else(|p| p.into_inner());
            if !seen.insert(key) {
                continue;
            }
            if seen.len() > 1024 {
                seen.clear();
            }
        }
        let mut out = Outbound { chat: chat.clone(), thread: thread.clone(), text: text.clone(), format: ark_channel::TextFormat::Markdown, ..Default::default() };
        if ch.caps().buttons {
            out.buttons = approval_buttons(req);
        }
        match hub.deliver.send(ch.as_ref(), &out) {
            // The forwarded chat's peer may answer this request without an approvers list.
            Ok(_) => {
                ark_security::approvals::allow_forwarded(&req.id, &channel, &chat);
                let mut m = forwarded_to().lock().unwrap_or_else(|p| p.into_inner());
                if m.len() > 1024 {
                    m.clear();
                }
                m.entry(req.id.clone()).or_default().push((channel.clone(), chat.clone(), thread.clone()));
            }
            Err(e) => eprintln!("arkd: approvals: forwarding {} to {channel} failed: {}", req.id, e.message),
        }
    }
}

/// srv-017: a forwarded approval that expired is announced where it was sent, so nobody
/// presses a dead button believing it still matters.
fn announce_expiry(hub: &Arc<Hub>, text: &str) {
    let Some(rest) = text.strip_prefix("approval expired: ") else { return };
    let id = rest.split_whitespace().next().unwrap_or("");
    let Some(targets) = forwarded_to().lock().unwrap_or_else(|p| p.into_inner()).remove(id) else { return };
    for (channel, chat, thread) in targets {
        if let Some(ch) = hub.ext.channels.get(&channel).map(|(c, _)| c.clone()) {
            let out = Outbound { chat, thread, text: format!("⏱ Approval {id} expired with no answer and was denied — silence is not consent. {}", rest.split_once(" — ").map(|x| x.1).unwrap_or("")), ..Default::default() };
            let _ = hub.deliver.send(ch.as_ref(), &out);
        }
    }
}

/// Bus listener: every `BusMsg::Pending(Approval)` becomes a channel message with buttons.
fn forward_loop(hub: Arc<Hub>, cancel: Cancel) {
    let rx = hub.k.bus.subscribe();
    forward_loop_with(hub, rx, cancel);
}

/// The loop body, over an already-subscribed receiver (subscribing first means no pending
/// message published afterwards is missed).
fn forward_loop_with(hub: Arc<Hub>, rx: Receiver<ark_kernel::kernel::BusMsg>, cancel: Cancel) {
    while !cancel.is_cancelled() {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(ark_kernel::kernel::BusMsg::Pending(ark_kernel::approver::PendingItem::Approval(req))) => forward_approval(&hub, &req),
            Ok(ark_kernel::kernel::BusMsg::Event { event, .. }) => {
                if let ark_kernel::event::EventKind::Notice { text, .. } = &event.kind {
                    announce_expiry(&hub, text);
                }
            }
            _ => {}
        }
    }
}

/// A pressed `appr:<id>:<choice>` button answers the pending approval (when this chat's sender
/// may answer it) instead of becoming a user message. `None` = not an approval button.
///
/// `Once`/`always`/`permanent` are this tree's spellings; `allow-once`/`allow-always` (the
/// OpenClaw decision names) are accepted too. A request that is gone answers with the
/// upstream wording ("no longer available": already answered, denied or expired).
fn answer_approval(k: &Kernel, m: &Inbound, data: &str) -> Option<String> {
    let rest = data.strip_prefix("appr:")?;
    let (id, choice) = rest.rsplit_once(':').unwrap_or((rest, ""));
    let choice = match choice {
        "once" | "allow-once" => "once",
        "always" => "always",
        // OpenClaw's `allow-always` is a durable grant, as is this tree's `permanent`.
        "permanent" | "allow-always" => "permanent",
        "deny" => "deny",
        // srv-018: the second press on a tier-3 request.
        "confirm" => "confirm",
        _ => return Some(format!("Unknown approval answer `{choice}`.")),
    };
    // A call queued for the owner (cron / unattended): answered in the deferred queue.
    if id.starts_with(ark_kernel::secgate::DEFERRED_PREFIX) {
        let r = ark_kernel::secgate::answer_deferred(k, id, matches!(choice, "once" | "confirm"), &m.channel, &m.sender);
        return Some(r.unwrap_or_else(|e| e));
    }
    let Some(req) = k.approver.pending().into_iter().find_map(|p| match p {
        ark_kernel::approver::PendingItem::Approval(r) if r.id == id => Some(r),
        _ => None,
    }) else {
        return Some(no_longer_available(id));
    };
    if ark_app::identity::channel_permits(&k.paths, &m.channel, &m.sender, true).is_err() || !ark_kernel::secgate::approver_allowed(&k.cfg.approvals, &m.channel, &m.sender, std::slice::from_ref(&req)) {
        if req.irreversible() {
            return Some("❌ Tier-3 (irreversible) approvals can only be answered by the owner (approvals.forward.owners).".to_string());
        }
        return Some("❌ You are not allowed to answer approvals here.".to_string());
    }
    // srv-018: tier 3 is allow-once only and needs a second, explicit press by the same owner.
    let choice = match (req.irreversible(), choice) {
        (true, "once") => {
            tier3_armed().lock().unwrap_or_else(|p| p.into_inner()).insert(id.to_string(), format!("{}:{}", m.channel, m.sender));
            return Some(format!("{TIER3_CONFIRM} — {} cannot be undone. {}\nPress Confirm (or send /approve {id} confirm) to allow it once. id: {id}", req.tool, req.reason));
        }
        (true, "confirm") => {
            let armed = tier3_armed().lock().unwrap_or_else(|p| p.into_inner()).remove(id);
            if armed.as_deref() != Some(format!("{}:{}", m.channel, m.sender).as_str()) {
                return Some(format!("Press \"Review & Allow Once\" first, then confirm. id: {id}"));
            }
            "once"
        }
        (true, "always" | "permanent") => return Some("Tier-3 approvals are allow-once only; nothing is remembered.".to_string()),
        (false, "confirm") => "once",
        (_, c) => c,
    };
    ark_security::approvals::set_answered_by(id, &format!("{}:{}", m.channel, m.sender));
    if !ark_kernel::approver::answer_by(&*k.approver, &k.paths.data, id, choice, &ark_security::audit::Actor::channel(&m.channel, &m.sender), "button") {
        return Some(no_longer_available(id));
    }
    let label = match choice {
        "once" => "✅ Approved (once)",
        "always" => "✅ Approved (always)",
        "permanent" => "✅ Approved (always, saved)",
        _ => "❌ Denied",
    };
    Some(format!("{label} — id: {id}"))
}

const TIER3_CONFIRM: &str = "⚠️ Confirm tier 3";

/// Tier-3 approvals whose first press arrived: id → `channel:sender` that must confirm.
fn tier3_armed() -> &'static Mutex<HashMap<String, String>> {
    static S: std::sync::OnceLock<Mutex<HashMap<String, String>>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

/// The upstream reply when an approval id no longer exists (`/approve` on a resolved or
/// expired request: "That approval is no longer available").
fn no_longer_available(id: &str) -> String {
    format!("That approval is no longer available — it was already answered, denied or expired. `/approvals` shows what is still pending. id: {id}")
}

/// Session → chat routing for kernel hook points (`subagent_delivery_target`, compaction-notifier).
struct ChannelRoutes {
    router: Arc<Router>,
    deliver: Arc<Deliverer>,
    channels: HashMap<String, Arc<dyn Channel>>,
    paths: Paths,
}

impl ark_kernel::kernel::HostRoutes for ChannelRoutes {
    fn origin(&self, session: &str) -> Option<Value> {
        // A thread-bound sub-agent session lives in its own thread, not in the chat route.
        if let Some(b) = ark_kernel::threads::by_session(&self.paths, session) {
            return Some(b.origin());
        }
        let r = self.router.routes().into_iter().find(|r| r.session == session)?;
        let (chat, thread) = match r.key.chat.split_once(":thread:") {
            Some((c, t)) => (c.to_string(), Some(t.to_string())),
            None => (r.key.chat.clone(), None),
        };
        Some(json!({"channel": r.key.channel, "to": chat, "thread_id": thread}))
    }
    fn supports_threads(&self, origin: &Value) -> bool {
        let Some(ch) = origin["channel"].as_str().and_then(|n| self.channels.get(n)) else { return false };
        ch.caps().threads && ch.message_actions().contains(&"thread-create")
    }
    fn create_thread(&self, origin: &Value, name: &str) -> Result<String, String> {
        let cname = origin["channel"].as_str().ok_or("origin has no `channel`")?;
        let ch = self.channels.get(cname).ok_or_else(|| format!("no channel `{cname}`"))?;
        let to = origin["to"].as_str().map(String::from).or_else(|| origin["to"].as_i64().map(|n| n.to_string())).ok_or("origin has no `to`")?;
        let args = json!({"target": to, "threadName": name});
        let v = ch.message_action("thread-create", &args).map_err(|e| e.message)?;
        let id = v["thread"]["id"]
            .as_str()
            .or_else(|| v["threadId"].as_str())
            .or_else(|| v["thread_id"].as_str())
            .or_else(|| v["id"].as_str())
            .or_else(|| v["thread"].as_str())
            .map(String::from)
            .ok_or_else(|| format!("{cname} did not return a thread id for `{name}`"))?;
        // Reuse the chat's own route key so replies in the thread resolve to the same chat.
        Ok(id)
    }
    fn deliver(&self, origin: &Value, text: &str) -> Result<(), String> {
        let name = origin["channel"].as_str().unwrap_or("");
        let ch = self.channels.get(name).ok_or_else(|| format!("no channel `{name}`"))?;
        let to = origin["to"].as_str().map(String::from).or_else(|| origin["to"].as_i64().map(|n| n.to_string())).ok_or("origin has no `to`")?;
        let thread = origin["thread_id"].as_str().map(String::from).or_else(|| origin["thread_id"].as_i64().map(|n| n.to_string()));
        let out = Outbound { chat: to, thread, text: text.to_string(), format: ark_channel::TextFormat::Markdown, ..Default::default() };
        self.deliver.send(ch.as_ref(), &out).map(|_| ()).map_err(|e| e.message)
    }
}

/// Connection state per channel for `/ready` (ent-098): `(ok, detail)`.
fn channel_states() -> &'static std::sync::Mutex<HashMap<String, (bool, String)>> {
    static S: std::sync::OnceLock<std::sync::Mutex<HashMap<String, (bool, String)>>> = std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

fn channel_seen(name: &str, ok: bool, detail: &str) {
    channel_states().lock().unwrap_or_else(|e| e.into_inner()).insert(name.to_string(), (ok, detail.to_string()));
}

/// Register `channel:<name>` as a readiness check reading the poll loop's last state.
fn register_channel_check(name: &str) {
    let n = name.to_string();
    ark_app::metrics::register_check(&format!("channel:{name}"), Arc::new(move || match channel_states().lock().unwrap_or_else(|e| e.into_inner()).get(&n) {
        Some((true, d)) => Ok(d.clone()),
        Some((false, d)) => Err(d.clone()),
        None => Err("not polled yet".into()),
    }));
}

fn channel_loop(hub: &Arc<Hub>, name: &str, ch: Arc<dyn Channel>, cancel: &Cancel) {
    let mut backoff = 1u64;
    register_channel_check(name);
    while !cancel.is_cancelled() {
        let msgs = match ch.poll(cancel) {
            Ok(m) => {
                backoff = 1;
                channel_seen(name, true, "connected");
                m
            }
            Err(e) => {
                channel_seen(name, false, &e.message);
                if matches!(e.kind, ChannelErrorKind::Auth | ChannelErrorKind::Fatal) {
                    eprintln!("arkd: channel {name} stopped: {}", e.message);
                    channel_seen(name, false, &format!("stopped: {}", e.message));
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
    let text = chat_visible(text);
    let mut text = if text.trim().is_empty() { "(no reply)".to_string() } else { text };
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

/// srv-019: what of a reply may reach a chat — recalled-memory fences
/// (`<memory-context>`, `<recalled-context>` and their system notes) are dropped, as the
/// terminal's `Visible` scrubber does for streamed output.
fn chat_visible(text: &str) -> String {
    // H11: a credential-shaped string never leaves in a chat reply either.
    ark_security::risk::mask_secrets(&ark_memory::fence::sanitize_context(text)).0
}

fn base_out(to: &ReplyTo) -> Outbound {
    Outbound { chat: to.chat.clone(), reply_to: to.message.clone(), thread: to.thread.clone(), format: ark_channel::TextFormat::Markdown, ..Default::default() }
}

fn reply(hub: &Hub, ch: &Arc<dyn Channel>, to: &ReplyTo, text: &str) {
    let Some(text) = outgoing(hub, ch, to, text) else { return };
    let mut out = Outbound { text, ..base_out(to) };
    // `[media.tts] auto`: a voice note reply (OpenClaw src/tts, Hermes tts_tool auto mode).
    if let Some((audio, as_voice)) = voice_note(hub, ch, to, &out.text) {
        out.media.push(ark_channel::Media {
            kind: if as_voice { ark_channel::MediaKind::Voice } else { ark_channel::MediaKind::Audio },
            path: Some(audio.to_string_lossy().to_string()),
            mime: if as_voice { "audio/ogg".into() } else { "audio/mpeg".into() },
            name: audio.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
            ..Default::default()
        });
    }
    match hub.deliver.send(ch.as_ref(), &out) {
        Ok(_) => sent_hook(hub, ch, to, &out.text),
        Err(e) => eprintln!("arkd: channel {}: reply failed: {}", ch.id(), e.message),
    }
}

/// Whether this chat's last inbound message was a voice note (`[media.tts] auto = inbound`).
fn voice_reply() -> &'static std::sync::Mutex<HashMap<String, bool>> {
    static V: std::sync::OnceLock<std::sync::Mutex<HashMap<String, bool>>> = std::sync::OnceLock::new();
    V.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Speak `text` for `channel` when `[media.tts] auto` asks for it (lexical policy, plus
/// `chat`'s `/tts chat` // `/voice tts` override, inside ark-media); `None` keeps the
/// reply text-only.
fn auto_voice_reply(k: &Kernel, text: &str, inbound_voice: bool, channel: &str, chat: Option<&str>) -> Option<(std::path::PathBuf, bool)> {
    let m = crate::media_host::media(&k.cfg, k.vault.clone());
    let key = chat.map(|c| format!("{}:{}", channel.trim(), c.trim()));
    ark_media::tts::auto_reply(&m, text, inbound_voice, channel, key.as_deref(), &ark_core::Cancel::new())
}

/// Speak the reply when `[media.tts] auto` asks for it; `None` keeps it text-only.
fn voice_note(hub: &Hub, ch: &Arc<dyn Channel>, to: &ReplyTo, text: &str) -> Option<(std::path::PathBuf, bool)> {
    let flag = voice_reply().lock().unwrap().remove(&format!("{}:{}:{:?}", ch.id(), to.chat, to.thread)).unwrap_or(false);
    auto_voice_reply(&hub.k, text, flag, ch.id(), Some(&to.chat))
}

fn sent_hook(hub: &Hub, ch: &Arc<dyn Channel>, to: &ReplyTo, text: &str) {
    hub.k.emit(HookEvent::MessageSent, hook_payload(ch, &to.chat, text), "");
}

/// Download inbound attachments into the workspace so the agent can read them.
/// Returns (failure notes, understood items): every stored file becomes an
/// `inbound::Item` for media understanding (transcript / description / extracted text).
fn stash_media(hub: &Hub, ch: &Arc<dyn Channel>, m: &Inbound) -> (Vec<String>, Vec<ark_media::inbound::Item>) {
    let dir = hub.ws.join(".ark").join("inbox");
    let mut lines = Vec::new();
    let mut items = Vec::new();
    for (i, media) in m.media.iter().enumerate() {
        let safe: String = media.name.chars().filter(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_')).collect();
        let fname = format!("{}-{}-{i}-{}", m.channel, m.message_id.chars().filter(|c| c.is_alphanumeric()).collect::<String>(), if safe.is_empty() { "file".into() } else { safe });
        match ch.fetch_media(media) {
            Ok(bytes) => {
                let _ = std::fs::create_dir_all(&dir);
                let path = dir.join(&fname);
                if std::fs::write(&path, &bytes).is_ok() {
                    items.push(ark_media::inbound::Item { path, mime: media.mime.clone(), kind: media_kind(media.kind).to_string(), caption: media.caption.clone() });
                }
            }
            Err(e) => lines.push(format!("[附件 {:?} 無法下載: {}]", media.kind, e.message)),
        }
    }
    (lines, items)
}

/// Media understanding for one inbound message (OpenClaw `src/media-understanding`, Hermes
/// gateway inbound transcription): the prompt body with `[Audio] Transcript:` / `[Image]
/// Description:` sections, the images to attach, and whether the message was a voice note.
fn understand_media(k: &Kernel, text: &str, items: &[ark_media::inbound::Item]) -> (String, Vec<ark_core::Block>, bool) {
    let m = crate::media_host::media(&k.cfg, k.vault.clone());
    let a = ark_media::inbound::apply(&m, text, items, &ark_core::Cancel::new());
    let images = a.images.iter().map(|(mt, d)| ark_core::Block::Image { media_type: mt.clone(), data: d.clone() }).collect();
    (a.body, images, a.was_voice)
}

/// `ark_channel::MediaKind` → the media-understanding kind (`image`, `voice`, …).
fn media_kind(k: ark_channel::MediaKind) -> &'static str {
    match k {
        ark_channel::MediaKind::Image => "image",
        ark_channel::MediaKind::Audio => "audio",
        ark_channel::MediaKind::Voice => "voice",
        ark_channel::MediaKind::Video => "video",
        ark_channel::MediaKind::Animation => "animation",
        ark_channel::MediaKind::Sticker => "sticker",
        ark_channel::MediaKind::Document => "document",
    }
}

/// OpenClaw link understanding (`[web.links]`): summaries of bare links in the user's text
/// appended to the prompt. Scope key: `<channel>:<chat_type>:<chat>[:<sender>]`.
fn link_understanding(hub: &Hub, m: &Inbound, key: &ark_channel::router::RouteKey, body: &str) -> Option<String> {
    link_understanding_with(&hub.k.cfg, &hub.k.paths.data, m, key, body)
}

/// The `[web]` table reaches `ark_tools::web::WebConfig` through the serialized config (the
/// kernel keeps it as an untyped table so the `ark` crate owns no web schema).
fn link_understanding_with(cfg: &ark_kernel::config::Config, data: &std::path::Path, m: &Inbound, key: &ark_channel::router::RouteKey, body: &str) -> Option<String> {
    let web = serde_json::to_value(cfg).ok().and_then(|v| v.get("web").cloned()).unwrap_or(Value::Null);
    let cfg = ark_tools::web::WebConfig::from_value(web).map_err(|e| eprintln!("arkd: {e}")).ok()?;
    if !cfg.links.enabled {
        return None;
    }
    let chat_type = serde_json::to_value(m.chat_type).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
    let mut session_key = format!("{}:{chat_type}:{}", key.channel, key.chat);
    if let Some(s) = &key.sender {
        session_key.push(':');
        session_key.push_str(s);
    }
    let msg = ark_tools::web::links::LinkMessage { text: &m.text, channel: &m.channel, chat_type: &chat_type, session_key: &session_key, sender: &m.sender, sender_name: &m.sender_name };
    ark_tools::web::links::apply_link_understanding(&cfg, data, &msg, body)
}

/// Slash commands that keep working while `ark pause` is engaged — otherwise the operator
/// could not lift the stop from the very chat that is blocked.
const ESTOP_ALLOWED: [&str; 4] = ["resume", "status", "help", "pause"];

/// The slash command a message starts with, lowercased and without `@bot`
/// (`"/pause@ark now"` → `pause`); `None` for plain text.
fn leading_command(text: &str) -> Option<String> {
    let rest = text.trim_start().strip_prefix('/')?;
    let head = rest.split_whitespace().next().unwrap_or("");
    let name = head.split('@').next().unwrap_or("");
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

/// `/sethome`: make this chat the channel's home (where cron results and unaddressed
/// `message` / `channel_send` calls go). Only the owner (an `approvals.forward.approvers`
/// entry for this channel) may; fails closed without one.
fn sethome(k: &Kernel, m: &Inbound) -> String {
    if !ark_kernel::secgate::channel_operator(&k.cfg.approvals, &m.channel, &m.sender, &m.sender_name) {
        return "Only the owner can set the home chat. Set one with `ark setup --owner <your id>` (or approvals.forward.approvers).".into();
    }
    match ark_channel::outfile::set_home(&m.channel, &m.chat) {
        Ok(()) => format!("Home set: scheduled results and unaddressed messages on {} now go to this chat ({}).", m.channel, m.chat),
        Err(e) => format!("error: {e}"),
    }
}

/// What to reply instead of starting a new turn while the emergency stop is engaged
/// (`ark pause`, `<data>/ESTOP`). `None` = not paused, or a command that must keep
/// working: `/resume`, `/status`, `/help`, `/pause`.
fn estop_blocked(k: &Kernel, text: &str) -> Option<String> {
    if !ark_security::estop::is_engaged(&k.paths.data) {
        return None;
    }
    if leading_command(text).is_some_and(|n| ESTOP_ALLOWED.contains(&n.as_str())) {
        return None;
    }
    Some(ark_security::estop::paused_reply(&k.paths.data).unwrap_or_else(|| "⏸️ ark is paused (ESTOP). New work is on hold; run `ark resume` to pick things back up.".to_string()))
}

/// `[security.external_content.channels`: inbound text of a listed channel (webhook payloads,
/// mail bodies) enters model context wrapped in the untrusted-content boundary — the channel
/// twin of the kernel's `guard_tool_output`. `None` = pass the text through unchanged.
fn wrap_channel_inbound(k: &Kernel, m: &Inbound, text: &str) -> Option<String> {
    let sec = &k.cfg.security;
    if !sec.external_content.enabled || !sec.external_content.channels.iter().any(|g| ark_security::glob::fnmatch(g, &m.channel)) {
        return None;
    }
    // A slash command is the operator's instruction, not third-party data; and a hook that
    // already wrapped the message (the gmail hook) must not be wrapped twice.
    if text.trim_start().starts_with('/') || ark_security::external::is_wrapped(text) {
        return None;
    }
    let name = m.channel.to_ascii_lowercase();
    let source = if name.contains("mail") || name.contains("email") || name.contains("gmail") {
        ark_security::external::Source::Email
    } else if name.contains("webhook") {
        ark_security::external::Source::Webhook
    } else {
        ark_security::external::Source::ChannelMetadata
    };
    let who = if m.sender_name.trim().is_empty() { m.sender.as_str() } else { m.sender_name.as_str() };
    let meta = ark_security::external::Meta { sender: Some(who), subject: None, task: Some("channel inbound") };
    Some(ark_security::external::wrap(text, source, &meta, true))
}

fn handle_inbound(hub: &Arc<Hub>, ch: &Arc<dyn Channel>, m: Inbound) {
    let k = &hub.k;
    let to = ReplyTo { chat: m.chat.clone(), thread: m.thread.clone(), message: Some(m.message_id.clone()).filter(|s| !s.is_empty()) };
    crate::agentcmds::on_inbound(k, &hub.router, &m);
    // A message posted in a thread bound to a sub-agent session goes to that child, and its
    // reply stays in the thread (`sessions_spawn thread:true`).
    let mut m = m;
    if let Some(t) = m.thread.as_deref().filter(|t| !t.is_empty()).map(str::to_string) {
        match ark_kernel::threads::route_inbound(&k.paths, &m.channel, &m.chat, &t) {
            ark_kernel::threads::Route::Bound(b) => {
                if thread_inbound(hub, ch, &m, &b, &to) {
                    return;
                }
                // A command in the worker's thread belongs to the chat, not to a per-thread
                // session of its own: route it as if the message had come from the chat.
                m.thread = None;
            }
            ark_kernel::threads::Route::Expired { farewell, binding, reason } => {
                eprintln!("arkd: channel {}: thread binding {} expired ({reason}); messages go back to the chat", m.channel, binding.thread);
                reply(hub, ch, &to, &farewell);
                // The thread is gone as a session; the chat handles (and answers in the thread).
                m.thread = None;
            }
            ark_kernel::threads::Route::Unbound => {}
        }
    }
    // ent-047 / ent-060: a sender registered in `ark users` brings its role and status to chat
    // too. Disabled profiles are refused; operator / auditor profiles may only ask for status.
    if let Err(why) = ark_app::identity::channel_permits(&k.paths, &m.channel, &m.sender, false) {
        let cmd = m.text.split_whitespace().next().unwrap_or("");
        let status_only = matches!(cmd, "/status" | "/help" | "/whoami") && !why.contains("disabled");
        if !status_only {
            ark_security::audit::record(&k.paths.data, ark_security::audit::Event::new("auth.denied", ark_security::audit::Actor::channel(&m.channel, &m.sender), "channel.message", "deny").detail(json!({"reason": why})));
            return reply(hub, ch, &to, &format!("⛔ {why}."));
        }
    }
    match hub.router.route(&m) {
        Action::Ignore { reason } => eprintln!("arkd: channel {}: ignored message from {}: {reason}", m.channel, m.sender),
        Action::Pair { reply: text, .. } => {
            eprintln!("arkd: channel {}: pairing requested by {} ({}); approve with `ark pairing approve {} <code>`", m.channel, m.sender, m.sender_name, m.channel);
            crate::hooks_ext::pairing_requested(k, &m, &text);
            reply(hub, ch, &to, &text);
        }
        Action::Callback { session, callback, .. } => {
            let _ = ch.ack_callback(&callback, None);
            // `appr:<id>:<choice>` buttons answer a pending approval right here; every other
            // button press resumes the conversation as a user message (below).
            if let Some(out) = answer_approval(k, &m, &callback.data) {
                // The tier-3 second confirmation carries its own Confirm button.
                if let (true, Some(id)) = (out.starts_with(TIER3_CONFIRM) && ch.caps().buttons, out.rsplit("id: ").next().filter(|_| out.contains("id: "))) {
                    let mut o = Outbound { text: out.clone(), ..base_out(&to) };
                    o.buttons = vec![vec![ark_channel::Button { label: "Confirm (irreversible)".into(), data: format!("appr:{}:confirm", id.trim()), url: None }, ark_channel::Button { label: "Deny".into(), data: format!("appr:{}:deny", id.trim()), url: None }]];
                    let _ = hub.deliver.send(ch.as_ref(), &o);
                    return;
                }
                return reply(hub, ch, &to, &out);
            }
            // A button press starts a turn too: while paused it gets the notice instead.
            if let Some(p) = estop_blocked(k, "") {
                return reply(hub, ch, &to, &p);
            }
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
            let action = match cmd {
                Command::New => "new",
                Command::Stop => "stop",
                Command::Status => "status",
                Command::Help => "help",
                Command::Forget => "forget",
            };
            crate::hooks_ext::command_event(k, &m, action, session.as_deref());
            let text = match cmd {
                Command::New => {
                    // The router already unbound it; the old session ends as a reset.
                    if let Some(old) = &session {
                        k.end_session(old, "new");
                    }
                    "Started fresh: your next message opens a new session.".to_string()
                }
                Command::Stop => match session {
                    Some(s) if k.interrupt(&s) => "Stopping.".into(),
                    _ => "Nothing is running.".into(),
                },
                Command::Status | Command::Help => {
                    let ctx = slash_ctx(hub, ch, &m, &to, session.clone());
                    let line = if cmd == Command::Help { format!("/help {}", m.text.split_whitespace().nth(1).unwrap_or("")) } else { "/status".into() };
                    let mut t = crate::slash::run(&ctx, &line).and_then(|r| r.text).unwrap_or_default();
                    if cmd == Command::Help {
                        t = format!("{}\n\n{t}", ark_channel::router::HELP);
                    }
                    t
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
            // `ark pause` (ESTOP): no new channel turns — and no session — until `/resume`.
            if let Some(p) = estop_blocked(k, &text) {
                return reply(hub, ch, &to, &p);
            }
            if leading_command(&text).as_deref() == Some("sethome") {
                return reply(hub, ch, &to, &sethome(k, &m));
            }
            // Security commands (`/approve /deny /yolo /approvals /elevated /exec /pause
            // /resume`) authorize by `channel` + sender, so the chat path must pass `who`.
            if let Some(out) = ark_kernel::secgate::chat_command(k, &text, session.as_deref(), Some((m.channel.as_str(), m.sender.as_str(), m.sender_name.as_str()))) {
                return reply(hub, ch, &to, &out);
            }
            if crate::agentcmds::on_submit(k, &m) {
                return;
            }
            if let Some(r) = crate::hooks_ext::inbound_claim(k, &m, session.as_deref()) {
                if let Some(t) = r {
                    reply(hub, ch, &to, &t);
                }
                return;
            }
            let session = crate::hooks_ext::auto_reset(k, &hub.router, &key, session, &m);
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
            if text.trim_start().starts_with('/') {
                let sctx = slash_ctx(hub, ch, &m, &to, session.clone());
                if let Some(r) = crate::slash::run(&sctx, &text) {
                    if let Some(t) = &r.text {
                        reply(hub, ch, &to, t);
                    }
                    if let Some(crate::slash::Action::NewSession { .. }) = r.action {
                        if let Some(s) = &session {
                            k.end_session(s, "new");
                        }
                        hub.router.reset(&key);
                        if r.text.is_none() {
                            reply(hub, ch, &to, "Started fresh: your next message opens a new session.");
                        }
                    }
                    match r.prompt {
                        Some(p) => text = p,
                        None => return,
                    }
                }
            }
            let ctx = json!({"surface": "channel", "channel": m.channel, "chat": m.chat, "sender": m.sender, "session": session});
            // /model /models /think /reasoning /fast /usage /insights /login (models_cli.rs).
            if text.starts_with('/') {
                if let Some(sid) = session.as_deref() {
                    if let Some(out) = crate::models_cli::slash_on(k, sid, &text, "channel") {
                        return reply(hub, ch, &to, &out);
                    }
                }
            }
            match native_command(k, &text, session.as_deref(), "channel").or_else(|| run_plugin_command(&hub.plugins, &text, ctx)) {
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
                _ => {
                    // Routing bindings pick the agent (most specific match), the users registry
                    // supplies personal instructions; both are recorded on the new session.
                    let (agent, user) = crate::agentcmds::inbound_identity(k, &m);
                    let a = (agent != ark_kernel::agents::MAIN).then_some(agent.as_str());
                    match k.create_agent_session(&hub.ws, a, user.as_deref(), None, None, Some(&format!("{} · {}", key.channel, m.sender_name))) {
                        Ok(s) => {
                            hub.router.bind(&key, &s);
                            s
                        }
                        Err(e) => return reply(hub, ch, &to, &format!("error: {e}")),
                    }
                }
            };
            let builtin = |n: &str, a: &str| ark_kernel::devprompts::expand_builtin(n, a, &hub.ws, k.cfg.schedule.utc_offset_minutes).map(Ok);
            let text = match commands::expand(&text, &hub.commands, &builtin) {
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
            if let Some(t) = link_understanding(hub, &m, &key, &text) {
                text = t;
            }
            // Media understanding (OpenClaw `src/media-understanding`, Hermes gateway inbound
            // transcription): voice notes are transcribed, images described or attached,
            // videos described, documents extracted — the result replaces the attachment note
            // and images ride along as model input.
            let mut attachments: Vec<ark_core::Block> = Vec::new();
            if !m.media.is_empty() {
                let (notes, items) = stash_media(hub, ch, &m);
                let (body, imgs, was_voice) = understand_media(k, &text, &items);
                text = body;
                for line in notes {
                    text.push('\n');
                    text.push_str(&line);
                }
                attachments = imgs;
                // `[media.tts] auto = inbound` replies by voice to a voice message.
                voice_reply().lock().unwrap().insert(format!("{}:{}:{:?}", ch.id(), to.chat, to.thread), was_voice);
            }
            // `[security.external_content.channels`: a webhook / mail body is third-party data.
            if let Some(w) = wrap_channel_inbound(k, &m, &text) {
                text = w;
            }
            if let Some(r) = crate::hooks_ext::before_dispatch(k, &m, &sid, &text) {
                if let Some(t) = r {
                    reply(hub, ch, &to, &t);
                }
                return;
            }
            if let Err(e) = k.submit_with(&sid, &text, attachments, &format!("channel:{}", key.channel)) {
                return reply(hub, ch, &to, &format!("error: {e}"));
            }
            if k.is_running(&sid) {
                return; // steers the running turn; its reply covers this message
            }
            if let Some(r) = crate::hooks_ext::reply_dispatch(k, &m.channel, &to.chat, to.thread.as_deref(), &sid) {
                if let Some(t) = r {
                    reply(hub, ch, &to, &t);
                }
                return;
            }
            match crate::agentcmds::debounce::gate(&sid) {
                crate::agentcmds::debounce::Gate::Now => spawn_run(hub, ch, sid, to),
                crate::agentcmds::debounce::Gate::Skip => {}
                crate::agentcmds::debounce::Gate::Delay(d) => {
                    let (h, c) = (hub.clone(), ch.clone());
                    std::thread::spawn(move || {
                        std::thread::sleep(d);
                        crate::agentcmds::debounce::done(&sid);
                        if !h.k.is_running(&sid) {
                            spawn_run(&h, &c, sid, to);
                        }
                    });
                }
            }
        }
    }
}

/// Hermes slash access lists from the channel table (list or comma string).
fn id_list(cfg: &ark_channel::config::ChannelConfig, key: &str) -> Vec<String> {
    match cfg.settings.get(key) {
        Some(Value::Array(a)) => a.iter().filter_map(|v| v.as_str().map(String::from).or_else(|| v.as_i64().map(|n| n.to_string()))).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect(),
        Some(Value::Number(n)) => vec![n.to_string()],
        _ => vec![],
    }
}

pub fn sender_access(cfg: Option<&ark_channel::config::ChannelConfig>, m: &Inbound) -> crate::slash::Sender {
    let group = m.chat_type != ark_channel::ChatType::Direct;
    let mut s = crate::slash::Sender { channel: m.channel.clone(), chat: m.chat.clone(), sender: m.sender.clone(), group, ..Default::default() };
    let Some(cfg) = cfg else { return s };
    let (ak, ck) = if group { ("group_allow_admin_from", "group_user_allowed_commands") } else { ("allow_admin_from", "user_allowed_commands") };
    let admins = id_list(cfg, ak);
    let mut cmds = id_list(cfg, ck);
    if !group && cmds.is_empty() {
        cmds = id_list(cfg, "group_user_allowed_commands");
    }
    s.gated = !admins.is_empty();
    s.admin = admins.iter().any(|a| *a == m.sender || a.trim_start_matches('@').eq_ignore_ascii_case(m.sender_name.trim_start_matches('@')));
    s.user_commands = cmds.into_iter().map(|c| c.trim_start_matches('/').to_lowercase()).collect();
    s
}

fn slash_ctx<'a>(hub: &'a Arc<Hub>, ch: &Arc<dyn Channel>, m: &Inbound, to: &ReplyTo, session: Option<String>) -> crate::slash::Ctx<'a> {
    let (h, c, t) = (hub.clone(), ch.clone(), to.clone());
    let notify: crate::slash::Notify = Arc::new(move |text: String| reply(&h, &c, &t, &text));
    crate::slash::Ctx {
        k: &hub.k,
        ext: Some(&hub.ext),
        session,
        workspace: hub.ws.clone(),
        surface: crate::slash::Surface::Channel,
        sender: Some(sender_access(hub.ext.channels.get(&m.channel).map(|(_, c)| c), m)),
        notify: Some(notify),
    }
}

/// Compact progress for long chat tasks (srv-009): nothing for short ones; once a task has run
/// past `first`, at most one line per `every` while new tools keep being used, at most `MAX`
/// per task. Pure (the clock is passed in) so the pacing is unit-testable.
pub struct Pulse {
    start: std::time::Instant,
    first: Duration,
    every: Duration,
    last: Option<std::time::Instant>,
    tools: Vec<(String, u32)>,
    fresh: bool,
    sent: u32,
}

impl Pulse {
    const MAX: u32 = 12;
    pub fn new(first: Duration, every: Duration) -> Pulse {
        Pulse { start: std::time::Instant::now(), first, every, last: None, tools: vec![], fresh: false, sent: 0 }
    }
    /// 20 s before the first line, then every 45 s; `ARK_CHAT_PROGRESS_SECS=first,every` overrides.
    pub fn from_env() -> Pulse {
        let (f, e) = std::env::var("ARK_CHAT_PROGRESS_SECS")
            .ok()
            .and_then(|v| v.split_once(',').and_then(|(a, b)| Some((a.trim().parse::<u64>().ok()?, b.trim().parse::<u64>().ok()?))))
            .unwrap_or((20, 45));
        Pulse::new(Duration::from_secs(f), Duration::from_secs(e))
    }
    pub fn note(&mut self, tool: &str) {
        self.fresh = true;
        match self.tools.iter_mut().find(|(n, _)| n == tool) {
            Some((_, c)) => *c += 1,
            None => self.tools.push((tool.to_string(), 1)),
        }
    }
    /// The line to send now, if one is due.
    pub fn due(&mut self, now: std::time::Instant) -> Option<String> {
        let ran = now.saturating_duration_since(self.start);
        let gap_ok = self.last.is_none_or(|l| now.saturating_duration_since(l) >= self.every);
        if !self.fresh || self.sent >= Self::MAX || ran < self.first || !gap_ok {
            return None;
        }
        self.fresh = false;
        self.last = Some(now);
        self.sent += 1;
        let secs = ran.as_secs();
        let mut top = self.tools.clone();
        top.sort_by_key(|t| std::cmp::Reverse(t.1));
        let used = top.iter().take(4).map(|(n, c)| if *c > 1 { format!("{n}×{c}") } else { n.clone() }).collect::<Vec<_>>().join(", ");
        let more = if top.len() > 4 { format!(" +{}", top.len() - 4) } else { String::new() };
        Some(format!("{} {}m{:02}s · {}{}{more}", crate::setup::t("⏳ 仍在處理", "⏳ Still working"), secs / 60, secs % 60, crate::setup::t("用到：", "used: "), used))
    }
}

/// Tool progress lines for `/verbose new|all|verbose` (Hermes tool progress display).
fn progress_line(level: &str, seen: &mut HashSet<String>, name: &str, input: &Value) -> Option<String> {
    match level {
        "new" if seen.insert(name.to_string()) => Some(format!("⚙ {name}")),
        "all" => Some(format!("⚙ {name}")),
        "verbose" => Some(format!("⚙ {name} {}", input.to_string().chars().take(200).collect::<String>())),
        _ => None,
    }
}

/// Input that arrived in a thread bound to a sub-agent session: hand it to the child and
/// keep the answer in the thread. `false` = not ours (slash commands belong to the chat).
fn thread_inbound(hub: &Arc<Hub>, ch: &Arc<dyn Channel>, m: &Inbound, b: &ark_kernel::threads::Binding, to: &ReplyTo) -> bool {
    let k = &hub.k;
    if let Some(p) = estop_blocked(k, &m.text) {
        reply(hub, ch, to, &p);
        return true;
    }
    if let Some(out) = ark_kernel::secgate::chat_command(k, &m.text, Some(&b.session), Some((m.channel.as_str(), m.sender.as_str(), m.sender_name.as_str()))) {
        reply(hub, ch, to, &out);
        return true;
    }
    if m.text.trim_start().starts_with('/') {
        // `/stop` in the worker's thread stops the worker; every other command is the chat's.
        if leading_command(&m.text).as_deref() == Some("stop") {
            let out = if k.interrupt(&b.session) { "Stopping." } else { "Nothing is running." };
            reply(hub, ch, to, out);
            return true;
        }
        return false;
    }
    if let Err(e) = k.submit(&b.session, &m.text, &format!("channel:{}", m.channel)) {
        reply(hub, ch, to, &format!("error: {e}"));
        return true;
    }
    if !k.is_running(&b.session) {
        spawn_run(hub, ch, b.session.clone(), to.clone());
    }
    true
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
                // srv-019: recalled-memory fences never reach the chat, even mid-stream.
                let mut scrub = ark_memory::fence::StreamScrubber::default();
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
                                scrub = ark_memory::fence::StreamScrubber::default();
                                fresh = false;
                            }
                            buf.push_str(&scrub.feed(&text));
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
        let prefs = crate::slash::display_get(&hub.k.paths, &sid);
        // Default: a compact heartbeat for long tasks (`/verbose off` silences it, `/verbose
        // new|all|verbose` shows per-tool lines instead).
        let level = prefs["verbose"].as_str().unwrap_or("auto").to_string();
        let progress = (level != "off").then(|| {
            let (rx, d, c, base, s) = (hub.k.bus.subscribe(), done.clone(), ch.clone(), base_out(&to), sid.clone());
            std::thread::spawn(move || {
                let mut seen = HashSet::new();
                let mut pulse = Pulse::from_env();
                while !d.load(std::sync::atomic::Ordering::SeqCst) {
                    if let Ok(ark_kernel::kernel::BusMsg::Event { session, event }) = rx.recv_timeout(Duration::from_millis(200)) {
                        if let (true, ark_kernel::event::EventKind::ToolCalled { name, input, .. }) = (session == s, &event.kind) {
                            if level == "auto" {
                                pulse.note(name);
                            } else if let Some(line) = progress_line(&level, &mut seen, name, input) {
                                let _ = c.send(&Outbound { text: line, ..base.clone() });
                            }
                        }
                    }
                    if level == "auto" {
                        if let Some(text) = pulse.due(std::time::Instant::now()) {
                            let _ = c.send(&Outbound { text, silent: true, ..base.clone() });
                        }
                    }
                }
            })
        });
        let started = std::time::Instant::now();
        let r = hub.k.run(&sid, RunOpts::default());
        done.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(p) = progress {
            let _ = p.join();
        }
        let mut stream = streamer.and_then(|t| t.join().ok());
        if prefs["send"] == "off" {
            return; // `/send off`: the turn ran, nothing is delivered here
        }
        match r {
            Ok(o) => {
                let mut t = if o.reason.ok() { o.text } else { format!("{}\n\n[{}]", o.text, o.reason.label()) };
                if prefs["footer"] == true {
                    let model = hub.k.store.read(&sid).map(|e| ark_kernel::projection::project(&e).model).unwrap_or_default();
                    t = format!("{t}\n\n— {model} · {} tokens · {:.1}s", o.usage.total(), started.elapsed().as_secs_f32());
                }
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
mod tests;
