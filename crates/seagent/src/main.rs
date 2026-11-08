//! The `seagent` binary: argument dispatch, the command families that live in their own modules
//! (`session_cli`, `mcp_cli`, `wire`, `ops`, …) and the `build`/`build_agent` host assembler.
//!
//! Registration is *not* here: tools, CLI command families and config validators declare
//! themselves through `seagent_core::registry` and are collected by [`registry_init`]. See
//! docs/ARCHITECTURE.md.

// musl's malloc serialises threads on one lock; the static (musl) release builds use mimalloc.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod agentcmds;
mod args;
mod control_cli;
mod devtools;
mod export;
mod exec_cli;
mod ext;
mod gmail_hook;
mod hooks_bundled;
mod hooks_cli;
mod hooks_ext;
mod hooks_outbound;
mod mcp_cli;
mod mcp_presets;
mod media_host;
mod meetings;
mod message_cli;
mod models_cli;
mod ops;
mod outbound_host;
mod plugin_backends;
mod pro_tools;
mod providers;
mod registry_init;
mod role_cli;
mod security_cli;
mod session_cli;
mod setup;
mod setup_server;
mod setup_web;
mod slash;
mod system_cli;
mod telephony;
mod term;
mod vm_cli;
mod web_cli;
mod wire;
mod worktree_session;
#[cfg(test)]
mod testkit;

use args::Args;
use seagent_core::{Block, Role};
use seagent_kernel::approver::{Approver, Policy};
use seagent_kernel::automation::{self, Goal, GoalStatus, Job};
use seagent_kernel::checkpoint::Checkpoints;
use seagent_kernel::config::{project_config, Config, Paths, SAMPLE};
use seagent_kernel::daemon::{self, Daemon};
use seagent_kernel::event::EventKind;
use seagent_kernel::kernel::{new_kernel, EndReason, Kernel, Resolver, RunOpts};
use seagent_kernel::ledger::Budget;
use seagent_kernel::projection::project;
use seagent_kernel::vault::Vault;
use providers::Providers;
use serde_json::{json, Value};
use std::io::{BufRead, IsTerminal, Read, Write};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

mod help;
use help::HELP;

fn main() {
    // Pre-rename (`ark`) installs: old variables and per-user directories keep working.
    seagent_core::legacy::adopt_env();
    for note in seagent_core::legacy::migrate_user_dirs() {
        eprintln!("seagent: {note}");
    }
    let mut raw: Vec<String> = std::env::args().collect();
    ops::early(&mut raw);
    // Windows: the shim is `seagent-call.exe` (any case): compare the lowercased stem there.
    let argv0 = raw.first().map(|s| if cfg!(windows) { Path::new(s).file_stem().and_then(|f| f.to_str()).unwrap_or("").to_ascii_lowercase() } else { Path::new(s).file_name().and_then(|f| f.to_str()).unwrap_or("").to_string() }).unwrap_or_default();
    let rest: Vec<String> = if argv0 == "seagent-call" { std::iter::once("call".to_string()).chain(raw.into_iter().skip(1)).collect() } else { raw.into_iter().skip(1).collect() };
    let code = match dispatch(rest) {
        Ok(c) => c,
        Err(Fail::Usage(e)) => {
            eprintln!("seagent: {e}\nRun `seagent help` for usage.");
            2
        }
        Err(Fail::Msg(e)) => {
            eprintln!("seagent: {e}");
            1
        }
    };
    std::process::exit(code);
}

#[derive(Debug)]
enum Fail {
    Usage(String),
    Msg(String),
}
impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::Usage(m) | Fail::Msg(m) => f.write_str(m),
        }
    }
}
impl From<String> for Fail {
    fn from(s: String) -> Self {
        Fail::Msg(s)
    }
}
impl From<&str> for Fail {
    fn from(s: &str) -> Self {
        Fail::Msg(s.into())
    }
}
fn usage<T>(s: impl Into<String>) -> Result<T, Fail> {
    Err(Fail::Usage(s.into()))
}
type R = Result<i32, Fail>;

/// Top-level commands; plugins cannot take these names.
const BUILTINS: &[&str] = &[
    "help", "--help", "-h", "version", "--version", "-V", "setup", "onboard", "call", "run", "chat", "session", "sessions", "daemon", "send", "attach", "interrupt", "gate", "gates", "schedule",
    "cron", "goal", "goals", "memory", "checkpoint", "checkpoints", "undo", "config", "secrets", "secret", "providers", "models", "doctor", "mcp", "connector", "connectors", "plugin", "plugins", "channel", "channels",
    "pairing", "pair", "message", "tui", "acp", "acp-client", "node", "nodes", "app", "data", "service", "health", "commands", "command", "webhook", "webhooks", "model", "login", "logout", "auth", "fallback",
    "fallbacks", "usage", "insights", "approvals", "approval", "exec-policy", "security", "pause", "resume", "lsp", "verify", "init", "plan", "skills", "skill", "bundles", "bundle", "curator", "journey", "hub",
    "hooks", "hook", "kanban", "meet", "teams", "teams-pipeline", "web", "browser", "screen", "computer-use",
    "sandbox", "system", "suggestions", "worktree", "agents", "users", "moa",
    "infer", "capability", "voice", "stt", "transcripts",
    "status", "telemetry", "evals", "tools", "docker", "fleet", "index", "role", "roles",
];

fn dispatch(raw: Vec<String>) -> R {
    // Tools, CLI command families and config validators are declared by the modules that own
    // them; this collects them. Idempotent (see registry_init.rs).
    registry_init::register();
    let Some(cmd) = raw.first().cloned() else {
        print_help();
        if !Paths::from_env().user_config().exists() {
            println!("\n{}", setup::t("第一次使用？執行 `seagent setup`，一步步設定模型、金鑰與聊天平台。", "First time? Run `seagent setup` to configure a model, key and chat platform step by step."));
        }
        return Ok(0);
    };
    if wire::owns(&cmd, &raw[1..]) {
        return wire::cli(&cmd, &raw[1..]).map_err(Fail::Msg);
    }
    // Self-registered command families (`seagent meet …`, `seagent browser …`, `seagent message …`): each
    // subsystem claims its own command words and parses its own flags (see registry_init.rs).
    if let Some(r) = seagent_core::registry::command_route(&cmd, &raw[1..]) {
        return r.map_err(Fail::Msg);
    }
    let a = match Args::parse(&raw[1..]) {
        Ok(a) => a,
        // Plugin CLI commands take their own flags.
        Err(_) if !BUILTINS.contains(&cmd.as_str()) && !ops::owns(&cmd) => return cmd_plugin_cli(&cmd, &raw[1..]),
        Err(e) => return usage(e),
    };
    if a.flag("accept-hooks") {
        // First-use consent opt-in (Hermes --accept-hooks); read by hooks_ext::consented.
        std::env::set_var("SEAGENT_ACCEPT_HOOKS", "1");
    }
    if a.flag("help") && BUILTINS.contains(&cmd.as_str()) {
        print_help();
        return Ok(0);
    }
    if let Some(r) = ops::dispatch(&cmd, &a, &raw[1..]) {
        return r;
    }
    // `--yolo` is frozen once, before anything reads it (a later env change cannot lift approvals).
    if a.flag("yolo") && !matches!(cmd.as_str(), "run" | "chat" | "daemon" | "tui" | "acp") {
        return usage("--yolo applies to run, chat, daemon, tui and acp");
    }
    if seagent_security::approvals::freeze_process_yolo(a.flag("yolo") && cmd != "tui") && matches!(cmd.as_str(), "run" | "chat") && !a.flag("quiet") {
        eprintln!("seagent: ⚠ YOLO: approval prompts are skipped in this process (hardline floors and deny rules still apply)");
    }
    match cmd.as_str() {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(0)
        }
        "version" | "--version" | "-V" => {
            println!("seagent {} (log v{}, protocol v{})", env!("CARGO_PKG_VERSION"), seagent_kernel::event::LOG_VERSION, daemon::PROTOCOL_VERSION);
            Ok(0)
        }
        "setup" | "onboard" => Ok(setup_web::dispatch(&a)?),
        "call" => cmd_call(&a),
        "run" => cmd_run(&a),
        "chat" => cmd_chat(&a),
        "session" | "sessions" => session_cli::cmd_session(&a),
        "fleet" => cmd_fleet(&a),
        "daemon" => cmd_daemon(&a),
        "send" => {
            let id = a.need(0, "session")?;
            let text = a.rest(1);
            if text.trim().is_empty() {
                return usage("missing <text>");
            }
            // Not a config consumer otherwise, but the queue prefixes below follow `display.language`.
            load_config(&a, &workspace(&a)?, &Paths::from_env())?;
            let r = daemon::call(&Paths::from_env().socket(), "session.submit", json!({"id": id, "text": text}))?;
            println!("{}", seagent_kernel::i18n::t(if r["started"].as_bool() == Some(true) { "queue.started" } else { "queue.running" }));
            Ok(0)
        }
        "attach" => cmd_attach(&a),
        "interrupt" => {
            let id = a.need(0, "session")?;
            let r = daemon::call(&Paths::from_env().socket(), "session.interrupt", json!({"id": id}))?;
            println!("{}", if r["interrupted"].as_bool() == Some(true) { "interrupt sent" } else { "session is not running" });
            Ok(0)
        }
        "gate" | "gates" => cmd_gate(&a),
        "schedule" | "cron" => cmd_schedule(&a),
        "goal" | "goals" => cmd_goal(&a),
        "memory" => cmd_memory(&a),
        "checkpoint" | "checkpoints" | "undo" => cmd_checkpoint(&a),
        "config" => cmd_config(&a),
        "secrets" | "secret" => cmd_secrets(&a),
        "providers" => cmd_providers(&a),
        "model" | "models" | "login" | "logout" | "auth" | "fallback" | "fallbacks" | "usage" | "insights" => cmd_models_family(&cmd, &a),
        "doctor" => cmd_doctor(&a),
        "mcp" | "connector" | "connectors" => mcp_cli::cmd_mcp(&a),
        "plugin" | "plugins" => cmd_plugin(&a),
        "channel" | "channels" => cmd_channel(&a),
        "pairing" | "pair" => cmd_pairing(&a),
        "webhook" | "webhooks" => cmd_webhook(&a, &raw[1..]),
        "hooks" | "hook" => Ok(hooks_cli::cmd(&a)?),
        "tui" => cmd_tui(&a),
        "lsp" => {
            let paths = Paths::from_env();
            let cfg = load_config(&a, &workspace(&a)?, &paths)?;
            devtools::cmd_lsp(&a, &cfg)
        }
        "verify" => devtools::cmd_verify(&a),
        "init" | "plan" => cmd_prompt_command(&cmd, &a),
        "acp" => cmd_acp(&a),
        "acp-client" => cmd_acp_client(&a),
        "node" => cmd_node(&a),
        "nodes" => cmd_nodes(&a),
        "app" => ops::appcli::cmd_app(&a),
        "data" => cmd_data(&a),
        "health" => {
            // For container health checks and monitors: is the daemon answering?
            if a.flag("ready") {
                return ops::enterprise::health_ready(&a);
            }
            // Nagios / Icinga / Zabbix (external check) plugin: status line + perfdata, 0/1/2/3.
            if a.flag("nagios") {
                return ops::enterprise::health_nagios(&a);
            }
            match daemon::call(&Paths::from_env().socket(), "ping", json!({})) {
                Ok(_) => Ok(0),
                Err(e) => Err(e.into()),
            }
        }
        "approvals" | "approval" => {
            let c = build(&a, approver_for(&a, false))?;
            security_cli::cmd_approvals(&a, &c.k, &c.workspace)
        }
        "exec-policy" | "security" => {
            let paths = Paths::from_env();
            let ws = workspace(&a)?;
            let cfg = load_config(&a, &ws, &paths)?;
            if cmd == "security" {
                security_cli::cmd_security(&a, &cfg, &paths, &ws)
            } else {
                security_cli::cmd_exec_policy(&a, &cfg, &paths, &ws)
            }
        }
        "pause" | "resume" => security_cli::cmd_pause(&a, &Paths::from_env(), cmd == "resume"),
        "commands" | "command" => {
            let c = build_agent(&a, approver_for(&a, false), false)?;
            let defs = &c.ext.as_ref().unwrap().commands;
            if defs.is_empty() {
                println!("no commands (add Markdown files to .seagent/commands/ or ~/.claude/commands/)");
            }
            for d in defs {
                println!("/{:<20} {}  ({})", d.name, d.description, d.path.display());
            }
            for (n, d) in c.ext.as_ref().unwrap().plugin_commands() {
                println!("/{n:<20} {d}  (plugin)");
            }
            for (n, d) in c.k.slash_commands() {
                println!("/{n:<20} {d}  (builtin)");
            }
            for p in c.ext.as_ref().unwrap().registry.prompts() {
                println!("/mcp__{}__{:<10} {}", p.server, p.name, p.description);
            }
            Ok(0)
        }
        other => cmd_plugin_cli(other, &raw[1..]),
    }
}

/// `HELP`, plus the CLI commands configured plugins add.
fn print_help() {
    let (head, tail) = HELP.split_once("\n\nOPTIONS").unwrap_or((HELP, ""));
    println!("{head}\n{}{}", security_cli::HELP_LINES, if tail.is_empty() { String::new() } else { format!("\n\nOPTIONS{tail}") });
    let paths = Paths::from_env();
    let Ok(ws) = std::env::current_dir() else { return };
    let (Ok(cfg), Ok(vault)) = (Config::load(Some(&paths.user_config()), Some(&project_config(&ws)), &[]), load_vault(&paths)) else { return };
    if cfg.plugins.is_empty() {
        return;
    }
    let (plugins, _) = ext::start_plugins(&cfg, &vault);
    let cmds: Vec<String> = plugins.iter().flat_map(|p| p.cli.iter().filter(|c| !BUILTINS.contains(&c.name.as_str()) && !ops::owns(&c.name)).map(move |c| format!("  seagent {:<32} {} ({})", format!("{} {}", c.name, c.args).trim_end(), c.description, p.name))).collect();
    if !cmds.is_empty() {
        println!("\nPLUGIN COMMANDS\n{}", cmds.join("\n"));
    }
}

/// `seagent <name> …` served by a plugin's `cli` declaration (OpenClaw `registerCli`).
fn cmd_plugin_cli(name: &str, argv: &[String]) -> R {
    let paths = Paths::from_env();
    let ws = std::env::current_dir().map_err(|e| e.to_string())?;
    let cfg = Config::load(Some(&paths.user_config()), Some(&project_config(&ws)), &[]).map_err(Fail::Msg)?;
    if cfg.plugins.is_empty() {
        return usage(format!("unknown command `{name}`"));
    }
    let vault = load_vault(&paths)?;
    let (plugins, warn) = ext::start_plugins(&cfg, &vault);
    let Some(p) = ext::cli_owner(&plugins, name) else {
        for w in warn {
            eprintln!("seagent: warning: {w}");
        }
        return usage(format!("unknown command `{name}`"));
    };
    let r = p.cli(name, argv, &ws.to_string_lossy(), &mut |stream, text| {
        if stream == "stderr" {
            eprint!("{text}");
        } else {
            print!("{text}");
            let _ = std::io::stdout().flush();
        }
    })?;
    print!("{}", r.stdout);
    eprint!("{}", r.stderr);
    let _ = std::io::stdout().flush();
    Ok(r.exit)
}

// ───────────────────────── setup ─────────────────────────

struct Ctx {
    k: Kernel,
    paths: Paths,
    workspace: PathBuf,
    ext: Option<ext::Ext>,
}

fn workspace(a: &Args) -> Result<PathBuf, Fail> {
    let w = a.val("workspace").map(PathBuf::from).unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    w.canonicalize().map_err(|e| Fail::Msg(format!("workspace {}: {e}", w.display())))
}

fn load_config(a: &Args, ws: &Path, paths: &Paths) -> Result<Config, Fail> {
    let mut sets = a.vals("set");
    if let Some(m) = a.val("model") {
        sets.push(format!("model.default={m:?}"));
    }
    if let Some(n) = a.num::<u64>("budget-tokens").map_err(Fail::Usage)? {
        sets.push(format!("budget.max_tokens={n}"));
    }
    if let Some(n) = a.num::<f64>("budget-usd").map_err(Fail::Usage)? {
        sets.push(format!("budget.max_cost_usd={n}"));
    }
    if let Some(n) = a.num::<u64>("max-steps").map_err(Fail::Usage)? {
        sets.push(format!("runner.max_steps_per_turn={n}"));
    }
    let cfg = Config::load(Some(&paths.user_config()), Some(&project_config(ws)), &sets).map_err(Fail::Msg)?;
    let mut cfg = ops::debugdump::effective(&cfg).unwrap_or(cfg); // `/debug set` runtime overrides
    // `[role] active`: the occupation's default permissions tighten (never loosen) the config
    // the agent runs with — approval preset, workspace-only writes, tool profile (seagent_kernel::roles).
    seagent_kernel::roles::apply_policy(&mut cfg);
    models_cli::init(paths, &cfg);
    seagent_kernel::i18n::set_config_language(&cfg.display.language); // `display.language` → approval prompts, notices, headings
    Ok(cfg)
}

/// `seagent model|models|login|logout|auth|fallback|usage|insights` (crates/seagent/src/models_cli.rs).
fn cmd_models_family(cmd: &str, a: &Args) -> R {
    let paths = Paths::from_env();
    let ws = workspace(a)?;
    let cfg = load_config(a, &ws, &paths)?;
    let vault = load_vault(&paths)?;
    let r = match cmd {
        "model" => models_cli::cmd_model(a, &paths, &cfg, vault),
        "models" => models_cli::cmd_models(a, &paths, &cfg, vault),
        "login" => models_cli::cmd_login(a, &paths),
        "logout" => models_cli::cmd_logout(a, &paths),
        "auth" => models_cli::cmd_auth(a, &paths, &cfg, vault),
        "fallback" | "fallbacks" => models_cli::cmd_fallback(a, &paths, &cfg, vault),
        "usage" => models_cli::cmd_usage(a, &paths, &cfg, vault),
        _ => models_cli::cmd_insights(a, &paths, &cfg),
    };
    r.map_err(Fail::Msg)
}

fn load_vault(paths: &Paths) -> Result<Arc<Vault>, Fail> {
    Vault::load(&paths.secrets()).map(Arc::new).map_err(Fail::Msg)
}

fn approver_for(a: &Args, interactive_ok: bool) -> Arc<dyn Approver> {
    if a.flag("yes") {
        return Arc::new(Policy { allow_privilege: true, allow_egress: true });
    }
    if interactive_ok && term::TtyApprover::available() {
        return Arc::new(term::TtyApprover::new());
    }
    Arc::new(Policy { allow_privilege: a.flag("allow-privilege"), allow_egress: a.flag("allow-egress") })
}

fn build(a: &Args, approver: Arc<dyn Approver>) -> Result<Ctx, Fail> {
    let paths = Paths::from_env();
    let ws = workspace(a)?;
    let cfg = load_config(a, &ws, &paths)?;
    let vault = load_vault(&paths)?;
    // `$SEAGENT_AGENT=<name>` runs the process as that agent: its own credential profile store
    // (`<config>/agents/<name>/auth.json`) is tried before the shared pool (OpenClaw per-agent
    // auth profiles). Unset = the shared store only.
    let mut providers = Providers::new(&cfg.providers, vault.clone())?;
    if let Some(agent) = std::env::var("SEAGENT_AGENT").ok().map(|x| x.trim().to_string()).filter(|x| !x.is_empty()) {
        providers = providers.agent(&paths.config_dir, &agent);
    }
    let resolver: Arc<dyn Resolver> = Arc::new(providers);
    devtools::configure_lsp(&cfg);
    let mut tools = seagent_tools::builtin_tools();
    wire::merge_tools(&mut tools, wire::tools(&cfg, &paths, &ws));
    // Media tools (`[media]`: vision, documents, image/video/music generation, TTS/STT,
    // transcripts, voice calls, meeting bots); the same instance backs the callbacks below.
    let media = media_host::media(&cfg, vault.clone());
    tools.extend(seagent_media::tools(&media));
    // Built-in plugin slash commands (`/disk-cleanup`, `/achievements`) when enabled.
    let builtin_slash: Vec<Arc<dyn seagent_kernel::slash::Slash>> = seagent_plugin::builtin::slash(&cfg, &paths);
    // `[exec.sandbox]`: a sandboxed session only reaches the tools its policy allows, sees the
    // scratch workspace under `workspace_access = "none"`, and cannot write under `"ro"`
    // (OpenClaw sandbox tool policy; the wrapper is inert for host sessions).
    let tools = seagent_tools::exec::sandbox::wrap_all(tools);
    let k = new_kernel(cfg, paths.clone(), resolver, tools, vault, approver);
    for s in builtin_slash {
        k.add_slash(s);
    }
    media_host::install(&k, &media);
    wire::attach(&k, &ws);
    Ok(Ctx { k, paths, workspace: ws, ext: None })
}

/// Like `build`, plus MCP servers, plugins, channels, hooks and commands.
fn build_agent(a: &Args, approver: Arc<dyn Approver>, with_channels: bool) -> Result<Ctx, Fail> {
    let paths = Paths::from_env();
    let ws = workspace(a)?;
    let mut cfg = load_config(a, &ws, &paths)?;
    let vault = load_vault(&paths)?;
    let providers = Arc::new(Providers::new(&cfg.providers, vault.clone())?);
    let resolver: Arc<dyn Resolver> = providers.clone();
    let (ext, extra, hooks) = ext::load(&cfg, &paths, &vault, &ws, with_channels);
    outbound_host::install(ext.channels.iter().map(|(n, (ch, c))| (n.clone(), (ch.clone(), c.default_chat().map(String::from)))).collect(), ext::secrets_fn(&vault), paths.data.clone());
    for p in &ext.plugins {
        for (id, imp) in p.provider_impls() {
            providers.register(&id, imp);
        }
    }
    // Plugin capability backends (TTS/STT/image/video/cloud browser/web search): registered in
    // their consuming crate's provider table, so a config key (`[media.tts] provider`, …) can
    // select them. See `plugin_backends`.
    plugin_backends::install(&ext.plugins);
    // Plugin stream hooks (`on_stream_*`): wrap every provider so observers see the deltas.
    let resolver: Arc<dyn Resolver> = ext::stream_taps(resolver, &ext);
    if !a.flag("quiet") {
        for w in &ext.warnings {
            eprintln!("seagent: warning: {w}");
        }
    }
    let ins = ext::instructions(&ext);
    if !ins.is_empty() {
        cfg.identity = if cfg.identity.is_empty() { ins } else { format!("{}\n{ins}", cfg.identity) };
    }
    let persona = slash::active_personality(&cfg);
    if !persona.is_empty() {
        cfg.identity = if cfg.identity.is_empty() { persona } else { format!("{}\n\n{persona}", cfg.identity) };
    }
    let disabled = cfg.tools.disabled.clone();
    let mut tools = seagent_tools::builtin_tools();
    wire::merge_tools(&mut tools, wire::tools(&cfg, &paths, &ws));
    tools.extend(extra);
    match seagent_app::AppConfig::parse(&cfg.app) {
        Ok(app) => {
            if app.nodes {
                tools.push(Arc::new(seagent_app::node::NodeInvoke));
            }
            tools.extend(seagent_app::a2a::tools(&app.a2a));
        }
        Err(e) => eprintln!("seagent: warning: {e}"),
    }
    tools.extend(agentcmds::tools(ext.kernel.clone(), &paths, &cfg, ext::channel_map(&ext)));
    match seagent_app::surfaces::tools(&cfg, &paths, ext.kernel.clone(), ext::channel_map(&ext)) {
        Ok(t) => tools.extend(t),
        Err(e) => eprintln!("seagent: warning: {e}"),
    }
    match seagent_app::acp_client::AcpConfig::parse(&cfg.acp) {
        Ok(acp) => tools.push(Arc::new(seagent_app::acp_client::AcpDelegate { cfg: acp, gate: cfg.gate.clone(), vault: vault.clone() })),
        Err(e) => eprintln!("seagent: warning: {e}"),
    }
    match seagent_browser::tools(&seagent_app::computer::browser_table(&cfg.browser, &cfg.computer_use, &cfg.desktop_vm)) {
        Ok(b) => tools.extend(b),
        Err(e) => eprintln!("seagent: warning: {e}"),
    }
    // `computer_use` (Hermes) / `computer` (OpenClaw) on this gateway's own display
    // (`[computer_use]`; no paired node needed).
    match seagent_app::computer::tools_with(&cfg.computer_use, &cfg.desktop_vm) {
        Ok(c) => tools.extend(c),
        Err(e) => eprintln!("seagent: warning: {e}"),
    }
    // Media tools (`[media]`): vision/`view_image`, `pdf` + document extraction, image/video/
    // music generation, `text_to_speech`/`talk_voice`, `transcripts`, `voice_call` and the
    // meeting bots (`google_meet`, `teams_meetings`, `zoom_meetings`, `slack_huddles`).
    let media = media_host::media(&cfg, vault.clone());
    tools.extend(seagent_media::tools(&media));
    let (engine, memory) = ext::selected(&cfg, &ext).unwrap_or_else(|e| {
        eprintln!("seagent: warning: {e}; using seagent's own");
        (None, None)
    });
    if let Some(m) = memory {
        tools.retain(|t| t.spec().name != "memory");
        tools.push(m);
        if let Some(t) = ext.plugins.iter().find(|p| p.name == cfg.memory.provider.trim()).and_then(|p| p.memory_prompt()) {
            cfg.identity = if cfg.identity.is_empty() { t } else { format!("{}\n{t}", cfg.identity) };
        }
    }
    tools.retain(|t| !disabled.contains(&t.spec().name));
    devtools::configure_lsp(&cfg);
    let builtin_slash: Vec<Arc<dyn seagent_kernel::slash::Slash>> = seagent_plugin::builtin::slash(&cfg, &paths);
    // Sandbox tool policy / workspace access (see `build`).
    let tools = seagent_tools::exec::sandbox::wrap_all(tools);
    let k = new_kernel(cfg, paths.clone(), resolver, tools, vault, approver);
    k.add_hooks(hooks);
    for s in builtin_slash {
        k.add_slash(s);
    }
    // Model/session callbacks (image describe, PDF answers, voice turns, meeting talk-back),
    // the per-session image hooks and the background-generation completion sink.
    media_host::install(&k, &media);
    // Inbound voice calls need the webhook server up before a carrier dials
    // (`[media.phone] inbound = "allowlist" | "open"` + `public_url`).
    if with_channels && media.cfg.str("phone.inbound").is_some_and(|p| !p.trim().is_empty() && p != "off") {
        match seagent_media::phone::phone(&media).and_then(|p| p.serve()) {
            Ok(url) => eprintln!("seagent: voice-call webhook listening on {url}"),
            Err(e) => eprintln!("seagent: warning: voice calls: {e}"),
        }
    }
    if let Some(e) = engine {
        k.set_context_engine(e);
    }
    let _ = ext.kernel.set(k.clone());
    // Plugins declaring `"memory": true`: their `memory` tool joins the MemoryManager fan-out
    // (`search` for prefetch, `read` before compaction) as the one external provider.
    seagent_memory::host::set_plugin_providers(
        ext.plugins
            .iter()
            .filter(|p| p.memory)
            .map(|p| {
                let p = p.clone();
                let name = p.name.clone();
                let call: Arc<dyn Fn(serde_json::Value) -> Result<String, String> + Send + Sync> = Arc::new(move |params| p.memory(params));
                let rpc = seagent_memory::manager::tool_rpc(call);
                Arc::new(seagent_memory::manager::PluginProvider::new(&name, rpc)) as Arc<dyn seagent_memory::manager::Provider>
            })
            .collect(),
    );
    wire::attach(&k, &ws);
    agentcmds::attach(&k);
    Ok(Ctx { k, paths, workspace: ws, ext: Some(ext) })
}

/// The full agent kernel (hooks loaded) for `seagent hooks install`'s `before_install`.
pub(crate) fn build_agent_for_hooks(a: &Args) -> Result<Kernel, String> {
    build_agent(a, approver_for(a, false), false).map(|c| c.k).map_err(|e| match e {
        Fail::Msg(m) | Fail::Usage(m) => m,
    })
}

/// Expand `/command args` (custom commands, MCP prompts); plain text passes through.
fn expand_prompt(c: &Ctx, p: &str) -> Result<String, Fail> {
    match &c.ext {
        Some(e) => e.expand(p).map_err(Fail::Msg),
        None => Ok(p.to_string()),
    }
}

/// Resolve a possibly-abbreviated session id (unique prefix, or "last").
fn find_session(k: &Kernel, q: &str) -> Result<String, Fail> {
    let all = k.store.list();
    if q == "last" || q == "-" {
        return all.into_iter().find(|s| s.parent.is_none()).map(|s| s.id).ok_or_else(|| "no sessions yet".into());
    }
    let m: Vec<_> = all.into_iter().filter(|s| s.id == q || s.id.starts_with(q) || s.id.ends_with(q)).collect();
    match m.len() {
        0 => Err(format!("no session matches `{q}`").into()),
        1 => Ok(m[0].id.clone()),
        n => Err(format!("`{q}` matches {n} sessions; be more specific").into()),
    }
}

fn setup_hint(err: &str) -> Option<&'static str> {
    setup::hint(err)
}

fn exit_code(r: &EndReason) -> i32 {
    match r {
        EndReason::Done | EndReason::Idle => 0,
        EndReason::Interrupted => 130,
        EndReason::Budget(_) | EndReason::MaxSteps | EndReason::MaxTokens | EndReason::Stuck(_) => 3,
        // Temporarily stopped, not failed: the session resumes by itself (daemon) or on the
        // next run. Distinct from 1 so a script can tell "retry later" from "broken".
        EndReason::Paused(_) => 4,
        EndReason::Refusal | EndReason::Error(_) => 1,
    }
}

use ops::hostos::SIGINTS; // Ctrl-C counter (signal handler / console Ctrl handler)

/// Run a session in the foreground with live output and Ctrl-C → interrupt.
fn run_foreground(c: &Ctx, id: &str, a: &Args, opts: RunOpts) -> R {
    let rx = c.k.bus.subscribe();
    let (sid, json, quiet) = (id.to_string(), a.flag("json"), a.flag("quiet"));
    // Refresh the session's display preferences (/verbose, /timestamps, /focus, /trace,
    // /reasoning) once per turn, so a slash command applies to the next turn's output.
    let prefs = term::Prefs::for_session(&c.paths, id).quiet(quiet).offset(c.k.cfg.schedule.utc_offset_minutes);
    let focus = prefs.focus;
    let printer = std::thread::spawn(move || term::render_with(rx, sid, json, &prefs));
    ops::hostos::catch_sigint();
    let k2 = c.k.clone();
    let id2 = id.to_string();
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done2 = done.clone();
    let watcher = std::thread::spawn(move || {
        while !done2.load(Ordering::SeqCst) {
            if SIGINTS.load(Ordering::SeqCst) > 0 {
                k2.interrupt(&id2);
                eprintln!("\n• interrupting… (Ctrl-C again to force quit)");
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    });
    let started = Instant::now();
    let r = c.k.run(id, opts);
    done.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    ops::hostos::default_sigint();
    close_printer(&c.k, printer);
    let o = r.map_err(|e| Fail::Msg(e.to_string()))?;
    if !a.flag("quiet") && !a.flag("json") && !focus {
        // The error itself was already printed from the event stream. `/focus` keeps the
        // turn summary out of the way too (only the answer is shown).
        let label = match &o.reason {
            EndReason::Error(e) => setup_hint(e).map(|h| format!("failed — {h}")).unwrap_or_else(|| "failed".into()),
            EndReason::Paused(w) => format!("paused — {w} (state saved; it resumes on its own, or rerun when the provider is back)"),
            other => term::one_line(&other.label(), 120),
        };
        eprintln!("• {label} · {} tokens · {:.1}s · session {id}", o.usage.total(), started.elapsed().as_secs_f32());
    }
    if a.flag("json") {
        println!("{}", json!({"session": id, "reason": o.reason.label(), "text": o.text, "usage": o.usage}));
    }
    Ok(exit_code(&o.reason))
}

/// Stop a printer thread (it exits on the close sentinel) after flushing.
fn close_printer(k: &Kernel, h: std::thread::JoinHandle<()>) {
    k.bus.publish(seagent_kernel::kernel::BusMsg::Delta { session: term::CLOSE.into(), text: String::new(), thinking: false });
    let _ = h.join();
}

fn read_prompt(a: &Args, from: usize) -> Result<String, Fail> {
    let p = a.rest(from);
    if p.trim() == "-" || (p.trim().is_empty() && !std::io::stdin().is_terminal()) {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).map_err(|e| e.to_string())?;
        if s.trim().is_empty() {
            return usage("empty prompt on stdin");
        }
        return Ok(s);
    }
    if p.trim().is_empty() {
        return usage("missing <prompt>");
    }
    Ok(p)
}

// ───────────────────────── run / chat ─────────────────────────

fn cmd_run(a: &Args) -> R {
    let prompt = read_prompt(a, 0)?;
    let c = build_agent(a, approver_for(a, true), false)?;
    let prompt = match c.ext.as_ref().and_then(|e| e.run_command(&prompt, json!({"surface": "cli"}))) {
        Some(Err(e)) => return Err(e.into()),
        Some(Ok(r)) => {
            if let Some(t) = &r.text {
                println!("{t}");
            }
            match r.prompt {
                Some(p) => p,
                None => return Ok(0),
            }
        }
        None => expand_prompt(&c, &prompt)?,
    };
    let id = match a.val("session") {
        Some(s) => find_session(&c.k, s)?,
        None => c.k.create_session(&c.workspace, None, None, Some(&term::one_line(&prompt, 60))).map_err(|e| e.to_string())?,
    };
    if let Some(v) = a.val("output-schema") {
        c.k.set_output_schema(&id, output_schema_arg(v)?).map_err(|e| e.to_string())?;
    }
    c.k.submit(&id, &prompt, "cli").map_err(|e| e.to_string())?;
    let code = run_foreground(&c, &id, a, RunOpts::default())?;
    export::maybe_save_trajectory(&c.k, &id);
    Ok(code)
}

/// `--output-schema <json|@file|off>`: the run's answer must be submitted through
/// `structured_output` and validate against this JSON Schema (OpenClaw `structured-output-tool`).
pub(crate) fn output_schema_arg(v: &str) -> Result<Option<Value>, String> {
    let v = v.trim();
    if matches!(v, "off" | "none" | "-") {
        return Ok(None);
    }
    let text = match v.strip_prefix('@') {
        Some(p) => std::fs::read_to_string(p).map_err(|e| format!("{p}: {e}"))?,
        None => v.to_string(),
    };
    let s: Value = serde_json::from_str(&text).map_err(|e| format!("--output-schema: invalid JSON: {e}"))?;
    Ok(Some(s))
}

/// `seagent init [notes…]` / `seagent plan <task…>`: the built-in prompt as a one-shot run.
fn cmd_prompt_command(name: &str, a: &Args) -> R {
    let c = build_agent(a, approver_for(a, true), false)?;
    let args = a.rest(0);
    if name == "plan" && args.trim().is_empty() && a.val("session").is_none() {
        return usage("missing <task> (or --session ID to plan from that conversation)");
    }
    let prompt = devtools::builtin_prompt(name, &args, &c.workspace, &c.k.cfg).unwrap_or_default();
    let id = match a.val("session") {
        Some(s) => find_session(&c.k, s)?,
        None => c.k.create_session(&c.workspace, None, None, Some(&format!("/{name} {}", term::one_line(&args, 50)))).map_err(|e| e.to_string())?,
    };
    c.k.submit(&id, &prompt, "cli").map_err(|e| e.to_string())?;
    run_foreground(&c, &id, a, RunOpts::default())
}

fn cmd_chat(a: &Args) -> R {
    let c = build_agent(a, approver_for(a, true), false)?;
    let mut id = match a.val("session") {
        Some(s) => find_session(&c.k, s)?,
        None => c.k.create_session(&c.workspace, None, None, Some("chat")).map_err(|e| e.to_string())?,
    };
    eprintln!("seagent chat · session {id} · model {} · /help for commands, /exit to quit", c.k.cfg.model.default);
    ops::termcli::chat_started(&c.paths);
    let mut attach: Vec<seagent_core::Block> = vec![];
    let stdin = std::io::stdin();
    loop {
        eprint!("\n› ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let mut line = line.trim_end_matches(['\n', '\r']).to_string();
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with('/') {
            match chat_slash(&c, &mut id, a, &line, &mut attach)? {
                ChatStep::Continue => continue,
                ChatStep::Quit => break,
                ChatStep::Submit(t) => line = t,
            }
        }
        if seagent_kernel::reactions::detect(&line).is_some() && !a.flag("quiet") {
            eprintln!("♥");
        }
        let blocks = std::mem::take(&mut attach);
        c.k.submit_with(&id, &line, blocks, "cli").map_err(|e| e.to_string())?;
        let _ = run_foreground(&c, &id, a, RunOpts::default())?;
        ops::termcli::chat_turn_done(&c.k, &id);
        if let Some(bar) = chat_status_bar(&c, &id) {
            eprintln!("{bar}");
        }
        // The `/usage` footer is the session's own setting; `/focus` hides it with the rest.
        if !term::Prefs::for_session(&c.paths, &id).focus {
            if let Some(f) = models_cli::footer(&c.k, &id) {
                eprintln!("{f}");
            }
        }
    }
    c.k.end_session(&id, "exit");
    eprintln!("bye · resume with `seagent chat -s {id}`");
    Ok(0)
}

enum ChatStep {
    Continue,
    Quit,
    Submit(String),
}

/// The `/statusbar` line for `seagent chat`: model, context gauge, tokens and the git branch,
/// printed after each turn while the pref is on (`<config>/ui.json`, shared with `seagent tui`).
fn chat_status_bar(c: &Ctx, id: &str) -> Option<String> {
    use seagent_app::tui::statusbar::{self, Mode};
    // Unset = no bar in the plain REPL (the TUI shows one by default); `/statusbar on` here
    // turns it on for both surfaces.
    let pref = seagent_app::tui::prefs::get(&seagent_app::tui::prefs::load(&c.paths), "statusbar");
    if pref.is_null() || !Mode::from_value(&pref).shown() {
        return None;
    }
    let evs = c.k.store.read(id).ok()?;
    let v = project(&evs);
    let window = seagent_model::caps_for(v.model.rsplit('/').next().unwrap_or(&v.model)).context_window.max(1);
    let pct = (v.last_input_tokens as f64 * 100.0 / window as f64).round().clamp(0.0, 100.0) as u8;
    let ws = PathBuf::from(&v.workspace);
    let branch = statusbar::git_branch(if ws.is_dir() { ws.as_path() } else { c.workspace.as_path() });
    Some(statusbar::chat_line(&v.model, Some(pct), v.usage.total(), branch.as_deref()))
}

/// `seagent chat` slash handling: built-ins (shared with channels / TUI / web), then plugin
/// commands, then custom Markdown commands and MCP prompts.
fn chat_slash(c: &Ctx, id: &mut String, a: &Args, line: &str, attach: &mut Vec<seagent_core::Block>) -> Result<ChatStep, Fail> {
    let (name, arg) = {
        let cmd = line.trim_start_matches('/');
        cmd.split_once(' ').map(|(a, b)| (a, b.trim())).unwrap_or((cmd, ""))
    };
    if c.k.has_hooks(seagent_kernel::hooks::HookEvent::Command) {
        c.k.emit(seagent_kernel::hooks::HookEvent::Command, json!({"session_id": id, "cwd": c.workspace, "action": name, "sender_id": "cli", "source": "cli", "timestamp": hooks_ext::now_iso()}), "");
    }
    match name {
        // Model / reasoning / usage commands (models_cli).
        _ if models_cli::SLASH.iter().any(|(n, _)| *n == name) || name == "t" => {
            if let Some(out) = models_cli::slash(&c.k, id, line) {
                eprintln!("{out}");
            }
            return Ok(ChatStep::Continue);
        }
        // Approval / exec-policy controls (security).
        "approvals" if !arg.is_empty() => {
            match security_cli::persist_mode(&c.paths, &c.workspace, arg) {
                Ok(m) => eprintln!("• {m}"),
                Err(e) => eprintln!("error: {e}"),
            }
            return Ok(ChatStep::Continue);
        }
        "yolo" | "approvals" | "elevated" | "elev" | "exec" | "pause" | "resume" | "approve" | "deny" => {
            eprintln!("• {}", seagent_kernel::secgate::chat_command(&c.k, line, Some(id), None).unwrap_or_default());
            return Ok(ChatStep::Continue);
        }
        "upload-trace" | "trajectory" => {
            if let Err(e) = chat_export(c, id, name, arg) {
                eprintln!("error: {e}");
            }
            return Ok(ChatStep::Continue);
        }
        _ => {}
    }
    let notify: slash::Notify = Arc::new(|t: String| eprintln!("\n{t}"));
    // Commands act on the session's current workspace, not the one `seagent chat` started in:
    // `/worktree new|exit` move the session, and `/worktree status` must follow.
    let ws = c.k.store.read(id).ok().map(|e| PathBuf::from(project(&e).workspace)).unwrap_or_else(|| c.workspace.clone());
    let sctx = slash::Ctx { k: &c.k, ext: c.ext.as_ref(), session: Some(id.clone()), workspace: ws, surface: slash::Surface::Cli, sender: None, notify: Some(notify) };
    if let Some(r) = slash::run(&sctx, line) {
        if let Some(t) = &r.text {
            eprintln!("{t}");
        }
        match r.action {
            Some(slash::Action::NewSession { clear }) => {
                if clear {
                    eprint!("\x1b[2J\x1b[3J\x1b[H");
                }
                c.k.end_session(id, "new");
                *id = c.k.create_session(&c.workspace, None, None, Some("chat")).map_err(|e| e.to_string())?;
                eprintln!("• new session {id}");
            }
            Some(slash::Action::Quit { delete }) => {
                if delete {
                    c.k.end_session(id, "exit");
                    c.k.store.remove(id).map_err(|e| e.to_string())?;
                    eprintln!("• deleted session {id}");
                }
                return Ok(ChatStep::Quit);
            }
            Some(slash::Action::Local(name, arg)) => match name.as_str() {
                "redraw" => {
                    eprint!("\x1b[2J\x1b[3J\x1b[H");
                    if let Some(t) = slash::run(&sctx, "/history 40").and_then(|r| r.text) {
                        eprintln!("{t}");
                    }
                }
                "copy" => {
                    let last = project(&c.k.store.read(id).map_err(|e| e.to_string())?).messages.iter().rev().find(|m| m.role == Role::Assistant && !m.text().trim().is_empty()).map(|m| m.text());
                    match last {
                        Some(t) => match seagent_app::clip::copy(&t) {
                            Ok(how) => eprintln!("• copied {} chars ({how})", t.chars().count()),
                            Err(e) => eprintln!("error: {e}"),
                        },
                        None => eprintln!("nothing to copy yet"),
                    }
                }
                "paste" | "image" => {
                    let (arg, rest) = if name == "image" { seagent_app::clip::split_path_input(&arg) } else { (arg, String::new()) };
                    let b = if name == "paste" { seagent_app::clip::paste_image() } else { seagent_app::clip::image_file(&arg, &c.workspace) };
                    match b {
                        Ok(b) => {
                            attach.push(b);
                            eprintln!("• image attached to your next message ({} pending)", attach.len());
                            // Hermes leaves whatever followed the path as the prompt.
                            if !rest.is_empty() {
                                return Ok(ChatStep::Submit(rest));
                            }
                        }
                        Err(e) => eprintln!("error: {e}"),
                    }
                }
                "compose" => match seagent_app::clip::compose(&arg) {
                    Ok(t) if !t.is_empty() => return Ok(ChatStep::Submit(t)),
                    Ok(_) => eprintln!("• empty message, nothing sent"),
                    Err(e) => eprintln!("error: {e}"),
                },
                // `/statusbar [on|off|top|bottom|toggle]`: the plain REPL has no fixed chrome,
                // so the bar is one line printed after each turn (upstream `cli_status_bar_mixin`).
                "statusbar" => {
                    let cur = seagent_app::tui::statusbar::Mode::from_value(&seagent_app::tui::prefs::get(&seagent_app::tui::prefs::load(&c.paths), "statusbar"));
                    match seagent_app::tui::statusbar::Mode::parse(&arg, cur) {
                        Some(m) => match seagent_app::tui::prefs::set(&c.paths, "statusbar", json!(m.as_str())) {
                            Ok(_) => eprintln!("• status bar {} (top/bottom apply in `seagent tui`)", m.as_str()),
                            Err(e) => eprintln!("error: {e}"),
                        },
                        None => eprintln!("usage: /statusbar [on|off|top|bottom]"),
                    }
                }
                // `/worktree new` already moved the session in the kernel (`worktree_session`;
                // `EventKind::Workspace`), so the REPL only says where its tools run now.
                "workspace" => eprintln!("• tools now run in {arg} (/worktree exit returns)"),
                // `/branch` forked the conversation: this REPL continues in the fork.
                "session" => {
                    *id = arg.clone();
                    eprintln!("• now in session {arg} (/sessions shows them)");
                }
                _ => {}
            },
            None => {}
        }
        return Ok(match r.prompt {
            Some(p) => ChatStep::Submit(p),
            None => ChatStep::Continue,
        });
    }
    if c.ext.as_ref().is_some_and(|e| e.plugin_command(name).is_some()) {
        match c.ext.as_ref().and_then(|e| e.run_command(line, json!({"surface": "chat", "session": id}))) {
            Some(Ok(r)) => {
                if let Some(t) = &r.text {
                    eprintln!("{t}");
                }
                if let Some(p) = r.prompt {
                    return Ok(ChatStep::Submit(p));
                }
            }
            Some(Err(e)) => eprintln!("error: {e}"),
            None => {}
        }
        return Ok(ChatStep::Continue);
    }
    let _ = a;
    match expand_prompt(c, line) {
        Ok(t) if t != line => Ok(ChatStep::Submit(t)),
        Ok(_) => {
            eprintln!("unknown command /{name} (try /help or /commands)");
            Ok(ChatStep::Continue)
        }
        Err(e) => {
            eprintln!("error: {e}");
            Ok(ChatStep::Continue)
        }
    }
}

/// `/save [file]` (Markdown), `/export-session [file]` (HTML), `/export-trajectory`, `/upload-trace`.
fn chat_export(c: &Ctx, id: &str, name: &str, arg: &str) -> Result<(), String> {
    let events = c.k.store.read(id).map_err(|e| e.to_string())?;
    let now = seagent_kernel::event::now_ms();
    match name {
        "export-trajectory" | "trajectory" => {
            let dir = if arg.is_empty() { c.workspace.join(".seagent/trajectory-exports").join(seagent_kernel::trajectory::bundle_dir_name(id, now)) } else { PathBuf::from(arg) };
            eprintln!("• trajectory bundle → {}", export::write_bundle(&events, &dir, &c.k.vault)?.display());
        }
        "upload-trace" => eprintln!("{}", export::upload_trace(&c.k, id, None, true, true)?),
        _ => {
            let mut s = export::SessionData::from_events(&events);
            s.redact(&c.k.vault);
            let ext = if name == "save" { "md" } else { "html" };
            let path = if arg.is_empty() { c.workspace.join(export::safe_filename(&s, ext)) } else { PathBuf::from(arg) };
            std::fs::write(&path, export::render_one(&s, ext, c.k.cfg.schedule.utc_offset_minutes, now)).map_err(|e| format!("{}: {e}", path.display()))?;
            eprintln!("• saved {}", path.display());
        }
    }
    Ok(())
}

// ───────────────────────── sessions ─────────────────────────

/// `seagent fleet [status|board|files|limits|resume <session>] [--json]` — the multi-agent
/// progress overview (C10): the session tree, what every agent is doing right now, the files
/// it holds a lease on, its spend, and the shared board. `--json` is the same payload the
/// Web UI's Agents page renders, so CLI and UI can never disagree.
fn cmd_fleet(a: &Args) -> R {
    let sub = a.pos(0).unwrap_or("status");
    let c = build(a, approver_for(a, false))?;
    let json_out = a.flag("json");
    match sub {
        "status" | "list" | "ls" => {
            let v = seagent_kernel::coord::fleet_overview(&c.k);
            if json_out {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                return Ok(0);
            }
            let agents = v["agents"].as_array().cloned().unwrap_or_default();
            if agents.is_empty() {
                println!("no agents running or recorded (delegate_task / sessions_spawn fill this in)");
            } else {
                println!("{:<20} {:>3} {:<10} {:>8} {:>7}  goal · files", "agent", "dep", "state", "tokens", "$");
                for x in &agents {
                    let tokens = x["input_tokens"].as_u64().unwrap_or(0) + x["output_tokens"].as_u64().unwrap_or(0);
                    let files: Vec<String> = x["owned_files"].as_array().map(|f| f.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default();
                    println!(
                        "{:<20} {:>3} {:<10} {:>8} {:>7}  {}{}",
                        term::one_line(x["subagent_id"].as_str().or(x["id"].as_str()).or(x["session_id"].as_str()).unwrap_or("?"), 20),
                        x["depth"].as_u64().unwrap_or(0),
                        x["state"].as_str().unwrap_or("?"),
                        tokens,
                        format!("{:.2}", x["spend_usd"].as_f64().unwrap_or(0.0)),
                        term::one_line(x["goal"].as_str().unwrap_or(""), 48),
                        if files.is_empty() { String::new() } else { format!(" · {}", term::one_line(&files.join(","), 40)) }
                    );
                }
            }
            let counts = &v["counts"];
            println!("\nrunning {} · done {} · failed {} · leases {}", counts["running"], counts["done"], counts["failed"], counts["leased_files"]);
            Ok(0)
        }
        "board" => {
            let lim = a.num::<usize>("limit").map_err(Fail::Usage)?.unwrap_or(20);
            let entries = seagent_kernel::coord::board_recent(&c.k, lim, None, None);
            if json_out {
                println!("{}", serde_json::to_string_pretty(&entries).unwrap_or_default());
                return Ok(0);
            }
            if entries.is_empty() {
                println!("the board is empty (agents post with board_post)");
            }
            for e in entries {
                println!("{:<12} {:<10} {:<20} {}", e.kind, e.session.chars().take(10).collect::<String>(), e.ts_ms / 1000, term::one_line(&e.text, 100));
            }
            Ok(0)
        }
        "files" | "leases" => {
            let leases = seagent_kernel::coord::owned(&c.k);
            if json_out {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!(leases.iter().map(|l| serde_json::json!({"path": l.path, "owner": l.owner, "expires_ms": l.expires_ms})).collect::<Vec<_>>())).unwrap_or_default());
                return Ok(0);
            }
            if leases.is_empty() {
                println!("no file leases (files_claim takes one)");
            }
            for l in leases {
                println!("{:<40} {}", l.path, l.owner);
            }
            Ok(0)
        }
        "limits" => {
            let v = serde_json::json!({"limits": seagent_kernel::limits::status_json(&c.k), "reaper": seagent_kernel::reaper::sweep_json(&c.paths.data)});
            if json_out {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
                return Ok(0);
            }
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            Ok(0)
        }
        "resume" => {
            let id = a.need(1, "session")?;
            let was = seagent_kernel::limits::resumed(&c.paths.data, id);
            println!("{}", if was { format!("resumed {id}") } else { format!("{id} was not paused") });
            Ok(0)
        }
        other => usage(format!("unknown `fleet {other}`; use status, board, files, limits or resume")),
    }
}

// ───────────────────────── daemon ─────────────────────────

const HOST_METHODS: &[&str] = &["channels.list", "pairing.list", "pairing.approve", "pairing.revoke", "mcp.list", "mcp.app_call", "plugins.list", "plugins.ui", "plugins.ui_call", "command.run", "session.handoff"];

fn plugin_json(p: &Arc<seagent_plugin::PluginHost>) -> Value {
    json!({"name": p.name, "hooks": p.hooks(), "channels": p.channels(), "commands": p.commands, "routes": p.routes, "providers": p.providers, "services": p.services,
        "cli": p.cli, "middleware": p.middleware_kinds(), "context_engine": p.context_engine, "memory": p.memory, "node_commands": p.node_commands, "ui": p.ui,
        "backends": p.backends, "dashboard_auth": p.dashboard_auth})
}

/// `/plugins/<name>/ui/<id>`: a declared UI panel.
fn ui_panel(sub: &str) -> Option<&str> {
    sub.strip_prefix("/ui/").map(|id| id.trim_end_matches('/')).filter(|id| !id.is_empty() && !id.contains('/'))
}

/// A plugin's HTTP routes on the app server.
struct PluginMount(Arc<seagent_plugin::PluginHost>);

impl seagent_app::server::Mount for PluginMount {
    fn route(&self, method: &str, sub: &str) -> Option<bool> {
        if method == "GET" && ui_panel(sub).is_some_and(|id| self.0.ui.iter().any(|u| u.id == id)) {
            return Some(false);
        }
        self.0.route(method, sub).map(|r| r.public)
    }
    fn serve(&self, r: &seagent_net::httpd::Request, sub: &str) -> seagent_net::httpd::Response {
        if let Some(id) = ui_panel(sub).filter(|id| r.method == "GET" && self.0.ui.iter().any(|u| u.id == *id)) {
            return match self.0.ui_render(id, &r.raw_query) {
                Ok(v) => seagent_net::httpd::Response::new(200, "text/html; charset=utf-8", v["html"].as_str().unwrap_or("").as_bytes().to_vec()),
                Err(e) => seagent_net::httpd::Response::json(502, &json!({"error": e}).to_string()),
            };
        }
        match self.0.http(&r.method, sub, &r.raw_query, &r.headers, &r.body) {
            Ok(h) => {
                let ctype = h.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone()).unwrap_or_else(|| "application/octet-stream".into());
                let mut resp = seagent_net::httpd::Response::new(h.status, &ctype, h.body);
                const SKIP: &[&str] = &["content-type", "content-length", "connection", "transfer-encoding", "content-security-policy"];
                for (k, v) in h.headers.iter().filter(|(k, _)| !SKIP.iter().any(|s| k.eq_ignore_ascii_case(s))) {
                    resp = resp.with_header(k, v);
                }
                resp
            }
            Err(e) => seagent_net::httpd::Response::json(502, &json!({"error": e}).to_string()),
        }
    }
}

/// ARP methods that live in the binary (channels, DM pairing, MCP status).
fn host_methods(paths: &Paths, ext: Option<&ext::Ext>) -> seagent_kernel::daemon::MethodExt {
    let pairing = Arc::new(seagent_channel::access::Pairing::open(paths.data.join("channels").join("pairing.json")));
    let plugins: Vec<Arc<seagent_plugin::PluginHost>> = ext.map(|e| e.plugins.clone()).unwrap_or_default();
    let kslot: Arc<std::sync::OnceLock<Kernel>> = ext.map(|e| e.kernel.clone()).unwrap_or_default();
    let plugin_list: Vec<Value> = plugins.iter().map(plugin_json).collect();
    let channels: Vec<Value> = ext.map(|e| e.channels.iter().map(|(n, (ch, c))| json!({"name": n, "kind": c.kind, "caps": ch.caps(), "dm_policy": c.policy.dm_policy, "default_chat": c.default_chat})).collect()).unwrap_or_default();
    let handoff_channels = ext.map(agentcmds::handoff::channels).unwrap_or_default();
    let mcp: Vec<Value> = ext.map(|e| e.registry.status().into_iter().map(|(n, tools, running)| json!({"name": n, "tools": tools, "running": running})).collect()).unwrap_or_default();
    // MCP Apps: tools a view may call, with the client that serves them.
    let app_tools: Vec<(String, seagent_plugin::ToolDef, Arc<seagent_plugin::Client>)> =
        ext.map(|e| e.registry.app_tools().into_iter().filter_map(|(s, d)| Some((s.clone(), d, e.registry.client(&s)?))).collect()).unwrap_or_default();
    let kernel = ext.map(|e| e.kernel.clone());
    Arc::new(move |m: &str, p: &Value| {
        let s = |k: &str| p[k].as_str().unwrap_or("").to_string();
        Some(match m {
            "mcp.app_call" => mcp_app_call(&app_tools, kernel.as_ref().and_then(|k| k.get()), p),
            "channels.list" => Ok(json!(channels)),
            "mcp.list" => Ok(json!(mcp)),
            "plugins.list" => Ok(json!(plugin_list)),
            // UI panels: the page renders the HTML in a sandboxed srcdoc frame (like MCP Apps).
            "plugins.ui" | "plugins.ui_call" => {
                let (name, id) = (s("plugin"), s("id"));
                let Some(h) = plugins.iter().find(|h| h.name == name) else { return Some(Err((-32602, format!("no plugin `{name}`")))) };
                let r = if m == "plugins.ui" { h.ui_render(&id, p["query"].as_str().unwrap_or("")) } else { h.ui_call(&id, &s("method"), p.get("params").cloned().unwrap_or(json!({}))) };
                r.map_err(|e| (-32000, e))
            }
            // Plugin slash commands for the TUI / web UI: {handled:false} when `line` is not one.
            "command.run" => {
                let line = s("line");
                let ctx = json!({"surface": p["surface"].as_str().unwrap_or("tui"), "session": p["session"]});
                if let Some(r) = kslot.get().and_then(|k| ext::native_command(k, &line, p["session"].as_str(), p["surface"].as_str().unwrap_or("tui"))) {
                    return Some(r.map(|r| json!({"handled": true, "text": r.text, "prompt": r.prompt})).map_err(|e| (-32000, e)));
                }
                let rest = line.trim().trim_start_matches('/');
                let name = rest.split_whitespace().next().unwrap_or("");
                match plugins.iter().find(|h| h.commands.iter().any(|c| c.name == name)) {
                    None => Ok(json!({"handled": false})),
                    Some(h) => h.command(name, rest[name.len()..].trim(), ctx).map(|r| json!({"handled": true, "text": r.text, "prompt": r.prompt})).map_err(|e| (-32000, e)),
                }
            }
            // `/handoff` from a CLI process (its own router is not the daemon's).
            "session.handoff" => {
                let Some(k) = kslot.get() else { return Some(Err((-32000, "agent not ready".into()))) };
                let target = agentcmds::handoff::Target { channel: s("channel"), chat: s("chat") };
                agentcmds::handoff::perform(k, &handoff_channels, agentcmds::bindings::router().map(|r| r.as_ref()), &s("session"), &target)
                    .map(|text| json!({"text": text, "session": s("session"), "channel": target.channel, "chat": target.chat}))
                    .map_err(|e| (-32000, e))
            }
            "pairing.list" => Ok(json!({"pending": pairing.pending(), "approved": pairing.approved().into_iter().map(|(c, s, a)| json!({"channel": c, "sender": s, "name": a.sender_name, "approved_at": a.approved_at})).collect::<Vec<_>>()})),
            "pairing.approve" => pairing.approve(&s("channel"), &s("code")).map(|(sender, name)| json!({"sender": sender, "name": name})).map_err(|e| (-32001, e)),
            "pairing.revoke" => Ok(json!({"revoked": pairing.revoke(&s("channel"), &s("sender"))})),
            _ => return None,
        })
    })
}

/// `tools/call` from an MCP App view, proxied over ARP. Only tools the server marks
/// app-visible; anything not read-only asks the egress gate's human first.
fn mcp_app_call(tools: &[(String, seagent_plugin::ToolDef, Arc<seagent_plugin::Client>)], k: Option<&Kernel>, p: &Value) -> Result<Value, (i32, String)> {
    use seagent_kernel::approver::{Approval, ApprovalRequest};
    let (server, name) = (p["server"].as_str().unwrap_or(""), p["name"].as_str().unwrap_or(""));
    let Some((_, def, client)) = tools.iter().find(|(s, d, _)| s == server && d.name == name) else {
        return Err((-32602, format!("`{name}` on MCP server `{server}` is not callable from an app view")));
    };
    let args = if p["arguments"].is_object() { p["arguments"].clone() } else { json!({}) };
    if !def.read_only || client.config().untrusted() {
        let k = k.ok_or((-32000, "agent not ready".to_string()))?;
        let req = ApprovalRequest {
            id: format!("app-{}", seagent_net::crypto::random_token(6)),
            tool_use_id: String::new(),
            session: p["session"].as_str().unwrap_or("mcp-app").into(),
            tool: format!("mcp__{server}__{name}"),
            summary: args.to_string().chars().take(2000).collect(),
            input: args.clone(),
            gate: seagent_kernel::gate::GateKind::Egress,
            reason: format!("the `{server}` app view wants to call `{name}`"),
            tier: 0,
        };
        if k.approver.approve(&req) == Approval::Deny {
            return Err((-32001, "denied by the user".into()));
        }
    }
    let r = client.call_tool(name, args, &seagent_core::Cancel::new()).map_err(|e| (-32000, e))?;
    let mut raw = if r.raw.is_object() { r.raw } else { json!({"content": [{"type": "text", "text": r.text}]}) };
    if r.is_error {
        raw["isError"] = json!(true);
    }
    Ok(raw)
}

fn cmd_daemon(a: &Args) -> R {
    let paths = Paths::from_env();
    let sock = paths.socket();
    match a.pos(0).unwrap_or("status") {
        "run" => {
            let (pending, cell) = daemon::pending_approver(Duration::from_secs(600));
            let mut c = build_agent(a, pending.clone(), true)?;
            // srv-017: `approvals.timeout_secs` is the wait, not a hard-coded 600 s.
            pending.set_timeout(Duration::from_secs(c.k.cfg.approvals.timeout_secs.max(1)));
            let ext_arc: Option<Arc<ext::Ext>> = c.ext.take().map(Arc::new);
            let _ = cell.set(Arc::downgrade(&c.k));
            eprintln!("seagentd {} listening on {}", env!("CARGO_PKG_VERSION"), sock.display());
            if let Some(w) = ops::service::record_start(&paths) {
                eprintln!("seagentd: warning: {w}");
            }
            let stop = seagent_core::Cancel::new();
            let services = ext_arc.as_deref().and_then(|e| seagent_plugin::plugin::supervise(e.plugins.clone(), stop.clone()));
            agentcmds::start_daemon_services(&c.k);
            for p in ext_arc.iter().flat_map(|e| e.plugins.iter()).filter(|p| !p.routes.is_empty() || !p.ui.is_empty()) {
                seagent_app::server::mount(&p.name, Arc::new(PluginMount(p.clone())));
            }
            c.k.emit(seagent_kernel::hooks::HookEvent::DaemonStart, json!({"session_id": "", "cwd": c.workspace, "pid": std::process::id()}), "");
            let d = Arc::new(Daemon::new(c.k.clone(), pending));
            // Opt-in unattended plugin updates (`[automation] plugin_auto_update_hours`, default
            // off): the pass re-scans every candidate and skips caution verdicts for a human.
            {
                let (cfg, paths2) = (c.k.cfg.clone(), paths.clone());
                d.add_maintenance(Arc::new(move || {
                    let now = seagent_kernel::util::unix_now().max(0) as u64;
                    match seagent_skills::hub::plugins::run_auto_update(&cfg, &paths2, now) {
                        Ok(out) if out.contains("updated `") || out.contains("skipped:") => eprintln!("seagentd: {out}"),
                        Ok(_) => {}
                        Err(e) => eprintln!("seagentd: plugin auto-update: {e}"),
                    }
                }));
            }
            seagent_app::node::init(&paths.data);
            d.add_methods(seagent_app::node::methods());
            let lk = c.k.clone();
            d.add_methods(Arc::new(move |m: &str, p: &Value| seagent_app::logbook::call(&lk, m, p)));
            d.add_methods(slash::methods(c.k.clone(), ext_arc.clone(), c.workspace.clone()));
            ops::logs::install(&c.k);
            d.add_methods(ops::logs::methods(paths.clone()));
            d.add_methods(host_methods(&paths, ext_arc.as_deref()));
            d.add_methods(seagent_memory::host::methods(&c.k.cfg, &paths)); // srv-037: kb.search / kb.status
            // Work surfaces: dashboards / cards / workflow ARP, hosted documents, report schedule.
            let surfaces = ext_arc.as_deref().and_then(|e| seagent_app::surfaces::Env::new(&c.k.cfg, &paths, e.kernel.clone(), ext::channel_map(e)).map_err(|w| eprintln!("seagentd: warning: {w}")).ok()).map(Arc::new);
            if let Some(s) = &surfaces {
                d.add_methods(seagent_app::surfaces::methods(s.clone()));
                seagent_app::surfaces::gateway::deliver_restart_notice(s);
            }
            // ent-095: leader-only services — channel polling, hook services (watchers, Gmail),
            // scheduled backups and report schedules. Without `[ha]` the daemon leads at once;
            // with it they start on every lease win and stop when the lease is lost, so two
            // nodes never both answer a chat message or send the same report.
            {
                let (k, ext, ws, paths2, surf, stop) = (c.k.clone(), ext_arc.clone(), c.workspace.clone(), paths.clone(), surfaces.clone(), stop.clone());
                let term: std::sync::Mutex<Option<seagent_core::Cancel>> = std::sync::Mutex::new(None);
                d.on_leadership(Box::new(move |leader| {
                    if let Some(t) = term.lock().unwrap().take() {
                        t.cancel();
                    }
                    if !leader {
                        return;
                    }
                    let t = stop.child();
                    let loops = match &ext {
                        Some(e) => ext::spawn_channel_loops(k.clone(), e, ws.clone(), t.clone()),
                        None => vec![],
                    };
                    if !loops.is_empty() {
                        eprintln!("seagentd: {} channel(s) active", loops.len());
                    }
                    hooks_ext::start_daemon_services(&k, &ws, t.clone());
                    ops::backup::spawn_scheduler(paths2.clone(), k.cfg.backup.clone(), t.clone());
                    surf.clone().and_then(|s| seagent_app::surfaces::spawn_daemon(s, t.clone()));
                    *term.lock().unwrap() = Some(t);
                }));
            }
            d.add_methods(ops::ui_methods::methods(&paths, c.k.clone(), ext_arc.as_deref()));
            d.add_methods(ops::webui::methods(&paths, c.k.clone(), ext_arc.as_deref()));
            d.add_methods(ops::dock::methods(c.k.clone()));
            // First-run web wizard over ARP (admin credential); the page itself uses /setup/rpc.
            d.add_methods(setup_web::methods(&paths));
            // ent-098: readiness for `seagent health --ready` (the same checks as GET /ready).
            {
                let weak = Arc::downgrade(&d);
                d.add_methods(Arc::new(move |m: &str, _p: &Value| {
                    (m == "health.ready").then(|| weak.upgrade().map(|d| seagent_app::metrics::readiness_json(&d).1).ok_or((-32000, "daemon is stopping".to_string())))
                }));
            }
            // App server: web/desktop UI, WebSocket ARP, OpenAI-compatible API, A2A, nodes.
            // LAN mode: native TLS with the generated identity (seagent_app::lan), paired devices.
            let app_cfg = seagent_app::lan::effective(&seagent_app::AppConfig::parse(&c.k.cfg.app)?, &paths.data)?;
            d.add_methods(ops::lan::methods(&paths, c.k.clone(), app_cfg.clone()));
            let _server = if app_cfg.enabled {
                let token = app_cfg.token.as_deref().map(|t| (c.k.vault_substitute())(t)).unwrap_or_default();
                if token.contains("{{secret:") {
                    return Err("[app] token references a secret that is not set (seagent secrets set APP_TOKEN …)".into());
                }
                let mut host: Vec<String> = seagent_app::node::METHODS.iter().map(|s| s.to_string()).collect();
                host.extend(HOST_METHODS.iter().chain(ops::ui_methods::METHODS).chain(ops::webui::METHODS).chain(ops::dock::METHODS).map(|s| s.to_string()));
                host.extend(seagent_app::surfaces::METHODS.iter().map(|s| s.to_string()));
                host.extend(seagent_kernel::cluster::METHODS.iter().chain(seagent_app::devices::METHODS).chain(ops::lan::METHODS).map(|s| s.to_string()));
                // MCP event deliveries arrive as signed webhooks and are queued into the subscribing session.
                let mut routes: Vec<(String, seagent_net::httpd::Handler)> = surfaces.clone().map(|s| seagent_app::surfaces::routes(s, token.clone())).unwrap_or_default();
                if let Some(hub) = ext_arc.as_deref().and_then(|e| e.registry.events()) {
                    let k = c.k.clone();
                    hub.set_sink(Arc::new(move |dl: &seagent_plugin::events::Delivery| {
                        let Some(sid) = dl.session.as_deref() else { return };
                        if k.submit(sid, &seagent_plugin::events::prompt_for(dl), "mcp-event").is_ok() && !k.is_running(sid) {
                            let _ = k.start(sid, Default::default());
                        }
                    }));
                    hub.start_refresher();
                    routes.push(("/mcp-events/".into(), hub.handler()));
                }
                // Telegram Mini App launcher for the Control UI (`/controlui`); checks its own auth.
                routes.extend(ops::miniapp::routes(Arc::new(ops::miniapp::env(&paths, &c.workspace, &token))));
                // The setup wizard's RPC authenticates with its own one-time token (setup_web.rs).
                routes.extend(setup_web::routes(Arc::new(setup_web::Env { paths: paths.clone(), allow_origins: app_cfg.allow_origins.clone() })));
                host.extend(setup_web::METHODS.iter().map(|s| s.to_string()));
                let app = Arc::new(seagent_app::App { d: d.clone(), cfg: app_cfg.clone(), token, host_methods: host, routes });
                let srv = seagent_app::start(app)?;
                eprintln!("seagentd: app server on {}://{} (UI, /arp, /v1, {})", if srv.is_tls() { "https" } else { "http" }, srv.local_addr(), if app_cfg.a2a.enabled { "/a2a" } else { "no a2a" });
                Some((srv, seagent_app::lan::advertise(&app_cfg, &paths.data).map_err(|e| eprintln!("seagentd: warning: {e}")).ok().flatten()))
            } else {
                None
            };
            let r = d.run();
            c.k.emit(seagent_kernel::hooks::HookEvent::DaemonStop, json!({"session_id": "", "cwd": c.workspace, "reason": "shutdown"}), "");
            stop.cancel();
            if let Some(t) = services {
                let _ = t.join();
            }
            r?;
            if setup_web::restart_requested() {
                return Ok(setup_web::after_stop());
            }
            Ok(0)
        }
        "start" => {
            if daemon::call(&sock, "ping", json!({})).is_ok() {
                println!("seagentd already running");
                return Ok(0);
            }
            std::fs::create_dir_all(&paths.data).map_err(|e| e.to_string())?;
            let log = std::fs::OpenOptions::new().create(true).append(true).open(paths.daemon_log()).map_err(|e| e.to_string())?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let mut cmd = std::process::Command::new(exe);
            cmd.arg("daemon").arg("run").stdin(std::process::Stdio::null()).stdout(log.try_clone().map_err(|e| e.to_string())?).stderr(log);
            // Detached by us, not by a service manager: a restart after the setup wizard is ours to do.
            cmd.env("SEAGENT_DAEMON_DETACHED", "1").env_remove("NOTIFY_SOCKET").env_remove("INVOCATION_ID");
            for s in a.vals("set") {
                cmd.arg("--set").arg(s);
            }
            if let Some(w) = a.val("workspace") {
                cmd.arg("-w").arg(w);
            }
            if a.flag("yolo") {
                cmd.arg("--yolo");
            }
            ops::hostos::detach(&mut cmd);
            let mut child = cmd.spawn().map_err(|e| e.to_string())?;
            let until = Instant::now() + Duration::from_secs(8);
            while Instant::now() < until {
                if daemon::call(&sock, "ping", json!({})).is_ok() {
                    println!("seagentd started (pid {})", child.id());
                    return Ok(0);
                }
                if let Ok(Some(st)) = child.try_wait() {
                    return Err(format!("seagentd exited during startup ({st}); see {}", paths.daemon_log().display()).into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err("seagentd did not come up within 8s".into())
        }
        "stop" => {
            match daemon::call(&sock, "shutdown", json!({})) {
                Ok(_) => {
                    let until = Instant::now() + Duration::from_secs(15);
                    // A named pipe (Windows) is no file: wait until nobody answers on it.
                    let up = || if cfg!(windows) { ops::hostos::daemon_reachable(&sock) } else { sock.exists() };
                    while up() && Instant::now() < until {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    println!("{}", if up() { "seagentd is still shutting down" } else { "seagentd stopped" });
                }
                Err(_) => println!("seagentd is not running"),
            }
            Ok(0)
        }
        "status" => match daemon::call(&sock, "ping", json!({})) {
            Ok(r) => {
                let role = match (r["role"].as_str(), r["node"].as_str()) {
                    (Some(role), Some(node)) => format!(" · HA {role} ({node})"),
                    _ => String::new(),
                };
                println!("seagentd running · pid {} · version {} · running sessions: {}{role}", r["pid"], r["version"].as_str().unwrap_or("?"), r["running"].as_array().map(|v| v.len()).unwrap_or(0));
                Ok(0)
            }
            Err(e) => {
                println!("{e}");
                Ok(1)
            }
        },
        other => usage(format!("unknown `daemon {other}`")),
    }
}

fn cmd_attach(a: &Args) -> R {
    let id = a.need(0, "session")?.to_string();
    let from = a.num::<u64>("from").map_err(Fail::Usage)?.unwrap_or(0);
    let json_out = a.flag("json");
    let sock = Paths::from_env().socket();
    daemon::stream(&sock, "session.attach", json!({"id": id, "from_seq": from}), |v| match attach_render(v, json_out) {
        Attach::Skip => true,
        Attach::Text(t) => {
            print!("{t}");
            let _ = std::io::stdout().flush();
            true
        }
        Attach::Line(l) => {
            eprintln!("{l}");
            true
        }
        Attach::Json(j) => {
            println!("{j}");
            true
        }
    })?;
    Ok(0)
}

/// What `seagent attach` writes for one streamed message.
#[derive(Debug, PartialEq)]
pub enum Attach {
    Skip,
    Text(String),
    Line(String),
    Json(Value),
}

/// Render one `session.attach` message: assistant text streams without a newline, lifecycle
/// notices and approvals go to stderr as `•`/`⚑` lines, and `--json` prints the raw message.
/// Thinking deltas stay hidden (they are not the reply).
pub fn attach_render(v: &Value, json_out: bool) -> Attach {
    if json_out {
        return Attach::Json(v.clone());
    }
    match v.get("method").and_then(|m| m.as_str()) {
        Some("delta") => {
            if v["params"]["thinking"].as_bool() == Some(true) {
                Attach::Skip
            } else {
                Attach::Text(v["params"]["text"].as_str().unwrap_or("").to_string())
            }
        }
        Some("event") => {
            let e = &v["params"]["event"];
            match e["type"].as_str() {
                Some("turn_end") => Attach::Line(format!("\n• turn ended: {}", e["reason"].as_str().unwrap_or(""))),
                Some("notice") | Some("error") => Attach::Line(format!("• {}", e["text"].as_str().or(e["message"].as_str()).unwrap_or(""))),
                Some("gate") => Attach::Line(format!("⚑ {} gate: {} — {}", e["gate"].as_str().unwrap_or(""), e["verdict"].as_str().unwrap_or(""), e["reason"].as_str().unwrap_or(""))),
                _ => Attach::Skip,
            }
        }
        Some("pending") => Attach::Line(format!(
            "⚑ waiting for approval: {}  →  seagent gate answer {} once|always|deny",
            v["params"]["reason"].as_str().or(v["params"]["question"].as_str()).unwrap_or(""),
            v["params"]["id"].as_str().unwrap_or("")
        )),
        _ => Attach::Skip,
    }
}

fn cmd_gate(a: &Args) -> R {
    let sock = Paths::from_env().socket();
    match a.pos(0).unwrap_or("list") {
        "list" | "pending" => {
            let r = daemon::call(&sock, "gate.pending", json!({}))?;
            let items = r.as_array().cloned().unwrap_or_default();
            if items.is_empty() {
                println!("nothing pending");
            }
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&items).unwrap_or_default());
                return Ok(0);
            }
            for i in items {
                println!("{}  [{}] {} {}", i["id"].as_str().unwrap_or(""), i["kind"].as_str().unwrap_or(""), i["reason"].as_str().or(i["question"].as_str()).unwrap_or(""), i["summary"].as_str().map(|s| term::one_line(s, 100)).unwrap_or_default());
                if let Some(line) = ops::enterprise::dual_control_line(&i["dual_control"]) {
                    println!("{line}");
                }
            }
            Ok(0)
        }
        "policy" => ops::enterprise::out(serde_json::to_string_pretty(&daemon::call(&sock, "gate.policy.show", json!({}))?).unwrap_or_default()),
        "answer" => {
            let id = a.need(1, "id")?;
            let ans = a.rest(2);
            if ans.trim().is_empty() {
                return usage("missing <answer>");
            }
            // An open question takes free text; an approval needs a decision word.
            let is_approval = daemon::call(&sock, "gate.pending", json!({}))?.as_array().is_some_and(|v| v.iter().any(|i| i["id"] == id && i["kind"] == "approval"));
            let ans = if is_approval { security_cli::resolve_answer(&ans, a.val("reason")).ok_or_else(|| Fail::Usage("answer with once|session|permanent|deny [reason…]".into()))? } else { ans };
            let r = daemon::call(&sock, "gate.answer", json!({"id": id, "answer": ans}))?;
            if r["final"] == false {
                println!("approval counted: {}/{} (dual control — another approver is needed)", r["approvals"], r["required"]);
            } else {
                println!("answered");
            }
            Ok(0)
        }
        other => usage(format!("unknown `gate {other}` (list [--json] | answer <id> <once|deny …> | policy)")),
    }
}

// ───────────────────────── schedule / goals ─────────────────────────

fn cmd_schedule(a: &Args) -> R {
    use seagent_kernel::cronjob::{incidents, Settings, Spec};
    let paths = Paths::from_env();
    match a.pos(0).unwrap_or("list") {
        "add" => {
            let cron = a.need(1, "cron")?;
            let prompt = a.rest(2);
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let j = automation::add_job(&paths.data, cron, &prompt, &ws, a.val("model").map(String::from), a.flag("reuse"), cfg.schedule.utc_offset_minutes)?;
            println!("added {} · next run {} (UTC{:+})", j.id, seagent_kernel::util::fmt_time(j.next_run, cfg.schedule.utc_offset_minutes), cfg.schedule.utc_offset_minutes as f64 / 60.0);
            if daemon::call(&paths.socket(), "ping", json!({})).is_err() {
                eprintln!("note: seagentd is not running; schedules fire only while it runs (`seagent daemon start`)");
            }
            Ok(0)
        }
        "list" | "ls" => {
            let jobs: Vec<Job> = automation::read_list(&automation::jobs_path(&paths.data))?;
            if jobs.is_empty() {
                println!("no schedules");
            }
            for j in jobs {
                println!("{}  {:<16} {}  next {}  last {}  {}", j.id, j.cron, if j.enabled { "on " } else { "off" }, seagent_kernel::util::fmt_time(j.next_run, 480), j.last_result.as_deref().unwrap_or("-"), term::one_line(&j.prompt, 50));
            }
            Ok(0)
        }
        // `seagent schedule edit <id|name> [field=value …]`: only the named fields change.
        // Fields: cron (alias schedule/expr), prompt, name, model, deliver, failure-deliver,
        // repeat, skill (comma-separated, replaces the set), workdir, enabled|disabled,
        // no-agent|agent, continuity=on|off. `prompt=` / `deliver=` with nothing clears them.
        "edit" => {
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let st = Settings::from_config(&cfg);
            let job = seagent_kernel::cronjob::find(&paths.data, a.need(1, "id")?)?;
            let mut spec = Spec::default();
            if let Some(v) = a.val("name") {
                spec.name = Some(v.to_string());
            }
            if let Some(v) = a.val("model") {
                spec.model = Some(v.to_string());
            }
            let mut enabled: Option<bool> = None;
            for tok in a.pos.iter().skip(2) {
                let Some((k, v)) = tok.split_once('=') else {
                    return usage(format!("`schedule edit` takes field=value pairs (got `{tok}`); e.g. `seagent schedule edit {} cron=\"0 9 * * 1-5\"`", job.id));
                };
                let v = v.trim();
                match k.trim().to_ascii_lowercase().replace('_', "-").as_str() {
                    "cron" | "schedule" | "expr" => {
                        if v.is_empty() {
                            return usage("cron= cannot be empty");
                        }
                        spec.schedule = Some(v.to_string())
                    }
                    "prompt" => spec.prompt = Some(v.replace("\\n", "\n")),
                    "name" => spec.name = Some(v.to_string()),
                    "model" => spec.model = Some(v.to_string()),
                    "deliver" => spec.deliver = Some(v.to_string()),
                    "failure-deliver" | "failure" => spec.failure_deliver = Some(v.to_string()),
                    "repeat" => spec.repeat = Some(v.parse::<u32>().map_err(|_| Fail::Usage(format!("repeat=`{v}` is not a positive integer")))?),
                    "skill" | "skills" => spec.skills = Some(v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()),
                    "workdir" => spec.workdir = Some(v.to_string()),
                    "no-agent" => spec.no_agent = Some(true),
                    "agent" => spec.no_agent = Some(false),
                    "continuity" => spec.continuity = Some(v.is_empty() || matches!(v.to_ascii_lowercase().as_str(), "on" | "true" | "yes" | "1")),
                    "enabled" => enabled = Some(!matches!(v.to_ascii_lowercase().as_str(), "false" | "off" | "no" | "0")),
                    "disabled" | "paused" => enabled = Some(matches!(v.to_ascii_lowercase().as_str(), "false" | "off" | "no" | "0")),
                    other => return usage(format!("unknown `schedule edit` field `{other}` (cron, prompt, name, model, deliver, failure-deliver, repeat, skill, workdir, enabled|disabled, no-agent|agent, continuity)")),
                }
            }
            let mut j = seagent_kernel::cronjob::update(&paths.data, &st, &job.id, spec)?;
            if let Some(on) = enabled {
                if on != j.enabled {
                    j = seagent_kernel::cronjob::set_paused(&paths.data, &j.id, !on, (!on).then_some("disabled by `seagent schedule edit`"))?;
                }
            }
            println!("updated {} · {:<16} {}  next {}", j.id, j.cron, if j.enabled { "on " } else { "off" }, if j.enabled { seagent_kernel::util::fmt_time(j.next_run, cfg.schedule.utc_offset_minutes) } else { "-".into() });
            println!("  {} · {}", j.ext.display.clone().unwrap_or_else(|| j.cron.clone()), term::one_line(&j.prompt, 70));
            if let Some(s) = &j.ext.script {
                println!("  script: {s}{}", if j.ext.no_agent { " (no-agent: stdout is the result)" } else { "" });
            }
            Ok(0)
        }
        "rm" | "remove" => {
            let ok = automation::remove_job(&paths.data, a.need(1, "id")?)?;
            println!("{}", if ok { "removed" } else { "no such schedule" });
            Ok(if ok { 0 } else { 1 })
        }
        s @ ("enable" | "disable") => {
            let ok = automation::set_job_enabled(&paths.data, a.need(1, "id")?, s == "enable")?;
            println!("{}", if ok { format!("{s}d") } else { "no such schedule".into() });
            Ok(if ok { 0 } else { 1 })
        }
        "run" => {
            let id = a.need(1, "id")?;
            let job = automation::read_list::<Job>(&automation::jobs_path(&paths.data))?.into_iter().find(|j| j.id == id).ok_or("no such schedule")?;
            let c = build_agent(a, approver_for(a, true), false)?;
            let sid = automation::run_job(&c.k, &job)?;
            println!("ran in session {sid}");
            Ok(0)
        }
        // One pass of the scheduler loop: claim and run whatever is due right now.
        "tick" => {
            let c = build_agent(a, approver_for(a, true), false)?;
            let (seen, lines) = seagent_kernel::cronjob::tick(&c.k)?;
            if lines.is_empty() {
                println!("tick: nothing due ({seen} scheduled)");
            } else {
                println!("tick: ran {} of {seen} scheduled", lines.iter().filter(|l| !l.starts_with("    ")).count());
                for l in lines {
                    println!("{l}");
                }
            }
            Ok(0)
        }
        // Durable execution history of one job (`--limit N`, default 20).
        "runs" | "history" => {
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let job = seagent_kernel::cronjob::find(&paths.data, a.need(1, "id")?)?;
            let limit = a.num::<usize>("limit").map_err(Fail::Usage)?.unwrap_or(20).clamp(1, 500);
            let rows = incidents::history(&paths.data, &job.id, limit);
            if rows.is_empty() {
                println!("no runs recorded for {} yet", job.id);
                return Ok(0);
            }
            println!("{}  {} · {}", job.id, job.ext.name.clone().unwrap_or_default(), job.cron);
            for r in &rows {
                let dur = if r.duration_ms >= 1000 { format!("{:.1}s", r.duration_ms as f64 / 1000.0) } else { format!("{}ms", r.duration_ms) };
                let mut line = format!("{}  {:<9} {:>7}  {}", seagent_kernel::util::fmt_time(r.ended_at, cfg.schedule.utc_offset_minutes), r.status, dur, r.delivery.clone().unwrap_or_default());
                if let Some(e) = &r.error {
                    line.push_str(&format!("  error: {}", term::one_line(e, 100)));
                } else if let Some(s) = &r.summary {
                    if !s.trim().is_empty() {
                        line.push_str(&format!("  {}", term::one_line(s, 100)));
                    }
                }
                println!("{line}");
            }
            let h = incidents::health(&paths.data, &job.id);
            if h.consecutive_failures > 0 {
                println!("  ⚠ {} consecutive failure(s) since {}", h.consecutive_failures, h.last_error.clone().unwrap_or_default());
            }
            Ok(0)
        }
        // Durable failure incidents: list (`[state]`) or `ack <incident-id>`.
        "incidents" | "incident" => {
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let first = a.pos(1).unwrap_or("");
            if first == "ack" || first == "close" {
                let id = a.need(2, "incident id")?;
                let ok = incidents::ack(&paths.data, id, seagent_kernel::util::unix_now());
                println!("{}", if ok { format!("incident {id} closed") } else { format!("incident {id} not found or already closed") });
                return Ok(if ok { 0 } else { 1 });
            }
            let state = (!first.is_empty() && first != "list").then_some(first);
            if let Some(s) = state {
                if !incidents::INCIDENT_STATES.contains(&s) {
                    return usage(format!("unknown incident state `{s}` (detected, alerted, resolved, closed)"));
                }
            }
            let list = incidents::list(&paths.data, state);
            if list.is_empty() {
                println!("no cron failure incidents recorded{}", state.map(|s| format!(" (state {s})")).unwrap_or_default());
                return Ok(0);
            }
            for inc in &list {
                println!("{}  {:<9} job {}  {}  retries {}  {} → {}", inc.id, inc.state, inc.job_id, inc.failure_type, inc.retries, seagent_kernel::util::fmt_time(inc.opened_at, cfg.schedule.utc_offset_minutes), seagent_kernel::util::fmt_time(inc.last_seen_at, cfg.schedule.utc_offset_minutes));
                println!("    {}", term::one_line(&inc.error, 160));
                if inc.state != "closed" {
                    println!("    ack: seagent schedule incidents ack {}", inc.id);
                }
            }
            Ok(0)
        }
        // Per-job free-text notepad (`seagent schedule notepad <id> [text… | clear]`).
        "notepad" | "note" => {
            let job = seagent_kernel::cronjob::find(&paths.data, a.need(1, "id")?)?;
            let text = a.rest(2);
            if text.trim().is_empty() {
                match incidents::note(&paths.data, &job.id) {
                    Some(n) => println!("{n}"),
                    None => println!("(no notepad for {})", job.id),
                }
                return Ok(0);
            }
            if text.trim() == "clear" {
                let had = incidents::clear_note(&paths.data, &job.id)?;
                println!("{}", if had { "notepad cleared" } else { "notepad was empty" });
                return Ok(0);
            }
            incidents::set_note(&paths.data, &job.id, Some(&text))?;
            println!("notepad saved for {} ({} bytes) — injected into every run of this job", job.id, incidents::note(&paths.data, &job.id).map(|n| n.len()).unwrap_or(0));
            Ok(0)
        }
        // Read-only health checks with actionable advice (exit 1 when anything is off).
        "doctor" => {
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let jobs: Vec<Job> = automation::read_list(&automation::jobs_path(&paths.data)).unwrap_or_default();
            let alive = daemon::call(&paths.socket(), "ping", json!({})).is_ok();
            let findings = incidents::doctor(&paths.data, &jobs, seagent_kernel::util::unix_now(), cfg.schedule.utc_offset_minutes, alive);
            let stores = incidents::doctor_stores(&paths.data);
            let issues: usize = findings.iter().map(|f| f.2.len()).sum::<usize>() + stores.len();
            if issues == 0 {
                println!("✓ cron doctor found no issues ({} job(s), seagentd {})", jobs.len(), if alive { "running" } else { "not running" });
                return Ok(0);
            }
            println!("cron doctor found {issues} issue(s) across {} job(s):", findings.len());
            for (id, name, list) in &findings {
                println!("  {id}  {name}");
                for i in list {
                    println!("    - {i}");
                }
            }
            for (area, issue) in &stores {
                println!("  {area}: {issue}");
            }
            println!("\nfix what is actionable above, then run `seagent schedule doctor` again.");
            Ok(1)
        }
        other => usage(format!("unknown `schedule {other}`")),
    }
}

#[cfg(test)]
mod schedule_cli_tests {
    use super::*;

    /// A temp `SEAGENT_HOME` (the env is process-wide: hold the kit lock) plus the argv parser.
    struct Env {
        _guard: std::sync::MutexGuard<'static, ()>,
        old: Option<std::ffi::OsString>,
        pub root: PathBuf,
        pub ws: PathBuf,
    }
    impl Env {
        fn new() -> Env {
            let guard = crate::testkit::env_lock();
            let root = seagent_core::tmp::scratch_path(format!("seagent-sched-cli-{}", seagent_kernel::util::random_hex(8)));
            let ws = root.join("ws");
            std::fs::create_dir_all(&ws).unwrap();
            let old = std::env::var_os("SEAGENT_HOME");
            std::env::set_var("SEAGENT_HOME", &root);
            Env { _guard: guard, old, root, ws }
        }
        fn data(&self) -> PathBuf {
            self.root.join("data")
        }
        fn args(&self, v: &[&str]) -> Args {
            let mut argv: Vec<String> = vec!["--workspace".into(), self.ws.to_string_lossy().into()];
            argv.extend(v.iter().map(|s| s.to_string()));
            Args::parse(&argv).unwrap()
        }
        fn run(&self, v: &[&str]) -> Result<i32, Fail> {
            cmd_schedule(&self.args(v))
        }
    }
    impl Drop for Env {
        fn drop(&mut self) {
            match self.old.take() {
                Some(h) => std::env::set_var("SEAGENT_HOME", h),
                None => std::env::remove_var("SEAGENT_HOME"),
            }
        }
    }

    fn add(env: &Env, cron: &str, prompt: &str) -> Job {
        std::fs::create_dir_all(env.data()).unwrap();
        automation::add_job(&env.data(), cron, prompt, &env.ws, None, false, 0).unwrap()
    }

    #[test]
    fn schedule_cli_edit_runs_incidents_notepad_and_doctor() {
        let env = Env::new();
        let job = add(&env, "@hourly", "watch the queue");
        let store = || automation::read_list::<Job>(&automation::jobs_path(&env.data())).unwrap();

        // edit: only the named fields change; cron/name/deliver/prompt land in the store.
        assert_eq!(env.run(&["edit", &job.id, "cron=weekdays at 9am", "name=weekday digest", "deliver=local"]).unwrap(), 0);
        let j = &store()[0];
        assert_eq!((j.cron.as_str(), j.ext.name.as_deref(), j.ext.deliver.as_deref(), j.enabled), ("0 9 * * 1-5", Some("weekday digest"), Some("local"), true));
        assert_eq!(j.prompt, "watch the queue", "untouched fields survive");
        // Long-form cron expressions are accepted, and `enabled=` toggles the pause override.
        assert_eq!(env.run(&["edit", &job.id[..6], "enabled=false"]).unwrap(), 0);
        assert!(!store()[0].enabled);
        assert_eq!(env.run(&["edit", &job.id, "enabled=on", "prompt=watch\\nthe queue"]).unwrap(), 0);
        assert!(store()[0].enabled);
        assert_eq!(store()[0].prompt, "watch\nthe queue");
        assert_eq!(env.run(&["edit", &job.id, "repeat=3", "skill=triage,ops"]).unwrap(), 0);
        assert_eq!((store()[0].ext.repeat, store()[0].ext.skills.len()), (Some(3), 2));
        // A bad field / bare token is a usage error, and nothing is written.
        assert!(env.run(&["edit", &job.id, "frobnicate=1"]).is_err());
        assert!(env.run(&["edit", &job.id, "cron"]).is_err());
        assert!(env.run(&["edit", &job.id, "repeat=lots"]).is_err());
        assert!(env.run(&["edit", "no-such-job", "name=x"]).is_err());

        // runs + incidents: three recorded failures open one incident, `runs` prints history.
        for _ in 0..3 {
            seagent_kernel::cronjob::record(&env.data(), &job.id, "error", Some("provider down"), None);
        }
        assert_eq!(env.run(&["runs", &job.id, "--limit", "5"]).unwrap(), 0);
        assert_eq!(env.run(&["runs", &job.id]).unwrap(), 0, "our own runs show up");
        assert_eq!(env.run(&["incidents"]).unwrap(), 0);
        assert_eq!(env.run(&["incidents", "detected"]).unwrap(), 0);
        let inc = seagent_kernel::cronjob::incidents::list(&env.data(), None)[0].clone();
        assert_eq!((inc.state.as_str(), inc.retries), ("detected", 3));
        assert_eq!(env.run(&["incidents", "bogus-state"]).is_err() as u8, 1, "a bad state is a usage error");
        assert_eq!(env.run(&["incidents", "ack", &inc.id]).unwrap(), 0);
        assert_eq!(seagent_kernel::cronjob::incidents::list(&env.data(), None)[0].state, "closed");
        assert_eq!(env.run(&["incidents", "ack", "nope"]).unwrap(), 1, "unknown incident = non-zero exit");

        // notepad: read/write/clear round trip.
        assert_eq!(env.run(&["notepad", &job.id]).unwrap(), 0, "empty note prints, exit 0");
        assert_eq!(env.run(&["notepad", &job.id, "cursor: PR", "#41"]).unwrap(), 0);
        assert_eq!(seagent_kernel::cronjob::incidents::note(&env.data(), &job.id).as_deref(), Some("cursor: PR #41"));
        assert_eq!(env.run(&["notepad", &job.id, "clear"]).unwrap(), 0);
        assert!(seagent_kernel::cronjob::incidents::note(&env.data(), &job.id).is_none());

        // doctor: healthy → 0, a broken job → 1 with advice (never a crash).
        assert_eq!(env.run(&["doctor"]).unwrap(), 1, "the three failures are reported");
        seagent_kernel::cronjob::record(&env.data(), &job.id, "ok", Some("all clear"), None);
        assert_eq!(env.run(&["doctor"]).unwrap(), 0, "one success clears the streak");
        let mut broken = store()[0].clone();
        broken.id = "broken1".into();
        broken.cron = "not a cron".into();
        broken.next_run = seagent_kernel::util::unix_now() - 7200;
        automation::with_list(&automation::jobs_path(&env.data()), |v: &mut Vec<Job>| v.push(broken)).unwrap();
        assert_eq!(env.run(&["doctor"]).unwrap(), 1);
        // Existing commands keep their behaviour.
        assert_eq!(env.run(&["ls"]).unwrap(), 0);
        assert_eq!(env.run(&["disable", "broken1"]).unwrap(), 0);
        assert_eq!(env.run(&["enable", "broken1"]).unwrap(), 0);
        assert_eq!(env.run(&["rm", "broken1"]).unwrap(), 0);
        assert_eq!(env.run(&["rm", "broken1"]).unwrap(), 1, "removing twice reports no such schedule");
        assert!(env.run(&["frobnicate"]).is_err());
    }
}

fn cmd_goal(a: &Args) -> R {
    let paths = Paths::from_env();
    let goals = || automation::read_list::<Goal>(&automation::goals_path(&paths.data));
    let find = |id: &str| -> Result<Goal, Fail> {
        let m: Vec<Goal> = goals()?.into_iter().filter(|g| g.id == id || g.id.starts_with(id) || g.id.ends_with(id)).collect();
        match m.len() {
            1 => Ok(m[0].clone()),
            0 => Err(format!("no goal matches `{id}`").into()),
            _ => Err(format!("`{id}` is ambiguous").into()),
        }
    };
    match a.pos(0).unwrap_or("list") {
        "add" => {
            let objective = a.rest(1);
            let c = build(a, approver_for(a, false))?;
            let rounds = a.num::<u32>("rounds").map_err(Fail::Usage)?.unwrap_or(20);
            let budget = Budget { max_tokens: a.num("budget-tokens").map_err(Fail::Usage)?, max_cost_usd: a.num("budget-usd").map_err(Fail::Usage)?, ..Default::default() };
            let g = automation::add_goal(&c.k, &objective, &c.workspace, rounds, budget, a.val("model"))?;
            println!("goal {} (session {})", g.id, g.session);
            match daemon::call(&paths.socket(), "goal.start", json!({"id": g.id})) {
                Ok(_) => println!("running in seagentd · follow with `seagent attach {}`", g.session),
                Err(_) => println!("seagentd not running · run it now with `seagent goal run {}`", g.id),
            }
            Ok(0)
        }
        "list" | "ls" => {
            let gs = goals()?;
            if gs.is_empty() {
                println!("no goals");
            }
            for g in gs {
                println!("{}  {:<9} {:>3}/{:<3} {}  {}", g.id, format!("{:?}", g.status).to_lowercase(), g.rounds, g.max_rounds, term::one_line(&g.objective, 50), term::one_line(&g.summary, 60));
            }
            Ok(0)
        }
        "show" => {
            let g = find(a.need(1, "id")?)?;
            println!("{}", serde_json::to_string_pretty(&g).unwrap_or_default());
            Ok(0)
        }
        // Extra criteria (Hermes /subgoal): `seagent goal subgoal <id> [text | remove N | clear]`.
        "subgoal" => {
            let g = find(a.need(1, "id")?)?;
            println!("{}", seagent_kernel::cronjob::slash::apply_subgoal(&paths.data, &g, &a.rest(2)));
            Ok(0)
        }
        "run" => {
            let g = find(a.need(1, "id")?)?;
            if g.status == GoalStatus::Paused {
                automation::set_goal_status(&paths.data, &g.id, GoalStatus::Active)?;
            }
            let c = build_agent(a, approver_for(a, true), false)?;
            let rx = c.k.bus.subscribe();
            let (sid, json_out, quiet) = (g.session.clone(), a.flag("json"), a.flag("quiet"));
            std::thread::spawn(move || term::render(rx, sid, json_out, quiet));
            let done = automation::run_goal(&c.k, &g.id)?;
            println!("\ngoal {:?} after {} round(s): {}", done.status, done.rounds, done.summary);
            Ok(match done.status {
                GoalStatus::Done => 0,
                GoalStatus::Paused | GoalStatus::Active => 3,
                _ => 1,
            })
        }
        s @ ("pause" | "cancel" | "resume") => {
            let g = find(a.need(1, "id")?)?;
            let status = match s {
                "pause" => GoalStatus::Paused,
                "cancel" => GoalStatus::Cancelled,
                _ => GoalStatus::Active,
            };
            automation::set_goal_status(&paths.data, &g.id, status)?;
            if s != "resume" {
                let _ = daemon::call(&paths.socket(), "session.interrupt", json!({"id": g.session}));
            } else if daemon::call(&paths.socket(), "goal.start", json!({"id": g.id})).is_err() {
                println!("seagentd not running · continue with `seagent goal run {}`", g.id);
            }
            println!("goal {s}d");
            Ok(0)
        }
        other => usage(format!("unknown `goal {other}`")),
    }
}

// ───────────────────────── memory / checkpoints ─────────────────────────

const MEM_SEP: &str = "\n§\n";

fn cmd_memory(a: &Args) -> R {
    let paths = Paths::from_env();
    let dir = paths.data.join("memory");
    let staging = dir.join("staging");
    let staged = || -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(&staging).map(|r| r.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect()).unwrap_or_default();
        v.sort();
        v
    };
    match a.pos(0).unwrap_or("show") {
        "show" => {
            for f in ["USER.md", "MEMORY.md"] {
                let s = std::fs::read_to_string(dir.join(f)).unwrap_or_default();
                println!("── {f} ──\n{}\n", if s.trim().is_empty() { "(empty)" } else { s.trim() });
            }
            Ok(0)
        }
        "add" => {
            let text = a.rest(1);
            if text.trim().is_empty() {
                return usage("missing <text>");
            }
            append_memory(&dir, if a.flag("user") { "USER.md" } else { "MEMORY.md" }, &text)?;
            println!("saved");
            Ok(0)
        }
        "review" => {
            let files = staged();
            if files.is_empty() {
                println!("no staged suggestions");
            }
            for (i, f) in files.iter().enumerate() {
                let v: Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap_or_default()).unwrap_or(Value::Null);
                println!("[{}] from session {}", i + 1, v["session"].as_str().unwrap_or("?"));
                for k in ["memory", "user"] {
                    for e in v[k].as_array().cloned().unwrap_or_default() {
                        println!("    {k}: {}", e.as_str().unwrap_or(""));
                    }
                }
            }
            Ok(0)
        }
        s @ ("accept" | "reject") => {
            let which = a.need(1, "n|all")?;
            let files = staged();
            let pick: Vec<PathBuf> = if which == "all" {
                files
            } else {
                let n: usize = which.parse().map_err(|_| Fail::Usage(format!("`{which}` is not a number")))?;
                vec![files.get(n.wrapping_sub(1)).cloned().ok_or("no such suggestion")?]
            };
            for f in &pick {
                if s == "accept" {
                    let v: Value = serde_json::from_str(&std::fs::read_to_string(f).map_err(|e| e.to_string())?).map_err(|e| format!("{}: {e}", f.display()))?;
                    for (k, file) in [("memory", "MEMORY.md"), ("user", "USER.md")] {
                        for e in v[k].as_array().cloned().unwrap_or_default() {
                            if let Some(t) = e.as_str() {
                                append_memory(&dir, file, t)?;
                            }
                        }
                    }
                }
                std::fs::remove_file(f).map_err(|e| e.to_string())?;
            }
            println!("{s}ed {}", pick.len());
            Ok(0)
        }
        other => usage(format!("unknown `memory {other}`")),
    }
}

fn append_memory(dir: &Path, file: &str, text: &str) -> Result<(), Fail> {
    let p = dir.join(file);
    let cur = std::fs::read_to_string(&p).unwrap_or_default();
    if cur.split(MEM_SEP).any(|e| e.trim() == text.trim()) {
        return Ok(());
    }
    let new = if cur.trim().is_empty() { text.trim().to_string() } else { format!("{}{MEM_SEP}{}", cur.trim_end(), text.trim()) };
    seagent_kernel::util::atomic_write(&p, new.as_bytes()).map_err(|e| Fail::Msg(e.to_string()))
}

fn cmd_checkpoint(a: &Args) -> R {
    if let Some(sub @ ("status" | "prune" | "clear")) = a.pos(0) {
        return export::cmd_checkpoint_store(a, sub);
    }
    let paths = Paths::from_env();
    let ws = workspace(a)?;
    let cp = Checkpoints::new(&paths.data, &ws)?;
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            let l = cp.list(a.num::<usize>("limit").map_err(Fail::Usage)?.unwrap_or(20))?;
            if l.is_empty() {
                println!("no checkpoints for {}", ws.display());
            }
            for c in l {
                println!("{}  {}  {}", c.id, c.time, c.label);
            }
            Ok(0)
        }
        "restore" => {
            let id = a.need(1, "id")?;
            let saved = cp.restore(id)?;
            println!("restored {id}{}", saved.map(|s| format!(" · previous state saved as {s}")).unwrap_or_default());
            Ok(0)
        }
        other => usage(format!("unknown `checkpoint {other}`")),
    }
}

// ───────────────────────── config / secrets / providers ─────────────────────────

fn cmd_config(a: &Args) -> R {
    let paths = Paths::from_env();
    match a.pos(0).unwrap_or("show") {
        "path" => {
            ops::confcli::print_paths(&paths, &project_config(&workspace(a)?), a.flag("json"));
            Ok(0)
        }
        "show" | "dump" => {
            let ws = workspace(a)?;
            print!("{}", load_config(a, &ws, &paths)?.dump());
            Ok(0)
        }
        "validate" => {
            let ws = workspace(a)?;
            load_config(a, &ws, &paths)?;
            println!("config ok");
            Ok(0)
        }
        "get" => {
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let mut v: toml::Value = toml::Value::try_from(&cfg).map_err(|e| e.to_string())?;
            for part in a.need(1, "key")?.split('.') {
                v = v.get(part).cloned().ok_or_else(|| format!("no key `{part}`"))?;
            }
            match v {
                toml::Value::String(s) => println!("{s}"),
                other => println!("{other}"),
            }
            Ok(0)
        }
        "init" => {
            let p = paths.user_config();
            if p.exists() {
                return Err(format!("{} already exists", p.display()).into());
            }
            std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
            std::fs::write(&p, SAMPLE).map_err(|e| e.to_string())?;
            println!("wrote {}", p.display());
            Ok(0)
        }
        other => usage(format!("unknown `config {other}`")),
    }
}

fn cmd_secrets(a: &Args) -> R {
    let paths = Paths::from_env();
    std::fs::create_dir_all(&paths.config_dir).map_err(|e| e.to_string())?;
    let sub = a.pos(0).unwrap_or("list");
    // `backend` must work when the store cannot be unlocked — that is exactly when the
    // operator runs it — so it reads the header instead of opening the vault.
    if matches!(sub, "backend" | "store") {
        return secrets_backend(&paths);
    }
    // Likewise `migrate` must not open (and thereby auto-migrate) the vault first: it is the
    // command that reports what the migration did.
    if matches!(sub, "migrate" | "encrypt") {
        let opts = seagent_kernel::secretstore::Options::from_env();
        let (n, backend, notes) = seagent_kernel::secretstore::migrate(&paths.secrets(), &opts)?;
        for note in &notes {
            println!("note     {note}");
        }
        println!("{n} secret{} now in {} ({})", if n == 1 { "" } else { "s" }, seagent_kernel::secretstore::store_path(&paths.secrets()).display(), backend.as_str());
        return Ok(0);
    }
    let v = load_vault(&paths)?;
    match sub {
        "list" | "ls" => {
            let n = v.names();
            if n.is_empty() {
                println!("no secrets");
            }
            for name in n {
                println!("{name}");
            }
            Ok(0)
        }
        "set" => {
            let name = a.need(1, "NAME")?;
            if a.pos(2).is_some() {
                return usage("pass the value on stdin, not as an argument (it would end up in shell history)");
            }
            if std::io::stdin().is_terminal() {
                eprint!("value for {name} (input hidden is not supported; paste then Enter): ");
            }
            let mut val = String::new();
            std::io::stdin().read_line(&mut val).map_err(|e| e.to_string())?;
            let val = val.trim_end_matches(['\n', '\r']);
            if val.is_empty() {
                return Err("empty value".into());
            }
            v.set(name, val)?;
            println!("stored {name} · reference it as {{{{secret:{name}}}}}");
            Ok(0)
        }
        "rm" | "remove" => {
            let name = a.need(1, "NAME")?;
            println!("{}", if v.remove(name)? { "removed" } else { "no such secret" });
            Ok(0)
        }
        // A4: where the secrets actually live, and how they are protected at rest.
        "status" => {
            let st = v.status();
            println!("file     {}", st.path.display());
            println!("backend  {} — {}", st.backend.as_str(), st.backend.explain());
            println!("secrets  {}", st.secrets);
            if st.legacy_present {
                println!("note     a plaintext secrets.toml is still present; `seagent secrets migrate` folds it in and removes it");
            }
            for n in &st.notes {
                println!("note     {n}");
            }
            Ok(0)
        }
        // A4: one-way, verified migration of the old 0600 plaintext file (handled above).
        "migrate" | "encrypt" => Ok(0),
        other => usage(format!("unknown `secrets {other}`")),
    }
}

/// `seagent secrets backend` — the key source, the file, and what to do about it. Deliberately
/// independent of `load_vault`: a store whose key is missing is exactly when this runs.
fn secrets_backend(paths: &Paths) -> R {
    let opts = seagent_kernel::secretstore::Options::from_env();
    let st = seagent_kernel::secretstore::status(&paths.secrets(), &opts);
    println!("file     {}", st.path.display());
    println!("backend  {} — {}", st.backend.as_str(), st.backend.explain());
    println!("secrets  {}", st.secrets);
    if st.legacy_present {
        println!("note     a plaintext secrets.toml is still present; `seagent secrets migrate` folds it in and removes it");
    }
    for n in &st.notes {
        println!("note     {n}");
    }
    if !st.backend.encrypted() {
        println!("fix      install libsecret-tools (keyring), enable a TPM, or set SEAGENT_VAULT_PASSPHRASE_FILE, then run `seagent secrets migrate`");
    }
    println!("hint     SEAGENT_VAULT_BACKEND=keyring|tpm|passphrase|env forces the source for a new store");
    Ok(0)
}

fn cmd_providers(a: &Args) -> R {
    let paths = Paths::from_env();
    let ws = workspace(a)?;
    let cfg = load_config(a, &ws, &paths)?;
    let vault = load_vault(&paths)?;
    let p = Providers::new(&cfg.providers, vault)?;
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            for (id, c) in p.configs() {
                let key = match p.key_source(id) {
                    Ok(s) => format!("key: {s}"),
                    Err(_) => format!("key: missing ({})", c.key_env_names().first().map(String::as_str).unwrap_or("login")),
                };
                println!("{id:<12} {:<17} {:<52} {key}", format!("{:?}", c.format), c.base_url);
            }
            Ok(0)
        }
        "check" => {
            let model = a.pos(1).map(String::from).unwrap_or(cfg.model.default.clone());
            let (pid, m) = seagent_kernel::context::split_model(&model);
            let prov = p.provider(pid)?;
            let req = seagent_core::ModelRequest { model: m.into(), system: vec![], messages: vec![seagent_core::Message::user("Reply with exactly: pong")], tools: vec![], max_tokens: 2048, temperature: None, cache_after_message: None, reasoning: None, options: Default::default() };
            let t0 = Instant::now();
            match prov.complete(&req, &mut |_| {}, &seagent_core::Cancel::new().with_deadline(Instant::now() + Duration::from_secs(60))) {
                Ok(r) => {
                    println!("{model}: ok in {:.1}s · reply {:?} · {} tokens", t0.elapsed().as_secs_f32(), term::one_line(&r.message.text(), 40), r.usage.total());
                    Ok(0)
                }
                Err(e) => Err(format!("{model}: {e}").into()),
            }
        }
        other => usage(format!("unknown `providers {other}`")),
    }
}

fn cmd_doctor(a: &Args) -> R {
    let paths = Paths::from_env();
    let mut bad = 0;
    let mut check = |name: &str, r: Result<String, String>| match r {
        Ok(s) => println!("✓ {name}: {s}"),
        Err(e) => {
            bad += 1;
            println!("✗ {name}: {e}")
        }
    };
    let ws = workspace(a)?;
    let cfg = load_config(a, &ws, &paths);
    check("config", cfg.as_ref().map(|_| "valid".into()).map_err(|e| match e {
        Fail::Msg(m) | Fail::Usage(m) => m.clone(),
    }));
    let vault = Vault::load(&paths.secrets());
    check("secrets", vault.as_ref().map(|v| {
        let st = v.status();
        let plain = if st.backend.encrypted() { "" } else { ", PLAINTEXT (run `seagent secrets migrate`)" };
        format!("{} stored, {} at rest{}", v.names().len(), st.backend.as_str(), plain)
    }).map_err(|e| e.clone()));
    if let (Ok(cfg), Ok(v)) = (&cfg, vault) {
        if let Ok(p) = Providers::new(&cfg.providers, Arc::new(v)) {
            let mut models = vec![cfg.model.default.clone()];
            models.extend(cfg.model.fallback.clone());
            models.push(cfg.aux_model().to_string());
            models.dedup();
            for m in models {
                let pid = seagent_kernel::context::split_model(&m).0;
                check(&format!("model {m}"), p.key_source(pid).map(|s| format!("key from {s}")));
            }
            // ent-086: which teams have their own model keys (`<KEY_ENV>__<TEAM>`).
            let mut teams: Vec<String> = seagent_kernel::agents::users(&paths).into_iter().map(|u| u.team).filter(|t| !t.is_empty()).collect();
            teams.sort();
            teams.dedup();
            if !teams.is_empty() {
                let own = p.team_keys(&teams);
                println!("· team model keys: {}", teams.iter().map(|t| { let ps: Vec<&str> = own.iter().filter(|(x, _)| x == t).map(|(_, id)| id.as_str()).collect(); format!("{t}={}", if ps.is_empty() { "shared".to_string() } else { ps.join("+") }) }).collect::<Vec<_>>().join(", "));
            }
        }
    }
    let tool = |bin: &str| std::process::Command::new(bin).arg("--version").output().map(|o| String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").to_string()).map_err(|e| e.to_string());
    check("bash", tool("bash"));
    #[cfg(not(target_os = "linux"))] // shell, control endpoint, autostart, VM providers of this OS
    ops::service_os::doctor_checks(&paths).into_iter().for_each(|(n, r)| check(&n, r));
    check("git (checkpoints)", tool("git"));
    check("python3 (code mode)", tool("python3"));
    // The bundled skills / roles / catalogs: a binary copied without its share/ has none of them.
    check("bundled share/", seagent_core::share::share_dir().filter(|d| d.join("skills").is_dir() && d.join("plugin-catalog").is_dir()).map(|d| d.display().to_string()).ok_or_else(|| "not found (bundled skills and catalogs are unavailable): install with install.sh / the release tarball, or set SEAGENT_SHARE_DIR".to_string()));
    check("data dir", std::fs::create_dir_all(&paths.data).map(|_| paths.data.display().to_string()).map_err(|e| e.to_string()));
    // gen2-508 (H6): the base prompt and the shipped skills still match this build's pins.
    check("prompt & bundled skills", seagent_skills::integrity::doctor_line());
    // gen2-413: too many questions train people to click Allow — say so before it happens.
    if let Ok(c) = &cfg {
        check("approval load", seagent_security::approvals::fatigue_check(&paths.data, c.approvals.fatigue_daily_asks));
    }
    // Browser readiness (OpenClaw `extensions/browser` doctor-browser): optional, so a
    // missing browser is a note rather than a failed check.
    if let Ok(c) = &cfg {
        match seagent_browser::BrowserConfig::parse(&c.browser) {
            Ok(b) => match seagent_browser::control::doctor_check(&b) {
                Ok(s) => println!("✓ browser: {s}"),
                Err(e) => println!("· browser: {e}"),
            },
            Err(e) => println!("· browser: {e}"),
        }
        match seagent_app::computer::ComputerUseConfig::parse(&c.computer_use) {
            Ok(cc) if cc.enabled() == Some(true) => println!("✓ computer_use: enabled ({})", seagent_app::computer::driver_kind(&cc, &paths.data)),
            Ok(_) => println!("· computer_use: off (set [computer_use] enabled = true, or `seagent computer-use status`)"),
            Err(e) => println!("· computer_use: {e}"),
        }
    }
    // ent-085: keys past their rotation schedule (`seagent secrets rotation`).
    check("key rotation", ops::rotate::doctor_line(&paths));
    // ent-036/037/039: the outbound network policy every HTTP/TLS client is built with.
    for (k, v) in seagent_net::http::describe() {
        if k == "ca" && v.contains("falling back") {
            check("network ca", Err(v));
        } else {
            println!("· network {k}: {v}");
        }
    }
    let sock = paths.socket();
    check("socket path length", if sock.as_os_str().len() < 100 { Ok(format!("{} bytes", sock.as_os_str().len())) } else { Err("too long for a unix socket; set XDG_RUNTIME_DIR".into()) });
    match daemon::call(&sock, "ping", json!({})) {
        Ok(r) => println!("✓ seagentd: running (pid {})", r["pid"]),
        Err(_) => println!("· seagentd: not running (needed for schedules, goals in background, send/attach)"),
    }
    Ok(if bad == 0 { 0 } else { 1 })
}

fn cmd_call(a: &Args) -> R {
    let tool = a.need(0, "tool")?;
    let input = a.rest(1);
    match seagent_kernel::coderun::client(tool, &input) {
        Ok(out) => {
            println!("{out}");
            Ok(0)
        }
        Err(e) => {
            eprintln!("{e}");
            Ok(1)
        }
    }
}


// ───────────────────────── mcp / plugins / channels ─────────────────────────

fn valid_ext_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 40 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn toml_str(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn cmd_plugin(a: &Args) -> R {
    let c = build_agent(a, approver_for(a, false), false)?;
    let e = c.ext.as_ref().unwrap();
    if e.plugins.is_empty() {
        println!("no plugin processes configured ([plugins.<name>] command = …)");
    }
    // Built-ins, installed packages and process plugins: the lifecycle inventory.
    println!("{}", seagent_skills::hub::plugins::inventory_text(&c.k.cfg, &c.paths));
    for p in &e.plugins {
        let tools = c.k.tools.iter().filter(|t| t.spec().name.starts_with(&format!("mcp__{}__", p.name))).count();
        let list = |v: Vec<String>| if v.is_empty() { "-".to_string() } else { v.join(",") };
        println!(
            "{:<16} {tools} tools · hooks: {} · channels: {} · commands: {} · routes: {} · providers: {} · services: {}",
            p.name,
            list(p.hooks().to_vec()),
            list(p.channels().to_vec()),
            list(p.commands.iter().map(|c| format!("/{}", c.name)).collect()),
            list(p.routes.iter().map(|r| format!("/plugins/{}{}", p.name, if r.path.is_empty() { "/" } else { &r.path })).collect()),
            list(p.providers.iter().map(|x| x.id.clone()).collect()),
            list(p.services.iter().map(|x| x.name.clone()).collect()),
        );
        let mut extra = vec![];
        if !p.cli.is_empty() {
            extra.push(format!("cli: {}", list(p.cli.iter().map(|c| format!("seagent {}", c.name)).collect())));
        }
        if !p.middleware_kinds().is_empty() {
            extra.push(format!("middleware: {}", list(p.middleware_kinds().to_vec())));
        }
        if let Some(e) = &p.context_engine {
            extra.push(format!("context engine{}", if e.owns_compaction { " (owns compaction)" } else { "" }));
        }
        if p.memory {
            extra.push("memory provider".into());
        }
        if !p.node_commands.is_empty() {
            extra.push(format!("node commands: {}", list(p.node_commands.iter().map(|c| c.command.clone()).collect())));
        }
        if !p.ui.is_empty() {
            extra.push(format!("ui: {}", list(p.ui.iter().map(|u| format!("/plugins/{}/ui/{}", p.name, u.id)).collect())));
        }
        if !extra.is_empty() {
            println!("{:<16} {}", "", extra.join(" · "));
        }
    }
    Ok(0)
}

/// Data-subject requests (個資法 §3/§11): export or delete everything seagent holds about one
/// channel user — their sessions, routing, pairing approval and downloaded attachments.
fn cmd_data(a: &Args) -> R {
    let paths = Paths::from_env();
    let action = a.pos(0).unwrap_or("");
    let channel = a.need(1, "channel")?;
    let who = a.need(2, "sender or chat id")?;
    let dir = paths.data.join("channels");
    let router = seagent_channel::Router::open(dir.join("routes.json"), Default::default());
    let routes = ext::forget_routes(&router, channel, &[who]);
    let store = seagent_kernel::store::Store::new(paths.data.join("sessions"));
    let pairing = seagent_channel::access::Pairing::open(dir.join("pairing.json"));
    match action {
        "export" => {
            let mut sessions = Vec::new();
            for r in &routes {
                let events = store.read(&r.session).map(|e| serde_json::to_value(e).unwrap_or_default()).unwrap_or(Value::Null);
                sessions.push(json!({"chat": r.key.chat, "sender": r.key.sender, "session": r.session, "events": events}));
            }
            let approved: Vec<Value> = pairing.approved().into_iter().filter(|(c, s, _)| c == channel && s == who).map(|(_, _, ap)| json!(ap)).collect();
            let doc = json!({"channel": channel, "subject": who, "exported_at": now_secs(), "sessions": sessions, "pairing": approved,
                "note": "Long-term memory (seagent memory) is shared across sessions and is not split per person; review it with `seagent memory show`."});
            println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
            Ok(0)
        }
        "delete" => {
            if !a.flag("yes") {
                return Err(format!("this permanently deletes {} session(s) for {who} on {channel}; re-run with --yes", routes.len()).into());
            }
            let (n, files, revoked) = ext::forget(&store, &router, Some(&pairing), channel, &[who]);
            println!("deleted {n} session(s), {files} attachment(s){} for {who} on {channel}", if revoked { ", revoked pairing" } else { "" });
            println!("note: shared long-term memory is not split per person; check `seagent memory show` for anything about them.");
            Ok(0)
        }
        _ => Err("usage: seagent data export <channel> <sender|chat>  |  seagent data delete <channel> <sender|chat> --yes".into()),
    }
}

/// Dynamic webhook routes (Hermes `webhook subscribe`); the listener hot-reloads the file.
fn cmd_webhook(a: &Args, argv: &[String]) -> R {
    use seagent_channel::webhook;
    let paths = Paths::from_env();
    // `seagent webhook gmail …` (OpenClaw `src/cli/webhooks-cli.ts`): the helpers take their own
    // flags, so they read the raw argv instead of the parsed positionals.
    if a.pos(0) == Some("gmail") {
        let cfg = load_config(a, &workspace(a)?, &paths)?;
        let vault = load_vault(&paths)?;
        return gmail_hook::cli(&argv[1..], &paths, &cfg, &|s: &str| vault.substitute(s)).map_err(Fail::Msg);
    }
    let channel = a.need(1, "channel")?;
    let file = webhook::subscriptions_path(&paths.data.join("channels"), channel);
    match a.pos(0).unwrap_or("") {
        "list" | "ls" => {
            let subs = webhook::list_subscriptions(&file)?;
            for (name, r) in &subs {
                let target = r["cron_job"].as_str().map(|j| format!("cron job {j}")).unwrap_or_else(|| r["deliver"].as_str().unwrap_or("reply").to_string());
                println!("{name}  {}  → {target}{}", r["path"].as_str().map(String::from).unwrap_or(format!("/webhooks/{name}")), if r["enabled"] == json!(false) { "  (disabled)" } else { "" });
            }
            if subs.is_empty() {
                println!("no subscriptions on {channel}");
            }
            Ok(0)
        }
        "subscribe" | "add" => {
            let name = a.need(2, "route")?;
            let route: Value = match a.pos(3) {
                Some(j) => serde_json::from_str(j).map_err(|e| format!("route json: {e}"))?,
                None => json!({}),
            };
            let r = webhook::subscribe(&file, name, route)?;
            println!("subscribed {name} on {channel}: POST {}", r["path"].as_str().map(String::from).unwrap_or(format!("/webhooks/{name}")));
            println!("secret: {}", r["secret"].as_str().unwrap_or(""));
            Ok(0)
        }
        "rm" | "remove" => {
            let name = a.need(2, "route")?;
            Ok(if webhook::unsubscribe(&file, name)? { 0 } else { 1 })
        }
        "test" => {
            let name = a.need(2, "route")?;
            let cfg = load_config(a, &workspace(a)?, &paths)?;
            let vault = load_vault(&paths)?;
            let (url, secret) = hooks_cli::route_target(&cfg, &paths, channel, name, &|s: &str| vault.substitute(s))?;
            let payload = a.val("payload").unwrap_or(hooks_cli::DEFAULT_TEST_PAYLOAD);
            serde_json::from_str::<Value>(payload).map_err(|e| format!("--payload is not JSON: {e}"))?;
            println!("Sending test POST to {url}");
            let (status, body) = hooks_cli::webhook_test(&url, &secret, payload)?;
            println!("Response ({status}): {body}");
            Ok(if (200..300).contains(&status) { 0 } else { 1 })
        }
        _ => usage(format!("usage: seagent webhook list <channel> | subscribe <channel> <route> [json] | rm <channel> <route> | test <channel> <route> [--payload JSON]\n       {}", gmail_hook::CLI_USAGE)),
    }
}

/// Full-screen terminal UI on the daemon (same protocol as the web UI).
fn cmd_tui(a: &Args) -> R {
    let paths = Paths::from_env();
    let ws = workspace(a)?;
    seagent_app::tui::run(&paths.socket(), &ws, a.flag("yolo"))?;
    Ok(0)
}

/// ACP agent on stdio for editors (Zed, JetBrains, Neovim…): `"command": "seagent", "args": ["acp"]`.
fn cmd_acp(a: &Args) -> R {
    let slot: Arc<std::sync::OnceLock<Arc<seagent_app::acp::Peer>>> = Arc::default();
    let approver = Arc::new(seagent_app::acp::AcpApprover(slot.clone()));
    let c = build_agent(a, approver, false)?;
    let mut commands: Vec<(String, String)> = c.ext.as_ref().map(|e| e.commands.iter().map(|c| (c.name.clone(), c.description.clone())).collect()).unwrap_or_default();
    commands.extend([("new".to_string(), "開新對話".to_string()), ("compact".into(), "壓縮對話脈絡".into())]);
    let acp = seagent_app::acp_client::AcpConfig::parse(&c.k.cfg.acp).map_err(Fail::Msg)?;
    let stdin = std::io::stdin();
    seagent_app::acp::serve(c.k.clone(), commands, acp, slot, stdin.lock(), Box::new(std::io::stdout()));
    Ok(0)
}

/// Drive an external ACP agent (acpx-style): `seagent acp-client claude "fix the tests"`.
fn cmd_acp_client(a: &Args) -> R {
    use seagent_app::acp_client::{describe_update, render_turn, AcpClient, AcpConfig, PermissionMode};
    let paths = Paths::from_env();
    let ws = workspace(a)?;
    let cfg = load_config(a, &ws, &paths)?;
    let acp = AcpConfig::parse(&cfg.acp).map_err(Fail::Msg)?;
    if a.flag("list") {
        for n in acp.names() {
            let s = acp.agent(&n).map_err(Fail::Msg)?;
            println!("{n:<12} {}  {}", seagent_app::acp_client::command_line(&s), s.description.unwrap_or_default());
        }
        return Ok(0);
    }
    let name = a.need(0, "agent")?;
    let spec = acp.agent(name).map_err(Fail::Msg)?;
    let prompt = read_prompt(a, 1)?;
    let cwd = match a.val("cwd") {
        Some(d) => PathBuf::from(d).canonicalize().map_err(|e| Fail::Msg(format!("--cwd {d}: {e}")))?,
        None => ws.clone(),
    };
    let mode = match a.val("permission-mode") {
        Some(m) => PermissionMode::parse(m).map_err(Fail::Usage)?,
        None if a.flag("yes") => PermissionMode::ApproveAll,
        None => acp.mode_for(&spec),
    };
    let tty = term::TtyApprover::available().then(|| Arc::new(term::TtyApprover::new()));
    let ask: seagent_app::acp_client::Asker = Arc::new(move |q: &str| match &tty {
        Some(t) => t.ask("", &format!("{q} [y/N]")).is_ok_and(|x| seagent_app::acp_client::is_yes(&x)),
        None => false,
    });
    let vault = load_vault(&paths)?;
    let secrets = ext::secrets_fn(&vault);
    let mut c = AcpClient::start(name, &spec, &cwd, mode, ask, Some((cfg.gate.clone(), vault)), &*secrets).map_err(Fail::Msg)?;
    c.open_session(a.val("session")).map_err(Fail::Msg)?;
    let json_out = a.flag("json");
    let quiet = a.flag("quiet");
    if !json_out {
        c.set_progress(Some(Arc::new(move |u: &Value| {
            if u["sessionUpdate"] == "agent_message_chunk" {
                print!("{}", u["content"]["text"].as_str().unwrap_or(""));
                let _ = std::io::stdout().flush();
            } else if let Some(l) = describe_update(u).filter(|_| !quiet) {
                eprintln!("{l}");
            }
        })));
    }
    // Ctrl-C → session/cancel (a second one quits).
    ops::hostos::catch_sigint();
    let cancel = seagent_core::Cancel::new();
    let c2 = cancel.clone();
    std::thread::spawn(move || loop {
        if SIGINTS.load(Ordering::SeqCst) > 0 {
            eprintln!("\n• cancelling… (Ctrl-C again to force quit)");
            c2.cancel();
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    });
    let timeout = Duration::from_secs(a.num::<u64>("timeout").map_err(Fail::Usage)?.or(acp.timeout_secs).unwrap_or(1800));
    let t = c.prompt(&prompt, &cancel, timeout).map_err(Fail::Msg)?;
    if json_out {
        println!("{}", json!({"agent": name, "sessionId": c.session_id, "stopReason": t.stop_reason, "text": t.text, "toolCalls": t.tools.iter().map(|x| json!({"id": x.0, "title": x.1, "kind": x.2, "status": x.3})).collect::<Vec<_>>(), "plan": t.plan, "permissions": t.permissions}));
    } else {
        println!();
        if !quiet {
            eprintln!("{}", render_turn(&c, &t, "done").lines().next().unwrap_or(""));
        }
    }
    c.close();
    Ok(if t.stop_reason == "cancelled" { 130 } else { 0 })
}

/// Run this machine as a node of an seagent app server.
fn cmd_node(a: &Args) -> R {
    let paths = Paths::from_env();
    // A setup code (from `seagent nodes setup-code`) carries the URL, a one-time bootstrap token and
    // optionally the server's certificate fingerprint.
    let (url, bootstrap, tls_fingerprint) = match a.val("setup-code") {
        Some(code) => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
            let sc = seagent_app::node::SetupCode::decode(code, now)?;
            (sc.url, Some(sc.bootstrap_token), sc.tls_fingerprint)
        }
        None => (a.val("url").ok_or("--url ws://host:8640/node (or --setup-code CODE) is required")?.to_string(), None, None),
    };
    let host = ops::hostos::etc_hostname().unwrap_or_else(|_| std::env::consts::OS.into()).trim().to_string();
    let id = a.val("session").map(str::to_string).unwrap_or_else(|| format!("{}-{host}", std::env::consts::OS));
    let policy_path = paths.config_dir.join("node.toml");
    let policy: seagent_app::node::HostPolicy = match std::fs::read_to_string(&policy_path) {
        Ok(t) => toml::from_str(&t).map_err(|e| format!("{}: {e}", policy_path.display()))?,
        Err(_) => seagent_app::node::HostPolicy { run: "deny".into(), read_roots: vec![workspace(a)?], ..Default::default() },
    };
    eprintln!("seagent node: {id} → {url} (system.run: {}, policy file {})", if policy.run.is_empty() { "deny" } else { &policy.run }, policy_path.display());
    let token_path = paths.data.join("node.token");
    let mut backoff = 1u64;
    loop {
        // The bootstrap token is single use: once a device token exists it is not sent again.
        let conn = seagent_app::node::HostConn { url: url.clone(), id: id.clone(), name: a.val("name").unwrap_or(&host).to_string(), key_path: paths.data.join("node.key"), token_path: token_path.clone(), bootstrap: bootstrap.clone(), tls_fingerprint: tls_fingerprint.clone() };
        match seagent_app::node::run_host(&conn, &policy) {
            Ok(()) => return Ok(0),
            Err(e) => {
                eprintln!("seagent node: {e}; retry in {backoff}s");
                std::thread::sleep(Duration::from_secs(backoff));
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

/// Manage devices connected to the app server (through the daemon).
fn cmd_nodes(a: &Args) -> R {
    let sock = Paths::from_env().socket();
    let r = match a.pos(0).unwrap_or("list") {
        "list" | "ls" => daemon::call(&sock, "node.list", json!({}))?,
        "pending" => daemon::call(&sock, "node.pair.list", json!({}))?,
        "approve" => daemon::call(&sock, "node.pair.approve", json!({"code": a.need(1, "code")?}))?,
        "reject" => daemon::call(&sock, "node.pair.reject", json!({"code": a.need(1, "code")?}))?,
        "remove" | "rm" => daemon::call(&sock, "node.remove", json!({"id": a.need(1, "id")?}))?,
        "describe" | "show" => daemon::call(&sock, "node.describe", json!({"id": a.need(1, "id")?}))?,
        "rename" => daemon::call(&sock, "node.rename", json!({"id": a.need(1, "id")?, "name": a.rest(2)}))?,
        "invoke" => {
            let params = match a.rest(3) {
                r if r.trim().is_empty() => json!({}),
                r => serde_json::from_str::<Value>(&r).map_err(|e| format!("params must be JSON: {e}"))?,
            };
            daemon::call(&sock, "node.invoke", json!({"id": a.need(1, "node")?, "command": a.need(2, "command")?, "params": params, "queue": a.flag("queue")}))?
        }
        "queue" => daemon::call(&sock, "node.queue", json!({"id": a.pos(1).unwrap_or("")}))?,
        "events" => daemon::call(&sock, "node.events", json!({"id": a.pos(1).unwrap_or("")}))?,
        "rotate" | "rotate-token" => daemon::call(&sock, "node.token.rotate", json!({"id": a.need(1, "id")?}))?,
        "wake" | "enqueue" => daemon::call(&sock, "node.pending.enqueue", json!({"nodeId": a.need(1, "id")?, "type": a.pos(2).unwrap_or("status.request")}))?,
        "setup-code" => {
            let ws = workspace(a)?;
            let paths = Paths::from_env();
            let cfg = load_config(a, &ws, &paths)?;
            let app = seagent_app::AppConfig::parse(&cfg.app)?;
            if !app.nodes {
                eprintln!("seagent: warning: [app] nodes = false; the app server will not accept nodes until you enable it");
            }
            // Off loopback the URL is wss:// with LAN mode's certificate pinned (never cleartext).
            let (url, fp) = match a.val("url") {
                Some(u) => (u.to_string(), None),
                None => ops::controlcmds::pairing_url(&cfg, &paths.data)?,
            };
            let ttl = a.num::<u64>("ttl").map_err(Fail::Usage)?.unwrap_or(10) * 60_000;
            let mut p = json!({"url": url, "ttlMs": ttl});
            if let Some(f) = a.val("tls-fingerprint").map(String::from).or(fp) {
                p["tlsFingerprint"] = json!(f);
            }
            let r = daemon::call(&sock, "node.setup.create", p)?;
            let code = r["code"].as_str().unwrap_or("");
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
                return Ok(0);
            }
            match seagent_app::qr::Qr::encode(code.as_bytes()) {
                Some(q) => println!("{}", q.render(2)),
                None => eprintln!("(code is too long for a terminal QR code; copy it instead)"),
            }
            println!("setup code (valid {} min, single use) for {}:\n{code}\n\non the device: seagent node --setup-code {code}", ttl / 60_000, r["url"].as_str().unwrap_or(""));
            return Ok(0);
        }
        other => return Err(format!("unknown nodes subcommand `{other}` (list, pending, approve <code>, reject <code>, remove <id>, describe <id>, rename <id> <name>, invoke <node> <command> [json] [--queue], queue [id], events [id], rotate <id>, wake <id> [status.request|location.request], setup-code [--url ws://…] [--ttl MIN] [--tls-fingerprint SHA256])").into()),
    };
    println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
    Ok(0)
}

/// DM pairing: approve the one-time codes unknown senders receive under `dm_policy = "pairing"`.
fn cmd_pairing(a: &Args) -> R {
    let paths = Paths::from_env();
    let p = seagent_channel::access::Pairing::open(paths.data.join("channels").join("pairing.json"));
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            let pending = p.pending();
            if pending.is_empty() {
                println!("no pending pairing requests");
            }
            for r in pending {
                println!("pending  {:<14} {} ({})  {}s ago", r.channel, r.sender, r.sender_name, now_secs() - r.created);
            }
            for (c, s, ap) in p.approved() {
                println!("approved {c:<14} {s} ({})", ap.sender_name);
            }
            Ok(0)
        }
        "approve" => {
            let (ch, code) = (a.need(1, "channel")?, a.need(2, "code")?);
            let (s, n) = p.approve(ch, code).map_err(|e| e.to_string())?;
            println!("approved {s} ({n}) on {ch}");
            Ok(0)
        }
        "revoke" | "rm" => {
            let (ch, sender) = (a.need(1, "channel")?, a.need(2, "sender")?);
            if p.revoke(ch, sender) {
                println!("revoked {sender} on {ch}");
                Ok(0)
            } else {
                Err(format!("{sender} is not approved on {ch}").into())
            }
        }
        other => Err(format!("unknown pairing subcommand `{other}` (list, approve <channel> <code>, revoke <channel> <sender>)").into()),
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `seagent channel list`: one line per configured channel — name, kind, DM policy and who may talk
/// to it (an empty allow list means nobody, which is the safe default after `seagent setup`).
pub fn channel_lines(e: &ext::Ext) -> Vec<String> {
    e.channels
        .iter()
        .map(|(n, (_, cfg))| {
            let kind = serde_json::to_value(cfg).ok().and_then(|v| v["kind"].as_str().map(String::from)).unwrap_or_default();
            let r = cfg.router();
            let allow = &r.policy.allow;
            format!("{n:<16} {kind:<14} dm: {:?} · allow: {}", r.policy.dm_policy, if allow.is_empty() { "(nobody — set allow)".to_string() } else { allow.join(",") })
        })
        .collect()
}

fn cmd_channel(a: &Args) -> R {
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            let c = build_agent(a, approver_for(a, false), false)?;
            let e = c.ext.as_ref().unwrap();
            if e.channels.is_empty() {
                println!("no channels (configure [channels.<name>] kind = \"telegram\", \"discord\", \"slack\", \"line\"… — see docs/config-example.toml)");
            }
            for line in channel_lines(e) {
                println!("{line}");
            }
            Ok(0)
        }
        "send" => {
            let name = a.need(1, "channel")?;
            let chat = a.need(2, "chat")?;
            let text = a.rest(3);
            if text.trim().is_empty() {
                return usage("missing <text>");
            }
            let c = build_agent(a, approver_for(a, false), false)?;
            let (ch, _) = c.ext.as_ref().unwrap().channels.get(name).ok_or_else(|| format!("no channel `{name}`"))?;
            ch.send(&seagent_channel::Outbound { chat: chat.into(), text, reply_to: None, ..Default::default() }).map_err(|e| e.message)?;
            println!("sent");
            Ok(0)
        }
        other => usage(format!("unknown `channel {other}`")),
    }
}

#[cfg(test)]
mod wiring_tests {
    use super::*;

    /// Serializes the one test that rewrites `SEAGENT_HOME` (the env is process-wide).
    use crate::testkit::ENV;

    /// `build_agent` must hand the agent every media tool the audit lists as "wired", and the
    /// media host must have installed the model/session callbacks seagent-media calls back into.
    #[test]
    fn build_agent_registers_the_media_surface() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let root = seagent_core::tmp::scratch_path(format!("seagent-wire-{}-{}", std::process::id(), seagent_kernel::util::random_hex(4)));
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let old = std::env::var_os("SEAGENT_HOME");
        std::env::set_var("SEAGENT_HOME", &root);
        let argv = vec!["--workspace".to_string(), ws.to_string_lossy().to_string()];
        let a = Args::parse(&argv).unwrap();
        let c = build_agent(&a, approver_for(&a, false), false).expect("build_agent");
        if let Some(h) = old {
            std::env::set_var("SEAGENT_HOME", h);
        }
        let specs = c.k.specs();
        let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
        for n in [
            "vision_analyze", "view_image", "pdf", "image_generate", "video_generate", "music_generate", "video_analyze", "text_to_speech", "talk_voice", "transcripts",
            "voice_call", "google_meet", "teams_meetings", "zoom_meetings", "slack_huddles",
        ] {
            assert!(names.contains(&n), "media tool `{n}` is not registered (have {names:?})");
        }
        assert!(seagent_media::llm().is_some(), "the media LLM callback (set_llm) is installed");
        assert!(seagent_media::agent().is_some(), "the media agent callback (set_agent) is installed");
    }

    /// `/tts` and `/voice` are real slash commands backed by seagent-media's command surface.
    #[test]
    fn tts_and_voice_slash_commands_are_registered() {
        let kit = crate::testkit::kit();
        let c = slash::Ctx { k: &kit.k, ext: None, session: None, workspace: kit.ws.clone(), surface: slash::Surface::Cli, sender: None, notify: None };
        let tts = slash::run(&c, "/tts status").expect("/tts is registered");
        let text = tts.text.unwrap_or_default();
        assert!(text.contains("TTS status"), "{text}");
        let voice = slash::run(&c, "/voice status").expect("/voice is registered");
        let text = voice.text.unwrap_or_default();
        assert!(text.to_lowercase().contains("voice"), "{text}");
        // Both are listed for the web UI / TUI command palette.
        let names: Vec<&str> = slash::DEFS.iter().map(|d| d.name).collect();
        assert!(names.contains(&"tts") && names.contains(&"voice") && names.contains(&"browser"), "{names:?}");
    }

    /// `/tts chat on|off` and `/voice tts on|off` scope their override to the chat the
    /// command came from (`sender.channel` + `sender.chat`, Hermes `_voice_mode`).
    #[test]
    fn tts_chat_commands_use_the_channel_chat() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let kit = crate::testkit::kit();
        let sender = slash::Sender { channel: "slack".into(), chat: "C9".into(), sender: "u1".into(), group: true, admin: true, gated: false, user_commands: vec![] };
        let c = slash::Ctx { k: &kit.k, ext: None, session: None, workspace: kit.ws.clone(), surface: slash::Surface::Channel, sender: Some(sender), notify: None };
        let on = slash::run(&c, "/tts chat on").expect("/tts chat").text.unwrap_or_default();
        assert!(on.contains("enabled for this chat (slack:C9)"), "{on}");
        let m = media_host::media(&kit.k.cfg, kit.k.vault.clone());
        assert_eq!(seagent_media::tts::chat_auto(&m, "slack:C9").as_deref(), Some("all"));
        let st = slash::run(&c, "/tts chat status").expect("/tts chat status").text.unwrap_or_default();
        assert!(st.contains("slack:C9") && st.contains("spoken"), "{st}");
        let off = slash::run(&c, "/voice tts off").expect("/voice tts off").text.unwrap_or_default();
        assert!(off.contains("Applies to this chat (slack:C9)"), "{off}");
        assert_eq!(seagent_media::tts::chat_auto(&m, "slack:C9").as_deref(), Some("off"));
        // The CLI/TUI surface has no chat: it only speaks about the profile.
        let cli = slash::Ctx { k: &kit.k, ext: None, session: None, workspace: kit.ws.clone(), surface: slash::Surface::Cli, sender: None, notify: None };
        let p = slash::run(&cli, "/tts chat on").expect("/tts chat").text.unwrap_or_default();
        assert!(p.contains("need a chat surface"), "{p}");
    }

    /// The image hook seagent-core calls after a tool attached pictures is seagent-media's sanitizer.
    #[test]
    fn image_post_hook_is_installed() {
        let _g = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let kit = crate::testkit::kit();
        let m = media_host::media(&kit.k.cfg, kit.k.vault.clone());
        media_host::install(&kit.k, &m);
        assert!(seagent_core::tool::image_post_installed(), "install() must hand seagent-core the sanitizer");
        // A 1x1 PNG is small enough to survive sanitization untouched.
        let png = seagent_net::crypto::b64_decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==").unwrap();
        let mut blocks = vec![Block::Image { media_type: "image/png".into(), data: seagent_net::crypto::b64(&png) }];
        seagent_core::tool::post_process_images(&mut blocks);
        assert_eq!(blocks.len(), 1);
        assert!(matches!(blocks[0], Block::Image { .. }), "a small valid PNG stays an image: {:?}", blocks[0]);
    }
    /// `/statusbar` in `seagent chat`: off until switched on, then one plain line per turn with
    /// model, context gauge, tokens and the git branch (shared with the TUI through `ui.json`).
    #[test]
    fn chat_status_bar_follows_the_statusbar_pref() {
        let t = crate::testkit::kit();
        let id = t.k.create_session(&t.ws, None, None, Some("bar")).unwrap();
        t.k.submit(&id, "hello", "cli").unwrap();
        t.k.run(&id, RunOpts::default()).unwrap();
        let rt = Ctx { k: t.k.clone(), paths: t.paths.clone(), ext: None, workspace: t.ws.clone() };
        assert!(chat_status_bar(&rt, &id).is_none(), "no bar until /statusbar on");
        seagent_app::tui::prefs::set(&t.paths, "statusbar", serde_json::json!("top")).unwrap();
        let bar = chat_status_bar(&rt, &id).expect("the bar is on");
        assert!(bar.starts_with("[m]") && bar.contains("tok") && bar.contains('%'), "{bar}");
        seagent_app::tui::prefs::set(&t.paths, "statusbar", serde_json::json!("off")).unwrap();
        assert!(chat_status_bar(&rt, &id).is_none(), "off hides it again");
    }
}

#[cfg(test)]
mod ops_cli_tests {
    use super::*;

    /// `seagent channel list`: name, kind, DM policy and the allow list (empty = nobody).
    #[test]
    fn channel_lines_show_kind_policy_and_allowlist() {
        let _g = crate::testkit::env_lock();
        let t = crate::testkit::kit();
        let root = t.paths.config_dir.parent().unwrap().to_path_buf();
        std::env::set_var("SEAGENT_HOME", &root);
        // The CLI reads the config from disk, so write it (and the referenced secrets) there.
        std::fs::write(
            t.paths.user_config(),
            "[channels.tg]\nkind = \"telegram\"\ntoken = \"{{secret:TELEGRAM_TOKEN}}\"\ndm_policy = \"pairing\"\n\n[channels.ops]\nkind = \"slack\"\nbot_token = \"{{secret:SLACK_BOT_TOKEN}}\"\napp_token = \"{{secret:SLACK_APP_TOKEN}}\"\nallow = [\"U1\", \"U2\"]\n",
        )
        .unwrap();
        let v = seagent_kernel::vault::Vault::load(&t.paths.secrets()).unwrap();
        v.set("TELEGRAM_TOKEN", "1:abc").unwrap();
        v.set("SLACK_BOT_TOKEN", "xoxb-abc").unwrap();
        v.set("SLACK_APP_TOKEN", "xapp-abc").unwrap();
        let a = Args::parse(&["--workspace".into(), t.ws.display().to_string()]).unwrap();
        let c = build_agent(&a, approver_for(&a, false), false).unwrap();
        let lines = channel_lines(c.ext.as_ref().unwrap());
        let tg = lines.iter().find(|l| l.starts_with("tg")).expect("telegram listed");
        assert!(tg.contains("telegram") && tg.contains("Pairing") && tg.contains("nobody"), "{tg}");
        let ops = lines.iter().find(|l| l.starts_with("ops")).expect("slack listed");
        assert!(ops.contains("slack") && ops.contains("U1,U2"), "{ops}");
        // Nothing configured: no lines (the command prints its own hint).
        let empty = crate::testkit::kit();
        std::env::set_var("SEAGENT_HOME", empty.paths.config_dir.parent().unwrap());
        let a = Args::parse(&["--workspace".into(), empty.ws.display().to_string()]).unwrap();
        let c = build_agent(&a, approver_for(&a, false), false).unwrap();
        assert!(channel_lines(c.ext.as_ref().unwrap()).is_empty());
        std::env::remove_var("SEAGENT_HOME");
    }

    /// `seagent attach`: streamed text, lifecycle/gate/approval lines, `--json` passthrough.
    #[test]
    fn attach_render_streams_text_and_hints() {
        let delta = json!({"jsonrpc":"2.0","method":"delta","params":{"session":"s","text":"hel"}});
        assert_eq!(attach_render(&delta, false), Attach::Text("hel".into()));
        let think = json!({"method":"delta","params":{"text":"hmm","thinking":true}});
        assert_eq!(attach_render(&think, false), Attach::Skip, "thinking is not the reply");
        let end = json!({"method":"event","params":{"session":"s","event":{"type":"turn_end","reason":"end_turn"}}});
        assert_eq!(attach_render(&end, false), Attach::Line("\n• turn ended: end_turn".into()));
        let note = json!({"method":"event","params":{"event":{"type":"notice","text":"compacted"}}});
        assert_eq!(attach_render(&note, false), Attach::Line("• compacted".into()));
        let gate = json!({"method":"event","params":{"event":{"type":"gate","gate":"privilege","verdict":"ask","reason":"rm -rf"}}});
        assert_eq!(attach_render(&gate, false), Attach::Line("⚑ privilege gate: ask — rm -rf".into()));
        let pend = json!({"method":"pending","params":{"id":"p1","reason":"run shell?"}});
        assert_eq!(attach_render(&pend, false), Attach::Line("⚑ waiting for approval: run shell?  →  seagent gate answer p1 once|always|deny".into()));
        assert_eq!(attach_render(&json!({"method":"ready","params":{}}), false), Attach::Skip);
        // `--json` prints every message verbatim, including deltas.
        assert_eq!(attach_render(&delta, true), Attach::Json(delta.clone()));
    }
}
