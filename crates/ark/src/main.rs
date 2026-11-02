mod args;
mod ext;
mod providers;
mod setup;
mod term;

use args::Args;
use ark_core::{Block, Role};
use ark_kernel::approver::{Approver, Policy};
use ark_kernel::automation::{self, Goal, GoalStatus, Job};
use ark_kernel::checkpoint::Checkpoints;
use ark_kernel::config::{project_config, Config, Paths, SAMPLE};
use ark_kernel::daemon::{self, Daemon};
use ark_kernel::event::EventKind;
use ark_kernel::kernel::{new_kernel, EndReason, Kernel, Resolver, RunOpts};
use ark_kernel::ledger::Budget;
use ark_kernel::projection::project;
use ark_kernel::vault::Vault;
use providers::Providers;
use serde_json::{json, Value};
use std::io::{BufRead, IsTerminal, Read, Write};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HELP: &str = "ark — autonomous agent kernel

USAGE
  ark setup                            first-run wizard: provider, key, model, web UI, chat platform
  ark run [opts] <prompt…|->           run one task to completion (reads stdin with -)
  ark chat [opts]                      line-based conversation (/help inside)
  ark session list|show|resume|fork|search|export|compact|model|rm …
  ark daemon start|stop|status|run|install
  ark send <session> <text…>           queue input on a daemon-hosted session (starts it)
  ark attach <session> [--from N]      follow a daemon-hosted session live
  ark interrupt <session>              stop a running session
  ark gate list | answer <id> <once|always|deny>
  ark schedule add <cron> <prompt…> [--reuse] | list | rm|enable|disable|run <id>
  ark goal add <objective…> [--rounds N] | list | show|run|pause|resume|cancel <id>
  ark memory show | add <text…> [--user] | review | accept <n|all> | reject <n|all>
  ark checkpoint list | restore <id>
  ark config path|show|init|get <key>|validate
  ark secrets set <NAME> | list | rm <NAME>   (value read from stdin, never argv)
  ark providers list | check [provider/model]
  ark mcp list | tools [server] | test <server> | refresh <server> | add <name> (--url U | -- cmd args…) | rm <name> | serve [--relay URL [--pair]]
  ark plugin list                      plugins and what they provide (tools, hooks, channels,
                                       commands, CLI, routes, UI, providers, services…)
  ark <plugin-command> [args…]         a CLI command a plugin adds (listed by `ark help`)
  ark channel list | send <channel> <chat> <text…>
  ark webhook list <channel> | subscribe <channel> <route> [json] | rm <channel> <route>
  ark acp                              ACP agent on stdio (for Zed, JetBrains, Neovim…)
  ark acp-client <agent> <prompt…|->   drive an external ACP agent (claude, codex, gemini, opencode…)
                                       [--cwd DIR] [--permission-mode approve-all|approve-reads|deny-all]
                                       [--session ID] [--list] [--json]
  ark commands                         custom /commands, plugin commands and MCP prompts
  ark node --url ws://host:8640/node | --setup-code CODE   run this machine as a device node
  ark nodes list|pending|approve|reject|remove|rename|describe|invoke|queue|events|rotate|setup-code
  ark data export|delete <channel> <sender|chat>
  ark call <tool> [json]               call a tool from inside the `run` tool (alias: ark-call)
  ark doctor | version | help

OPTIONS
  -m, --model provider/model   -w, --workspace DIR      -s, --session ID
  --set key=value (repeatable) --budget-tokens N        --budget-usd X
  --max-steps N                --yes (approve gate prompts)
  --allow-privilege            --allow-egress           --json   -q, --quiet

EXIT CODES  0 done · 1 error · 2 usage · 3 budget/limits/stuck · 130 interrupted";

fn main() {
    let raw: Vec<String> = std::env::args().collect();
    let argv0 = raw.first().map(|s| Path::new(s).file_name().and_then(|f| f.to_str()).unwrap_or("").to_string()).unwrap_or_default();
    let rest: Vec<String> = if argv0 == "ark-call" { std::iter::once("call".to_string()).chain(raw.into_iter().skip(1)).collect() } else { raw.into_iter().skip(1).collect() };
    let code = match dispatch(rest) {
        Ok(c) => c,
        Err(Fail::Usage(e)) => {
            eprintln!("ark: {e}\nRun `ark help` for usage.");
            2
        }
        Err(Fail::Msg(e)) => {
            eprintln!("ark: {e}");
            1
        }
    };
    std::process::exit(code);
}

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
    "help", "--help", "-h", "version", "--version", "-V", "setup", "onboard", "call", "run", "chat", "session", "sessions", "daemon", "send", "attach", "interrupt", "gate", "gates", "schedule", "cron", "goal", "goals", "memory",
    "checkpoint", "checkpoints", "undo", "config", "secrets", "secret", "providers", "models", "doctor", "mcp", "connector", "connectors", "plugin", "plugins", "channel", "channels", "pairing", "pair", "tui",
    "acp", "acp-client", "node", "nodes", "app", "data", "service", "health", "commands", "command", "webhook", "webhooks",
];

fn dispatch(raw: Vec<String>) -> R {
    let Some(cmd) = raw.first().cloned() else {
        print_help();
        if !Paths::from_env().user_config().exists() {
            println!("\n{}", setup::t("第一次使用？執行 `ark setup`，一步步設定模型、金鑰與聊天平台。", "First time? Run `ark setup` to configure a model, key and chat platform step by step."));
        }
        return Ok(0);
    };
    let a = match Args::parse(&raw[1..]) {
        Ok(a) => a,
        // Plugin CLI commands take their own flags.
        Err(_) if !BUILTINS.contains(&cmd.as_str()) => return cmd_plugin_cli(&cmd, &raw[1..]),
        Err(e) => return usage(e),
    };
    if a.flag("help") && BUILTINS.contains(&cmd.as_str()) {
        print_help();
        return Ok(0);
    }
    match cmd.as_str() {
        "help" | "--help" | "-h" => {
            print_help();
            Ok(0)
        }
        "version" | "--version" | "-V" => {
            println!("ark {} (log v{}, protocol v{})", env!("CARGO_PKG_VERSION"), ark_kernel::event::LOG_VERSION, daemon::PROTOCOL_VERSION);
            Ok(0)
        }
        "setup" | "onboard" => Ok(setup::run(&Paths::from_env())?),
        "call" => cmd_call(&a),
        "run" => cmd_run(&a),
        "chat" => cmd_chat(&a),
        "session" | "sessions" => cmd_session(&a),
        "daemon" => cmd_daemon(&a),
        "send" => {
            let id = a.need(0, "session")?;
            let text = a.rest(1);
            if text.trim().is_empty() {
                return usage("missing <text>");
            }
            let r = daemon::call(&Paths::from_env().socket(), "session.submit", json!({"id": id, "text": text}))?;
            println!("{}", if r["started"].as_bool() == Some(true) { "queued; session started" } else { "queued; session already running (steering)" });
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
        "providers" | "models" => cmd_providers(&a),
        "doctor" => cmd_doctor(&a),
        "mcp" | "connector" | "connectors" => cmd_mcp(&a),
        "plugin" | "plugins" => cmd_plugin(&a),
        "channel" | "channels" => cmd_channel(&a),
        "pairing" | "pair" => cmd_pairing(&a),
        "webhook" | "webhooks" => cmd_webhook(&a),
        "tui" => cmd_tui(&a),
        "acp" => cmd_acp(&a),
        "acp-client" => cmd_acp_client(&a),
        "node" => cmd_node(&a),
        "nodes" => cmd_nodes(&a),
        "app" => cmd_app(&a),
        "data" => cmd_data(&a),
        "service" => cmd_service(&a),
        "health" => {
            // For container health checks and monitors: is the daemon answering?
            match daemon::call(&Paths::from_env().socket(), "ping", json!({})) {
                Ok(_) => Ok(0),
                Err(e) => Err(e.into()),
            }
        }
        "commands" | "command" => {
            let c = build_agent(&a, approver_for(&a, false), false)?;
            let defs = &c.ext.as_ref().unwrap().commands;
            if defs.is_empty() {
                println!("no commands (add Markdown files to .ark/commands/ or ~/.claude/commands/)");
            }
            for d in defs {
                println!("/{:<20} {}  ({})", d.name, d.description, d.path.display());
            }
            for (n, d) in c.ext.as_ref().unwrap().plugin_commands() {
                println!("/{n:<20} {d}  (plugin)");
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
    println!("{HELP}");
    let paths = Paths::from_env();
    let Ok(ws) = std::env::current_dir() else { return };
    let (Ok(cfg), Ok(vault)) = (Config::load(Some(&paths.user_config()), Some(&project_config(&ws)), &[]), load_vault(&paths)) else { return };
    if cfg.plugins.is_empty() {
        return;
    }
    let (plugins, _) = ext::start_plugins(&cfg, &vault);
    let cmds: Vec<String> = plugins.iter().flat_map(|p| p.cli.iter().filter(|c| !BUILTINS.contains(&c.name.as_str())).map(move |c| format!("  ark {:<32} {} ({})", format!("{} {}", c.name, c.args).trim_end(), c.description, p.name))).collect();
    if !cmds.is_empty() {
        println!("\nPLUGIN COMMANDS\n{}", cmds.join("\n"));
    }
}

/// `ark <name> …` served by a plugin's `cli` declaration (OpenClaw `registerCli`).
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
            eprintln!("ark: warning: {w}");
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
    Config::load(Some(&paths.user_config()), Some(&project_config(ws)), &sets).map_err(Fail::Msg)
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
    let resolver: Arc<dyn Resolver> = Arc::new(Providers::new(&cfg.providers, vault.clone())?);
    let tools = ark_tools::builtin_tools();
    let k = new_kernel(cfg, paths.clone(), resolver, tools, vault, approver);
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
    for p in &ext.plugins {
        for (id, imp) in p.provider_impls() {
            providers.register(&id, imp);
        }
    }
    if !a.flag("quiet") {
        for w in &ext.warnings {
            eprintln!("ark: warning: {w}");
        }
    }
    let ins = ext::instructions(&ext);
    if !ins.is_empty() {
        cfg.identity = if cfg.identity.is_empty() { ins } else { format!("{}\n{ins}", cfg.identity) };
    }
    let disabled = cfg.tools.disabled.clone();
    let mut tools = ark_tools::builtin_tools();
    tools.extend(extra);
    match ark_app::AppConfig::parse(&cfg.app) {
        Ok(app) => {
            if app.nodes {
                tools.push(Arc::new(ark_app::node::NodeInvoke));
            }
            tools.extend(ark_app::a2a::tools(&app.a2a));
        }
        Err(e) => eprintln!("ark: warning: {e}"),
    }
    match ark_app::acp_client::AcpConfig::parse(&cfg.acp) {
        Ok(acp) => tools.push(Arc::new(ark_app::acp_client::AcpDelegate { cfg: acp, gate: cfg.gate.clone(), vault: vault.clone() })),
        Err(e) => eprintln!("ark: warning: {e}"),
    }
    let (engine, memory) = ext::selected(&cfg, &ext).unwrap_or_else(|e| {
        eprintln!("ark: warning: {e}; using ark's own");
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
    let k = new_kernel(cfg, paths.clone(), resolver, tools, vault, approver);
    k.add_hooks(hooks);
    if let Some(e) = engine {
        k.set_context_engine(e);
    }
    let _ = ext.kernel.set(k.clone());
    Ok(Ctx { k, paths, workspace: ws, ext: Some(ext) })
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
        EndReason::Refusal | EndReason::Error(_) => 1,
    }
}

static SIGINTS: AtomicU32 = AtomicU32::new(0);
extern "C" fn on_sigint(_: libc::c_int) {
    if SIGINTS.fetch_add(1, Ordering::SeqCst) >= 1 {
        // Second Ctrl-C: give up immediately. The log is append-only and fsynced,
        // so the next run recovers.
        unsafe { libc::_exit(130) };
    }
}

/// Run a session in the foreground with live output and Ctrl-C → interrupt.
fn run_foreground(c: &Ctx, id: &str, a: &Args, opts: RunOpts) -> R {
    let rx = c.k.bus.subscribe();
    let (sid, json, quiet) = (id.to_string(), a.flag("json"), a.flag("quiet"));
    let printer = std::thread::spawn(move || term::render(rx, sid, json, quiet));
    SIGINTS.store(0, Ordering::SeqCst);
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
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
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_DFL);
    }
    close_printer(&c.k, printer);
    let o = r.map_err(|e| Fail::Msg(e.to_string()))?;
    if !a.flag("quiet") && !a.flag("json") {
        // The error itself was already printed from the event stream.
        let label = if let EndReason::Error(e) = &o.reason { setup_hint(e).map(|h| format!("failed — {h}")).unwrap_or_else(|| "failed".into()) } else { term::one_line(&o.reason.label(), 120) };
        eprintln!("• {label} · {} tokens · {:.1}s · session {id}", o.usage.total(), started.elapsed().as_secs_f32());
    }
    if a.flag("json") {
        println!("{}", json!({"session": id, "reason": o.reason.label(), "text": o.text, "usage": o.usage}));
    }
    Ok(exit_code(&o.reason))
}

/// Stop a printer thread (it exits on the close sentinel) after flushing.
fn close_printer(k: &Kernel, h: std::thread::JoinHandle<()>) {
    k.bus.publish(ark_kernel::kernel::BusMsg::Delta { session: term::CLOSE.into(), text: String::new(), thinking: false });
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
    c.k.submit(&id, &prompt, "cli").map_err(|e| e.to_string())?;
    run_foreground(&c, &id, a, RunOpts::default())
}

fn cmd_chat(a: &Args) -> R {
    let c = build_agent(a, approver_for(a, true), false)?;
    let mut id = match a.val("session") {
        Some(s) => find_session(&c.k, s)?,
        None => c.k.create_session(&c.workspace, None, None, Some("chat")).map_err(|e| e.to_string())?,
    };
    eprintln!("ark chat · session {id} · model {} · /help for commands, /exit to quit", c.k.cfg.model.default);
    let stdin = std::io::stdin();
    loop {
        eprint!("\n› ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            break;
        }
        let line = line.trim_end_matches(['\n', '\r']).to_string();
        if line.trim().is_empty() {
            continue;
        }
        if let Some(cmd) = line.strip_prefix('/') {
            let (name, arg) = cmd.split_once(' ').map(|(a, b)| (a, b.trim())).unwrap_or((cmd, ""));
            match name {
                "exit" | "quit" | "q" => break,
                "help" => eprintln!("/model provider/model · /compact · /status · /undo [id] · /new · /commands · /<custom or plugin command> · /exit"),
                "model" if !arg.is_empty() => match c.k.set_model(&id, arg) {
                    Ok(()) => eprintln!("• model → {arg}"),
                    Err(e) => eprintln!("error: {e}"),
                },
                "compact" => match c.k.compact(&id) {
                    Ok(true) => eprintln!("• compacted"),
                    Ok(false) => eprintln!("• nothing to compact"),
                    Err(e) => eprintln!("error: {e}"),
                },
                "status" => {
                    let v = project(&c.k.store.read(&id).map_err(|e| e.to_string())?);
                    eprintln!("session {id} · model {} · {} messages · {} turns · {} tokens · {} compactions", v.model, v.messages.len(), v.turns, v.usage.total(), v.compactions);
                }
                "undo" => match Checkpoints::new(&c.paths.data, &c.workspace) {
                    Ok(cp) => {
                        let target = if arg.is_empty() { cp.list(2).ok().and_then(|l| l.first().map(|c| c.id.clone())) } else { Some(arg.to_string()) };
                        match target.map(|t| cp.restore(&t)) {
                            Some(Ok(_)) => eprintln!("• workspace restored (the previous state was saved; /undo again to flip back)"),
                            Some(Err(e)) => eprintln!("error: {e}"),
                            None => eprintln!("no checkpoints"),
                        }
                    }
                    Err(e) => eprintln!("error: {e}"),
                },
                "new" => {
                    c.k.end_session(&id, "new");
                    id = c.k.create_session(&c.workspace, None, None, Some("chat")).map_err(|e| e.to_string())?;
                    eprintln!("• new session {id}");
                }
                "commands" => {
                    for d in c.ext.iter().flat_map(|e| e.commands.iter()) {
                        eprintln!("/{} — {}", d.name, d.description);
                    }
                    for (n, d) in c.ext.iter().flat_map(|e| e.plugin_commands()) {
                        eprintln!("/{n} — {d}");
                    }
                }
                _ if c.ext.as_ref().is_some_and(|e| e.plugin_command(name).is_some()) => match c.ext.as_ref().and_then(|e| e.run_command(&line, json!({"surface": "chat", "session": id}))) {
                    Some(Ok(r)) => {
                        if let Some(t) = &r.text {
                            eprintln!("{t}");
                        }
                        if let Some(p) = r.prompt {
                            c.k.submit(&id, &p, "cli").map_err(|e| e.to_string())?;
                            let _ = run_foreground(&c, &id, a, RunOpts::default())?;
                        }
                    }
                    Some(Err(e)) => eprintln!("error: {e}"),
                    None => {}
                },
                _ => match expand_prompt(&c, &line) {
                    Ok(t) if t != line => {
                        c.k.submit(&id, &t, "cli").map_err(|e| e.to_string())?;
                        let _ = run_foreground(&c, &id, a, RunOpts::default())?;
                    }
                    Ok(_) => eprintln!("unknown command /{name} (try /help or /commands)"),
                    Err(e) => eprintln!("error: {e}"),
                },
            }
            continue;
        }
        c.k.submit(&id, &line, "cli").map_err(|e| e.to_string())?;
        let _ = run_foreground(&c, &id, a, RunOpts::default())?;
    }
    c.k.end_session(&id, "exit");
    eprintln!("bye · resume with `ark chat -s {id}`");
    Ok(0)
}

// ───────────────────────── sessions ─────────────────────────

fn fmt_ms(ms: u64) -> String {
    ark_kernel::util::fmt_time((ms / 1000) as i64, 480)
}

fn cmd_session(a: &Args) -> R {
    let sub = a.pos(0).unwrap_or("list");
    match sub {
        "list" | "ls" => {
            let c = build(a, approver_for(a, false))?;
            let lim = a.num::<usize>("limit").map_err(Fail::Usage)?.unwrap_or(20);
            let list: Vec<_> = c.k.store.list().into_iter().filter(|s| a.flag("all") || s.parent.is_none()).take(lim).collect();
            if a.flag("json") {
                println!("{}", json!(list.iter().map(|s| json!({"id":s.id,"title":s.title,"model":s.model,"workspace":s.workspace,"updated":fmt_ms(s.updated_ms),"messages":s.messages})).collect::<Vec<_>>()));
                return Ok(0);
            }
            if list.is_empty() {
                println!("no sessions");
            }
            for s in list {
                println!("{}  {}  {:>4} msgs  {:<28} {}", s.id, fmt_ms(s.updated_ms), s.messages, term::one_line(&s.model, 28), term::one_line(s.title.as_deref().unwrap_or(""), 50));
            }
            Ok(0)
        }
        "show" | "cat" => {
            let c = build(a, approver_for(a, false))?;
            let id = find_session(&c.k, a.need(1, "session")?)?;
            let events = c.k.store.read(&id).map_err(|e| e.to_string())?;
            if a.flag("json") {
                for e in &events {
                    println!("{}", serde_json::to_string(e).unwrap_or_default());
                }
                return Ok(0);
            }
            let v = project(&events);
            println!("session {id}\nworkspace {}\nmodel {} · {} turns · {} tokens · {} compactions\n", v.workspace, v.model, v.turns, v.usage.total(), v.compactions);
            for m in &v.messages {
                for b in &m.content {
                    match (m.role, b) {
                        (Role::User, Block::Text { text }) => println!("› {text}\n"),
                        (Role::Assistant, Block::Text { text }) if !text.is_empty() => println!("{text}\n"),
                        (_, Block::ToolUse { name, input, .. }) => println!("  → {name} {}", term::one_line(&input.to_string(), 120)),
                        (_, Block::ToolResult { content, is_error, .. }) => println!("  {} {}", if *is_error { "✗" } else { "✓" }, term::one_line(content, 120)),
                        _ => {}
                    }
                }
            }
            Ok(0)
        }
        "resume" | "continue" => {
            let c = build_agent(a, approver_for(a, true), false)?;
            let id = find_session(&c.k, a.pos(1).unwrap_or("last"))?;
            let prompt = a.rest(2);
            if !prompt.trim().is_empty() {
                c.k.submit(&id, &prompt, "cli").map_err(|e| e.to_string())?;
            }
            let code = run_foreground(&c, &id, a, RunOpts::default())?;
            Ok(code)
        }
        "fork" => {
            let c = build(a, approver_for(a, false))?;
            let src = find_session(&c.k, a.need(1, "session")?)?;
            let v = project(&c.k.store.read(&src).map_err(|e| e.to_string())?);
            let new = c.k.create_session(Path::new(&v.workspace), Some(&v.model), None, Some(&format!("fork of {src}"))).map_err(|e| e.to_string())?;
            let mut log = c.k.store.open(&new).map_err(|e| e.to_string())?;
            let upto = if v.dangling.is_empty() { v.messages.len() } else { v.messages.len() - 1 };
            for m in &v.messages[..upto] {
                log.append(EventKind::Message { message: m.clone(), usage: None, model: None, inbox: None }).map_err(|e| e.to_string())?;
            }
            println!("{new}");
            Ok(0)
        }
        "search" => {
            let c = build(a, approver_for(a, false))?;
            let q = a.rest(1);
            if q.trim().is_empty() {
                return usage("missing <query>");
            }
            let hits = c.k.store.search(&q, a.num::<usize>("limit").map_err(Fail::Usage)?.unwrap_or(20));
            if hits.is_empty() {
                println!("no matches");
                return Ok(1);
            }
            for h in hits {
                println!("{} #{}  {}", h.session, h.seq, term::one_line(&h.snippet, 140));
            }
            Ok(0)
        }
        "export" => {
            let c = build(a, approver_for(a, false))?;
            let id = find_session(&c.k, a.need(1, "session")?)?;
            let v = project(&c.k.store.read(&id).map_err(|e| e.to_string())?);
            println!("# Session {id}\n\n- workspace: `{}`\n- model: `{}`\n", v.workspace, v.model);
            for m in &v.messages {
                let who = if m.role == Role::User { "User" } else { "Assistant" };
                let text = m.text();
                if !text.trim().is_empty() {
                    println!("## {who}\n\n{text}\n");
                }
                for (_, name, input) in m.tool_uses() {
                    println!("> tool `{name}` `{}`\n", term::one_line(&input.to_string(), 200));
                }
            }
            Ok(0)
        }
        "compact" => {
            let c = build(a, approver_for(a, false))?;
            let id = find_session(&c.k, a.need(1, "session")?)?;
            println!("{}", if c.k.compact(&id).map_err(|e| e.to_string())? { "compacted" } else { "nothing to compact" });
            Ok(0)
        }
        "model" => {
            let c = build(a, approver_for(a, false))?;
            let id = find_session(&c.k, a.need(1, "session")?)?;
            let m = a.need(2, "provider/model")?;
            c.k.set_model(&id, m).map_err(|e| e.to_string())?;
            println!("model → {m}");
            Ok(0)
        }
        "rm" | "delete" => {
            let c = build(a, approver_for(a, false))?;
            let id = find_session(&c.k, a.need(1, "session")?)?;
            c.k.store.remove(&id).map_err(|e| e.to_string())?;
            println!("removed {id}");
            Ok(0)
        }
        other => usage(format!("unknown `session {other}`")),
    }
}

// ───────────────────────── daemon ─────────────────────────

const HOST_METHODS: &[&str] = &["channels.list", "pairing.list", "pairing.approve", "pairing.revoke", "mcp.list", "mcp.app_call", "plugins.list", "plugins.ui", "plugins.ui_call", "command.run"];

fn plugin_json(p: &Arc<ark_plugin::PluginHost>) -> Value {
    json!({"name": p.name, "hooks": p.hooks(), "channels": p.channels(), "commands": p.commands, "routes": p.routes, "providers": p.providers, "services": p.services,
        "cli": p.cli, "middleware": p.middleware_kinds(), "context_engine": p.context_engine, "memory": p.memory, "node_commands": p.node_commands, "ui": p.ui})
}

/// `/plugins/<name>/ui/<id>`: a declared UI panel.
fn ui_panel(sub: &str) -> Option<&str> {
    sub.strip_prefix("/ui/").map(|id| id.trim_end_matches('/')).filter(|id| !id.is_empty() && !id.contains('/'))
}

/// A plugin's HTTP routes on the app server.
struct PluginMount(Arc<ark_plugin::PluginHost>);

impl ark_app::server::Mount for PluginMount {
    fn route(&self, method: &str, sub: &str) -> Option<bool> {
        if method == "GET" && ui_panel(sub).is_some_and(|id| self.0.ui.iter().any(|u| u.id == id)) {
            return Some(false);
        }
        self.0.route(method, sub).map(|r| r.public)
    }
    fn serve(&self, r: &ark_net::httpd::Request, sub: &str) -> ark_net::httpd::Response {
        if let Some(id) = ui_panel(sub).filter(|id| r.method == "GET" && self.0.ui.iter().any(|u| u.id == *id)) {
            return match self.0.ui_render(id, &r.raw_query) {
                Ok(v) => ark_net::httpd::Response::new(200, "text/html; charset=utf-8", v["html"].as_str().unwrap_or("").as_bytes().to_vec()),
                Err(e) => ark_net::httpd::Response::json(502, &json!({"error": e}).to_string()),
            };
        }
        match self.0.http(&r.method, sub, &r.raw_query, &r.headers, &r.body) {
            Ok(h) => {
                let ctype = h.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone()).unwrap_or_else(|| "application/octet-stream".into());
                let mut resp = ark_net::httpd::Response::new(h.status, &ctype, h.body);
                const SKIP: &[&str] = &["content-type", "content-length", "connection", "transfer-encoding", "content-security-policy"];
                for (k, v) in h.headers.iter().filter(|(k, _)| !SKIP.iter().any(|s| k.eq_ignore_ascii_case(s))) {
                    resp = resp.with_header(k, v);
                }
                resp
            }
            Err(e) => ark_net::httpd::Response::json(502, &json!({"error": e}).to_string()),
        }
    }
}

/// ARP methods that live in the binary (channels, DM pairing, MCP status).
fn host_methods(paths: &Paths, ext: Option<&ext::Ext>) -> ark_kernel::daemon::MethodExt {
    let pairing = Arc::new(ark_channel::access::Pairing::open(paths.data.join("channels").join("pairing.json")));
    let plugins: Vec<Arc<ark_plugin::PluginHost>> = ext.map(|e| e.plugins.clone()).unwrap_or_default();
    let plugin_list: Vec<Value> = plugins.iter().map(plugin_json).collect();
    let channels: Vec<Value> = ext.map(|e| e.channels.iter().map(|(n, (ch, c))| json!({"name": n, "kind": c.kind, "caps": ch.caps(), "dm_policy": c.policy.dm_policy, "default_chat": c.default_chat})).collect()).unwrap_or_default();
    let mcp: Vec<Value> = ext.map(|e| e.registry.status().into_iter().map(|(n, tools, running)| json!({"name": n, "tools": tools, "running": running})).collect()).unwrap_or_default();
    // MCP Apps: tools a view may call, with the client that serves them.
    let app_tools: Vec<(String, ark_plugin::ToolDef, Arc<ark_plugin::Client>)> =
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
                let rest = line.trim().trim_start_matches('/');
                let name = rest.split_whitespace().next().unwrap_or("");
                match plugins.iter().find(|h| h.commands.iter().any(|c| c.name == name)) {
                    None => Ok(json!({"handled": false})),
                    Some(h) => h.command(name, rest[name.len()..].trim(), ctx).map(|r| json!({"handled": true, "text": r.text, "prompt": r.prompt})).map_err(|e| (-32000, e)),
                }
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
fn mcp_app_call(tools: &[(String, ark_plugin::ToolDef, Arc<ark_plugin::Client>)], k: Option<&Kernel>, p: &Value) -> Result<Value, (i32, String)> {
    use ark_kernel::approver::{Approval, ApprovalRequest};
    let (server, name) = (p["server"].as_str().unwrap_or(""), p["name"].as_str().unwrap_or(""));
    let Some((_, def, client)) = tools.iter().find(|(s, d, _)| s == server && d.name == name) else {
        return Err((-32602, format!("`{name}` on MCP server `{server}` is not callable from an app view")));
    };
    let args = if p["arguments"].is_object() { p["arguments"].clone() } else { json!({}) };
    if !def.read_only || client.config().untrusted() {
        let k = k.ok_or((-32000, "agent not ready".to_string()))?;
        let req = ApprovalRequest {
            id: format!("app-{}", ark_net::crypto::random_token(6)),
            tool_use_id: String::new(),
            session: p["session"].as_str().unwrap_or("mcp-app").into(),
            tool: format!("mcp__{server}__{name}"),
            summary: args.to_string().chars().take(2000).collect(),
            input: args.clone(),
            gate: ark_kernel::gate::GateKind::Egress,
            reason: format!("the `{server}` app view wants to call `{name}`"),
        };
        if k.approver.approve(&req) == Approval::Deny {
            return Err((-32001, "denied by the user".into()));
        }
    }
    let r = client.call_tool(name, args, &ark_core::Cancel::new()).map_err(|e| (-32000, e))?;
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
            let c = build_agent(a, pending.clone(), true)?;
            let _ = cell.set(Arc::downgrade(&c.k));
            eprintln!("arkd {} listening on {}", env!("CARGO_PKG_VERSION"), sock.display());
            let stop = ark_core::Cancel::new();
            let loops = match &c.ext {
                Some(e) => ext::spawn_channel_loops(c.k.clone(), e, c.workspace.clone(), stop.clone()),
                None => vec![],
            };
            if !loops.is_empty() {
                eprintln!("arkd: {} channel(s) active", loops.len());
            }
            let services = c.ext.as_ref().and_then(|e| ark_plugin::plugin::supervise(e.plugins.clone(), stop.clone()));
            for p in c.ext.iter().flat_map(|e| e.plugins.iter()).filter(|p| !p.routes.is_empty() || !p.ui.is_empty()) {
                ark_app::server::mount(&p.name, Arc::new(PluginMount(p.clone())));
            }
            c.k.emit(ark_kernel::hooks::HookEvent::DaemonStart, json!({"session_id": "", "cwd": c.workspace, "pid": std::process::id()}), "");
            let d = Arc::new(Daemon::new(c.k.clone(), pending));
            ark_app::node::init(&paths.data);
            d.add_methods(ark_app::node::methods());
            d.add_methods(host_methods(&paths, c.ext.as_ref()));
            // App server: web/desktop UI, WebSocket ARP, OpenAI-compatible API, A2A, nodes.
            let app_cfg = ark_app::AppConfig::parse(&c.k.cfg.app)?;
            let _server = if app_cfg.enabled {
                let token = app_cfg.token.as_deref().map(|t| (c.k.vault_substitute())(t)).unwrap_or_default();
                if token.contains("{{secret:") {
                    return Err("[app] token references a secret that is not set (ark secrets set APP_TOKEN …)".into());
                }
                let mut host: Vec<String> = ark_app::node::METHODS.iter().map(|s| s.to_string()).collect();
                host.extend(HOST_METHODS.iter().map(|s| s.to_string()));
                // MCP event deliveries arrive as signed webhooks and are queued into the subscribing session.
                let mut routes: Vec<(String, ark_net::httpd::Handler)> = vec![];
                if let Some(hub) = c.ext.as_ref().and_then(|e| e.registry.events()) {
                    let k = c.k.clone();
                    hub.set_sink(Arc::new(move |dl: &ark_plugin::events::Delivery| {
                        let Some(sid) = dl.session.as_deref() else { return };
                        if k.submit(sid, &ark_plugin::events::prompt_for(dl), "mcp-event").is_ok() && !k.is_running(sid) {
                            let _ = k.start(sid, Default::default());
                        }
                    }));
                    hub.start_refresher();
                    routes.push(("/mcp-events/".into(), hub.handler()));
                }
                let app = Arc::new(ark_app::App { d: d.clone(), cfg: app_cfg.clone(), token, host_methods: host, routes });
                let srv = ark_app::start(app)?;
                eprintln!("arkd: app server on http://{} (UI, /arp, /v1, {})", srv.local_addr(), if app_cfg.a2a.enabled { "/a2a" } else { "no a2a" });
                Some(srv)
            } else {
                None
            };
            let r = d.run();
            c.k.emit(ark_kernel::hooks::HookEvent::DaemonStop, json!({"session_id": "", "cwd": c.workspace}), "");
            stop.cancel();
            if let Some(t) = services {
                let _ = t.join();
            }
            r?;
            Ok(0)
        }
        "start" => {
            if daemon::call(&sock, "ping", json!({})).is_ok() {
                println!("arkd already running");
                return Ok(0);
            }
            std::fs::create_dir_all(&paths.data).map_err(|e| e.to_string())?;
            let log = std::fs::OpenOptions::new().create(true).append(true).open(paths.data.join("arkd.log")).map_err(|e| e.to_string())?;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let mut cmd = std::process::Command::new(exe);
            cmd.arg("daemon").arg("run").stdin(std::process::Stdio::null()).stdout(log.try_clone().map_err(|e| e.to_string())?).stderr(log);
            for s in a.vals("set") {
                cmd.arg("--set").arg(s);
            }
            if let Some(w) = a.val("workspace") {
                cmd.arg("-w").arg(w);
            }
            use std::os::unix::process::CommandExt;
            unsafe {
                cmd.pre_exec(|| {
                    libc::setsid();
                    Ok(())
                });
            }
            let mut child = cmd.spawn().map_err(|e| e.to_string())?;
            let until = Instant::now() + Duration::from_secs(8);
            while Instant::now() < until {
                if daemon::call(&sock, "ping", json!({})).is_ok() {
                    println!("arkd started (pid {})", child.id());
                    return Ok(0);
                }
                if let Ok(Some(st)) = child.try_wait() {
                    return Err(format!("arkd exited during startup ({st}); see {}", paths.data.join("arkd.log").display()).into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err("arkd did not come up within 8s".into())
        }
        "stop" => {
            match daemon::call(&sock, "shutdown", json!({})) {
                Ok(_) => {
                    let until = Instant::now() + Duration::from_secs(15);
                    while sock.exists() && Instant::now() < until {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    println!("{}", if sock.exists() { "arkd is still shutting down" } else { "arkd stopped" });
                }
                Err(_) => println!("arkd is not running"),
            }
            Ok(0)
        }
        "status" => match daemon::call(&sock, "ping", json!({})) {
            Ok(r) => {
                println!("arkd running · pid {} · version {} · running sessions: {}", r["pid"], r["version"].as_str().unwrap_or("?"), r["running"].as_array().map(|v| v.len()).unwrap_or(0));
                Ok(0)
            }
            Err(e) => {
                println!("{e}");
                Ok(1)
            }
        },
        "install" => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
            let unit_dir = PathBuf::from(home).join(".config/systemd/user");
            std::fs::create_dir_all(&unit_dir).map_err(|e| e.to_string())?;
            let unit = format!("[Unit]\nDescription=ark agent daemon\nAfter=network-online.target\n\n[Service]\nExecStart={} daemon run\nRestart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n", exe.display());
            let path = unit_dir.join("arkd.service");
            std::fs::write(&path, unit).map_err(|e| e.to_string())?;
            println!("wrote {}\nenable with: systemctl --user daemon-reload && systemctl --user enable --now arkd", path.display());
            Ok(0)
        }
        other => usage(format!("unknown `daemon {other}`")),
    }
}

fn cmd_attach(a: &Args) -> R {
    let id = a.need(0, "session")?.to_string();
    let from = a.num::<u64>("from").map_err(Fail::Usage)?.unwrap_or(0);
    let json_out = a.flag("json");
    let sock = Paths::from_env().socket();
    daemon::stream(&sock, "session.attach", json!({"id": id, "from_seq": from}), |v| {
        if json_out {
            println!("{v}");
            return true;
        }
        match v.get("method").and_then(|m| m.as_str()) {
            Some("delta") => {
                if v["params"]["thinking"].as_bool() != Some(true) {
                    print!("{}", v["params"]["text"].as_str().unwrap_or(""));
                    let _ = std::io::stdout().flush();
                }
            }
            Some("event") => {
                let e = &v["params"]["event"];
                match e["type"].as_str() {
                    Some("turn_end") => eprintln!("\n• turn ended: {}", e["reason"].as_str().unwrap_or("")),
                    Some("notice") | Some("error") => eprintln!("• {}", e["text"].as_str().or(e["message"].as_str()).unwrap_or("")),
                    Some("gate") => eprintln!("⚑ {} gate: {} — {}", e["gate"].as_str().unwrap_or(""), e["verdict"].as_str().unwrap_or(""), e["reason"].as_str().unwrap_or("")),
                    _ => {}
                }
            }
            Some("pending") => eprintln!("⚑ waiting for approval: {}  →  ark gate answer {} once|always|deny", v["params"]["reason"].as_str().or(v["params"]["question"].as_str()).unwrap_or(""), v["params"]["id"].as_str().unwrap_or("")),
            _ => {}
        }
        true
    })?;
    Ok(0)
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
            for i in items {
                println!("{}  [{}] {} {}", i["id"].as_str().unwrap_or(""), i["kind"].as_str().unwrap_or(""), i["reason"].as_str().or(i["question"].as_str()).unwrap_or(""), i["summary"].as_str().map(|s| term::one_line(s, 100)).unwrap_or_default());
            }
            Ok(0)
        }
        "answer" => {
            let id = a.need(1, "id")?;
            let ans = a.rest(2);
            if ans.trim().is_empty() {
                return usage("missing <answer>");
            }
            daemon::call(&sock, "gate.answer", json!({"id": id, "answer": ans}))?;
            println!("answered");
            Ok(0)
        }
        other => usage(format!("unknown `gate {other}`")),
    }
}

// ───────────────────────── schedule / goals ─────────────────────────

fn cmd_schedule(a: &Args) -> R {
    let paths = Paths::from_env();
    match a.pos(0).unwrap_or("list") {
        "add" => {
            let cron = a.need(1, "cron")?;
            let prompt = a.rest(2);
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let j = automation::add_job(&paths.data, cron, &prompt, &ws, a.val("model").map(String::from), a.flag("reuse"), cfg.schedule.utc_offset_minutes)?;
            println!("added {} · next run {} (UTC{:+})", j.id, ark_kernel::util::fmt_time(j.next_run, cfg.schedule.utc_offset_minutes), cfg.schedule.utc_offset_minutes as f64 / 60.0);
            if daemon::call(&paths.socket(), "ping", json!({})).is_err() {
                eprintln!("note: arkd is not running; schedules fire only while it runs (`ark daemon start`)");
            }
            Ok(0)
        }
        "list" | "ls" => {
            let jobs: Vec<Job> = automation::read_list(&automation::jobs_path(&paths.data))?;
            if jobs.is_empty() {
                println!("no schedules");
            }
            for j in jobs {
                println!("{}  {:<16} {}  next {}  last {}  {}", j.id, j.cron, if j.enabled { "on " } else { "off" }, ark_kernel::util::fmt_time(j.next_run, 480), j.last_result.as_deref().unwrap_or("-"), term::one_line(&j.prompt, 50));
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
        other => usage(format!("unknown `schedule {other}`")),
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
                Ok(_) => println!("running in arkd · follow with `ark attach {}`", g.session),
                Err(_) => println!("arkd not running · run it now with `ark goal run {}`", g.id),
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
                println!("arkd not running · continue with `ark goal run {}`", g.id);
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
    ark_kernel::util::atomic_write(&p, new.as_bytes()).map_err(|e| Fail::Msg(e.to_string()))
}

fn cmd_checkpoint(a: &Args) -> R {
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
            println!("user     {}\nproject  {}\nsecrets  {}\ndata     {}\nsocket   {}", paths.user_config().display(), project_config(&workspace(a)?).display(), paths.secrets().display(), paths.data.display(), paths.socket().display());
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
    let v = load_vault(&paths)?;
    match a.pos(0).unwrap_or("list") {
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
        other => usage(format!("unknown `secrets {other}`")),
    }
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
                    Err(_) => format!("key: missing ({})", c.api_key_env.as_deref().unwrap_or("-")),
                };
                println!("{id:<12} {:<17} {:<52} {key}", format!("{:?}", c.format), c.base_url);
            }
            Ok(0)
        }
        "check" => {
            let model = a.pos(1).map(String::from).unwrap_or(cfg.model.default.clone());
            let (pid, m) = ark_kernel::context::split_model(&model);
            let prov = p.provider(pid)?;
            let req = ark_core::ModelRequest { model: m.into(), system: vec![], messages: vec![ark_core::Message::user("Reply with exactly: pong")], tools: vec![], max_tokens: 2048, temperature: None, cache_after_message: None, reasoning: None };
            let t0 = Instant::now();
            match prov.complete(&req, &mut |_| {}, &ark_core::Cancel::new().with_deadline(Instant::now() + Duration::from_secs(60))) {
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
    check("secrets", vault.as_ref().map(|v| format!("{} stored, permissions ok", v.names().len())).map_err(|e| e.clone()));
    if let (Ok(cfg), Ok(v)) = (&cfg, vault) {
        if let Ok(p) = Providers::new(&cfg.providers, Arc::new(v)) {
            let mut models = vec![cfg.model.default.clone()];
            models.extend(cfg.model.fallback.clone());
            models.push(cfg.aux_model().to_string());
            models.dedup();
            for m in models {
                let pid = ark_kernel::context::split_model(&m).0;
                check(&format!("model {m}"), p.key_source(pid).map(|s| format!("key from {s}")));
            }
        }
    }
    let tool = |bin: &str| std::process::Command::new(bin).arg("--version").output().map(|o| String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").to_string()).map_err(|e| e.to_string());
    check("bash", tool("bash"));
    check("git (checkpoints)", tool("git"));
    check("python3 (code mode)", tool("python3"));
    check("data dir", std::fs::create_dir_all(&paths.data).map(|_| paths.data.display().to_string()).map_err(|e| e.to_string()));
    let sock = paths.socket();
    check("socket path length", if sock.as_os_str().len() < 100 { Ok(format!("{} bytes", sock.as_os_str().len())) } else { Err("too long for a unix socket; set XDG_RUNTIME_DIR".into()) });
    match daemon::call(&sock, "ping", json!({})) {
        Ok(r) => println!("✓ arkd: running (pid {})", r["pid"]),
        Err(_) => println!("· arkd: not running (needed for schedules, goals in background, send/attach)"),
    }
    Ok(if bad == 0 { 0 } else { 1 })
}

fn cmd_call(a: &Args) -> R {
    let tool = a.need(0, "tool")?;
    let input = a.rest(1);
    match ark_kernel::coderun::client(tool, &input) {
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

fn cmd_mcp(a: &Args) -> R {
    let paths = Paths::from_env();
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let vault = load_vault(&paths)?;
            let (cfgs, warn) = ext::mcp_configs(&cfg);
            let reg = ark_plugin::Registry::load(&cfgs, &paths.data.join("mcp-cache"), ext::secrets_fn(&vault));
            if cfgs.is_empty() && warn.is_empty() {
                println!("no MCP servers (add one with `ark mcp add <name> -- <command> args…` or `--url`)");
            }
            for (name, n, running) in reg.status() {
                let c = &cfgs[&name];
                let what = c.url.clone().unwrap_or_else(|| format!("{} {}", c.command.as_deref().unwrap_or(""), c.args.join(" ")));
                println!("{name:<16} {:<8} {n:>3} tools  {}  {}", if !c.enabled { "disabled" } else if running { "running" } else { "lazy" }, if c.url.is_some() { "http " } else { "stdio" }, term::one_line(&what, 60));
            }
            for w in warn.iter().chain(reg.warnings()) {
                println!("! {w}");
            }
            Ok(0)
        }
        "tools" => {
            let c = build_agent(a, approver_for(a, false), false)?;
            let only = a.pos(1);
            for t in &c.k.tools {
                let s = t.spec();
                if let Some(rest) = s.name.strip_prefix("mcp__") {
                    if only.is_none_or(|o| rest.starts_with(&format!("{o}__"))) {
                        println!("{:<40} {}", s.name, term::one_line(s.summary(), 80));
                    }
                }
            }
            Ok(0)
        }
        "test" | "refresh" => {
            let name = a.need(1, "server")?;
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let vault = load_vault(&paths)?;
            let (cfgs, _) = ext::mcp_configs(&cfg);
            if !cfgs.contains_key(name) {
                return Err(format!("no MCP server `{name}` (see `ark mcp list`)").into());
            }
            let mut reg = ark_plugin::Registry::load(&BTreeMap::from([(name.to_string(), cfgs[name].clone())]), &paths.data.join("mcp-cache"), ext::secrets_fn(&vault));
            let t = Instant::now();
            match reg.refresh(name) {
                Ok(n) => {
                    println!("{name}: ok in {:.1}s · {n} tools", t.elapsed().as_secs_f32());
                    Ok(0)
                }
                Err(e) => Err(format!("{name}: {e}").into()),
            }
        }
        "login" => {
            let name = a.need(1, "server")?;
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let (cfgs, _) = ext::mcp_configs(&cfg);
            let c = cfgs.get(name).ok_or_else(|| format!("no MCP server `{name}` in config"))?;
            let url = c.url.as_deref().ok_or("OAuth applies to HTTP servers (`url`), not stdio")?;
            if !c.uses_oauth() {
                eprintln!("note: [mcp.{name}] has no `auth = \"oauth\"`; tokens are saved but not used until you add it");
            }
            struct Show(bool);
            impl ark_plugin::oauth::Prompter for Show {
                fn open(&self, url: &str) {
                    println!("在瀏覽器開啟以下網址完成授權：\n\n  {url}\n");
                    if self.0 {
                        let _ = std::process::Command::new("xdg-open").arg(url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn();
                    }
                }
                fn device(&self, uri: &str, code: &str, complete: Option<&str>) {
                    println!("請到 {uri} 輸入代碼：{code}");
                    if let Some(c) = complete {
                        println!("（或直接開啟 {c}）");
                    }
                }
            }
            let challenge = ark_plugin::oauth::probe_challenge(url);
            let wait = Duration::from_secs(600);
            let t = if a.flag("device") {
                ark_plugin::oauth::login_device(url, challenge.as_deref(), &c.oauth, &Show(false), wait)
            } else {
                ark_plugin::oauth::login_browser(url, challenge.as_deref(), &c.oauth, &Show(!a.flag("no-browser")), wait)
            }
            .map_err(|e| format!("{name}: login failed: {e}"))?;
            let store = ark_plugin::oauth::Store::new(&paths.data, name);
            store.save(t)?;
            println!("{name}: 已登入，token 存在 {}", store.path().display());
            Ok(0)
        }
        "logout" => {
            let name = a.need(1, "server")?;
            let store = ark_plugin::oauth::Store::new(&paths.data, name);
            let had = store.has_tokens();
            store.clear();
            println!("{name}: {}", if had { "已登出（token 已刪除）" } else { "原本就沒有登入" });
            Ok(0)
        }
        "add" => {
            let name = a.need(1, "name")?;
            if !valid_ext_name(name) {
                return usage("name: letters, digits, _ and - only");
            }
            let user = paths.user_config();
            let text = std::fs::read_to_string(&user).unwrap_or_default();
            if text.lines().any(|l| l.trim() == format!("[mcp.{name}]")) {
                return Err(format!("[mcp.{name}] already exists in {}", user.display()).into());
            }
            let mut block = format!("\n[mcp.{name}]\n");
            if let Some(u) = a.val("url") {
                block.push_str(&format!("url = {}\n", toml_str(u)));
                let hs = a.vals("header");
                if !hs.is_empty() {
                    let mut ht = toml::Table::new();
                    for h in hs {
                        let (k, v) = h.split_once('=').ok_or("--header expects Name=value (use {{secret:NAME}} for tokens)")?;
                        ht.insert(k.trim().into(), toml::Value::String(v.trim().into()));
                    }
                    block.push_str(&format!("headers = {}\n", toml::Value::Table(ht)));
                }
            } else {
                let cmd = a.pos(2).ok_or(Fail::Usage("give `--url URL` or `-- <command> args…`".into()))?;
                block.push_str(&format!("command = {}\n", toml_str(cmd)));
                let args: Vec<toml::Value> = a.pos.iter().skip(3).map(|s| toml::Value::String(s.clone())).collect();
                if !args.is_empty() {
                    block.push_str(&format!("args = {}\n", toml::Value::Array(args)));
                }
            }
            // Validate before writing.
            let t: toml::Table = block.parse().map_err(|e| format!("{e}"))?;
            let c: ark_plugin::McpServerConfig = toml::Value::Table(t["mcp"][name].as_table().cloned().unwrap_or_default()).try_into().map_err(|e: toml::de::Error| e.message().to_string())?;
            c.validate(name)?;
            if let Some(d) = user.parent() {
                std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
            }
            std::fs::write(&user, format!("{}{block}", text)).map_err(|e| e.to_string())?;
            println!("added [mcp.{name}] to {} — check it with `ark mcp test {name}`", user.display());
            Ok(0)
        }
        "rm" | "remove" => {
            let name = a.need(1, "name")?;
            let user = paths.user_config();
            let text = std::fs::read_to_string(&user).map_err(|e| e.to_string())?;
            let header = format!("[mcp.{name}]");
            let mut out = Vec::new();
            let mut skipping = false;
            let mut found = false;
            for l in text.lines() {
                let t = l.trim();
                if t.starts_with('[') {
                    skipping = t == header || t.starts_with(&format!("[mcp.{name}."));
                    found |= skipping;
                }
                if !skipping {
                    out.push(l);
                }
            }
            if !found {
                return Err(format!("no [mcp.{name}] in {}", user.display()).into());
            }
            std::fs::write(&user, out.join("\n") + "\n").map_err(|e| e.to_string())?;
            println!("removed [mcp.{name}]");
            Ok(0)
        }
        "serve" => {
            // Ark's builtin tools as an MCP server on stdio, behind the same gates.
            let ws = workspace(a)?;
            let cfg = load_config(a, &ws, &paths)?;
            let vault = load_vault(&paths)?;
            let mut tools: Vec<Arc<dyn ark_core::Tool>> = ark_tools::builtin_tools().into_iter().filter(|t| !matches!(t.spec().name.as_str(), "spawn" | "ask_user")).collect();
            // Conversation tools: drive and approve sessions in the running daemon.
            tools.extend(ark_app::conversations::tools(paths.socket()));
            let (allow_p, allow_e) = (a.flag("allow-privilege") || a.flag("yes"), a.flag("allow-egress") || a.flag("yes"));
            let v2 = vault.clone();
            let gcfg = cfg.gate.clone();
            let judge = move |effects: &[ark_core::Effect]| -> Result<(), String> {
                use ark_kernel::gate::{GateKind, Gates, Verdict};
                match (Gates { cfg: &gcfg, vault: &v2 }).judge(effects) {
                    Verdict::Allow => Ok(()),
                    Verdict::Ask { gate: GateKind::Privilege, .. } if allow_p => Ok(()),
                    Verdict::Ask { gate: GateKind::Egress, .. } if allow_e => Ok(()),
                    Verdict::Ask { gate, reason } | Verdict::Deny { gate, reason } => Err(format!("blocked by the {gate:?} gate: {reason}")),
                }
            };
            let data = paths.data.clone();
            let v3 = vault.clone();
            let ctx = move || ark_core::ToolCtx {
                workspace: ws.clone(),
                session_id: "mcp-serve".into(),
                artifacts: data.join("mcp-serve"),
                home: data.clone(),
                cancel: ark_core::Cancel::new(),
                host: Arc::new(NoHost),
                secrets: ext::secrets_fn(&v3),
            };
            let info = ark_plugin::ServerInfo { name: "ark".into(), version: env!("CARGO_PKG_VERSION").into(), instructions: Some("Ark's file, search, shell and memory tools, plus ark_session_* / ark_pending* to drive and approve sessions in the running ark daemon. Calls pass Ark's privilege and egress gates.".into()) };
            if let Some(relay) = a.val("relay") {
                // Outbound relay instead of stdio: no inbound port, Ed25519-authenticated, grant-scoped.
                let srv = ark_plugin::Server { info: &info, tools: &tools, ctx: &ctx, judge: &judge };
                let handle = |m: &Value| srv.handle(m).and_then(|r| serde_json::from_str(&vault.redact(&r.to_string())).ok());
                let opts = ark_plugin::relay::Opts { relay: relay.to_string(), state: paths.data.join("mcp-relay.json"), name: "ark".into(), version: env!("CARGO_PKG_VERSION").into(), pair: a.flag("pair") };
                ark_plugin::relay::run(&opts, &handle, &ark_core::Cancel::new(), &|l: &str| eprintln!("{l}"))?;
                return Ok(0);
            }
            let stdin = std::io::stdin();
            ark_plugin::serve(&info, &tools, &ctx, &judge, stdin.lock(), RedactingWriter { inner: std::io::stdout(), vault, buf: Vec::new() }).map_err(|e| e.to_string())?;
            Ok(0)
        }
        other => usage(format!("unknown `mcp {other}`")),
    }
}

struct NoHost;
impl ark_core::ToolHost for NoHost {
    fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &ark_core::Cancel) -> Result<String, String> {
        Err("not available over MCP".into())
    }
    fn ask_user(&self, _: &str) -> Result<String, String> {
        Err("not available over MCP".into())
    }
}

/// Line-buffered stdout that strips vault secrets from every reply.
struct RedactingWriter {
    inner: std::io::Stdout,
    vault: Arc<Vault>,
    buf: Vec<u8>,
}
impl Write for RedactingWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(b);
        while let Some(i) = self.buf.iter().position(|&c| c == b'\n') {
            let line: Vec<u8> = self.buf.drain(..=i).collect();
            let s = self.vault.redact(&String::from_utf8_lossy(&line));
            self.inner.write_all(s.as_bytes())?;
        }
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            let s = self.vault.redact(&String::from_utf8_lossy(&std::mem::take(&mut self.buf)));
            self.inner.write_all(s.as_bytes())?;
        }
        self.inner.flush()
    }
}

fn cmd_plugin(a: &Args) -> R {
    let c = build_agent(a, approver_for(a, false), false)?;
    let e = c.ext.as_ref().unwrap();
    if e.plugins.is_empty() {
        println!("no plugins (configure [plugins.<name>] command = …)");
    }
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
            extra.push(format!("cli: {}", list(p.cli.iter().map(|c| format!("ark {}", c.name)).collect())));
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

/// The systemd user unit for the daemon (see packaging/systemd/ for notes).
pub fn service_unit(exe: &Path, workspace: &Path) -> String {
    format!(
        "[Unit]
Description=ark agent daemon
Documentation=https://github.com/ark-agent/ark
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=notify
NotifyAccess=main
ExecStart={exe} daemon run -w {ws}
WorkingDirectory={ws}
Restart=on-failure
RestartSec=2s
# SIGTERM to arkd first (it interrupts runs and saves state), then the rest of the group.
KillMode=mixed
TimeoutStopSec=20s
# ark refuses sudo by policy; make that impossible rather than merely discouraged.
NoNewPrivileges=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
RestrictRealtime=yes
UMask=0077
# Not set on purpose: MemoryDenyWriteExecute (breaks Node/V8 bridges), ProtectHome (ark works
# in $HOME), RestrictNamespaces (breaks sandboxes ark may run). PrivateTmp/ProtectKernel* need
# unprivileged user namespaces in user units; enable them in a drop-in if your distro allows.

[Install]
WantedBy=default.target
",
        exe = exe.display(),
        ws = workspace.display()
    )
}

/// Install / remove the systemd user service.
fn cmd_service(a: &Args) -> R {
    let unit_dir = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config")).join("systemd/user");
    let unit = unit_dir.join("arkd.service");
    let systemctl = |args: &[&str]| std::process::Command::new("systemctl").arg("--user").args(args).status().map(|s| s.success()).unwrap_or(false);
    match a.pos(0).unwrap_or("status") {
        "install" => {
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let ws = workspace(a)?;
            std::fs::create_dir_all(&unit_dir).map_err(|e| e.to_string())?;
            std::fs::write(&unit, service_unit(&exe, &ws)).map_err(|e| format!("{}: {e}", unit.display()))?;
            println!("wrote {}", unit.display());
            if a.flag("no-start") {
                return Ok(0);
            }
            if !(systemctl(&["daemon-reload"]) && systemctl(&["enable", "--now", "arkd.service"])) {
                return Err("systemctl --user failed (no user session bus?). Start it later with: systemctl --user enable --now arkd".into());
            }
            println!("arkd enabled and started.");
            println!("To keep it running after logout and start it at boot: loginctl enable-linger $USER");
            Ok(0)
        }
        "uninstall" => {
            let _ = systemctl(&["disable", "--now", "arkd.service"]);
            let _ = std::fs::remove_file(&unit);
            let _ = systemctl(&["daemon-reload"]);
            println!("removed {}", unit.display());
            Ok(0)
        }
        "status" => {
            if !unit.exists() {
                println!("not installed (ark service install)");
                return Ok(0);
            }
            systemctl(&["status", "--no-pager", "arkd.service"]);
            Ok(0)
        }
        "print" => {
            print!("{}", service_unit(&std::env::current_exe().map_err(|e| e.to_string())?, &workspace(a)?));
            Ok(0)
        }
        other => Err(format!("unknown service subcommand `{other}` (install [--no-start], uninstall, status, print)").into()),
    }
}

/// Data-subject requests (個資法 §3/§11): export or delete everything ark holds about one
/// channel user — their sessions, routing, pairing approval and downloaded attachments.
fn cmd_data(a: &Args) -> R {
    let paths = Paths::from_env();
    let action = a.pos(0).unwrap_or("");
    let channel = a.need(1, "channel")?;
    let who = a.need(2, "sender or chat id")?;
    let dir = paths.data.join("channels");
    let router = ark_channel::Router::open(dir.join("routes.json"), Default::default());
    let routes = ext::forget_routes(&router, channel, &[who]);
    let store = ark_kernel::store::Store::new(paths.data.join("sessions"));
    let pairing = ark_channel::access::Pairing::open(dir.join("pairing.json"));
    match action {
        "export" => {
            let mut sessions = Vec::new();
            for r in &routes {
                let events = store.read(&r.session).map(|e| serde_json::to_value(e).unwrap_or_default()).unwrap_or(Value::Null);
                sessions.push(json!({"chat": r.key.chat, "sender": r.key.sender, "session": r.session, "events": events}));
            }
            let approved: Vec<Value> = pairing.approved().into_iter().filter(|(c, s, _)| c == channel && s == who).map(|(_, _, ap)| json!(ap)).collect();
            let doc = json!({"channel": channel, "subject": who, "exported_at": now_secs(), "sessions": sessions, "pairing": approved,
                "note": "Long-term memory (ark memory) is shared across sessions and is not split per person; review it with `ark memory show`."});
            println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
            Ok(0)
        }
        "delete" => {
            if !a.flag("yes") {
                return Err(format!("this permanently deletes {} session(s) for {who} on {channel}; re-run with --yes", routes.len()).into());
            }
            let (n, files, revoked) = ext::forget(&store, &router, Some(&pairing), channel, &[who]);
            println!("deleted {n} session(s), {files} attachment(s){} for {who} on {channel}", if revoked { ", revoked pairing" } else { "" });
            println!("note: shared long-term memory is not split per person; check `ark memory show` for anything about them.");
            Ok(0)
        }
        _ => Err("usage: ark data export <channel> <sender|chat>  |  ark data delete <channel> <sender|chat> --yes".into()),
    }
}

/// Dynamic webhook routes (Hermes `webhook subscribe`); the listener hot-reloads the file.
fn cmd_webhook(a: &Args) -> R {
    use ark_channel::webhook;
    let paths = Paths::from_env();
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
        _ => Err("usage: ark webhook list <channel> | subscribe <channel> <route> [json] | rm <channel> <route>".into()),
    }
}

/// Full-screen terminal UI on the daemon (same protocol as the web UI).
fn cmd_tui(a: &Args) -> R {
    let paths = Paths::from_env();
    let ws = workspace(a)?;
    ark_app::tui::run(&paths.socket(), &ws)?;
    Ok(0)
}

/// ACP agent on stdio for editors (Zed, JetBrains, Neovim…): `"command": "ark", "args": ["acp"]`.
fn cmd_acp(a: &Args) -> R {
    let slot: Arc<std::sync::OnceLock<Arc<ark_app::acp::Peer>>> = Arc::default();
    let approver = Arc::new(ark_app::acp::AcpApprover(slot.clone()));
    let c = build_agent(a, approver, false)?;
    let mut commands: Vec<(String, String)> = c.ext.as_ref().map(|e| e.commands.iter().map(|c| (c.name.clone(), c.description.clone())).collect()).unwrap_or_default();
    commands.extend([("new".to_string(), "開新對話".to_string()), ("compact".into(), "壓縮對話脈絡".into())]);
    let acp = ark_app::acp_client::AcpConfig::parse(&c.k.cfg.acp).map_err(Fail::Msg)?;
    let stdin = std::io::stdin();
    ark_app::acp::serve(c.k.clone(), commands, acp, slot, stdin.lock(), Box::new(std::io::stdout()));
    Ok(0)
}

/// Drive an external ACP agent (acpx-style): `ark acp-client claude "fix the tests"`.
fn cmd_acp_client(a: &Args) -> R {
    use ark_app::acp_client::{describe_update, render_turn, AcpClient, AcpConfig, PermissionMode};
    let paths = Paths::from_env();
    let ws = workspace(a)?;
    let cfg = load_config(a, &ws, &paths)?;
    let acp = AcpConfig::parse(&cfg.acp).map_err(Fail::Msg)?;
    if a.flag("list") {
        for n in acp.names() {
            let s = acp.agent(&n).map_err(Fail::Msg)?;
            println!("{n:<12} {}  {}", ark_app::acp_client::command_line(&s), s.description.unwrap_or_default());
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
    let ask: ark_app::acp_client::Asker = Arc::new(move |q: &str| match &tty {
        Some(t) => t.ask("", &format!("{q} [y/N]")).is_ok_and(|x| ark_app::acp_client::is_yes(&x)),
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
    SIGINTS.store(0, Ordering::SeqCst);
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
    let cancel = ark_core::Cancel::new();
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

/// Run this machine as a node of an ark app server.
fn cmd_node(a: &Args) -> R {
    let paths = Paths::from_env();
    // A setup code (from `ark nodes setup-code`) carries the URL, a one-time bootstrap token and
    // optionally the server's certificate fingerprint.
    let (url, bootstrap, tls_fingerprint) = match a.val("setup-code") {
        Some(code) => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
            let sc = ark_app::node::SetupCode::decode(code, now)?;
            (sc.url, Some(sc.bootstrap_token), sc.tls_fingerprint)
        }
        None => (a.val("url").ok_or("--url ws://host:8640/node (or --setup-code CODE) is required")?.to_string(), None, None),
    };
    let host = std::fs::read_to_string("/etc/hostname").unwrap_or_else(|_| "linux".into()).trim().to_string();
    let id = a.val("session").map(str::to_string).unwrap_or_else(|| format!("linux-{host}"));
    let policy_path = paths.config_dir.join("node.toml");
    let policy: ark_app::node::HostPolicy = match std::fs::read_to_string(&policy_path) {
        Ok(t) => toml::from_str(&t).map_err(|e| format!("{}: {e}", policy_path.display()))?,
        Err(_) => ark_app::node::HostPolicy { run: "deny".into(), read_roots: vec![workspace(a)?], ..Default::default() },
    };
    eprintln!("ark node: {id} → {url} (system.run: {}, policy file {})", if policy.run.is_empty() { "deny" } else { &policy.run }, policy_path.display());
    let token_path = paths.data.join("node.token");
    let mut backoff = 1u64;
    loop {
        // The bootstrap token is single use: once a device token exists it is not sent again.
        let conn = ark_app::node::HostConn { url: url.clone(), id: id.clone(), name: a.val("name").unwrap_or(&host).to_string(), key_path: paths.data.join("node.key"), token_path: token_path.clone(), bootstrap: bootstrap.clone(), tls_fingerprint: tls_fingerprint.clone() };
        match ark_app::node::run_host(&conn, &policy) {
            Ok(()) => return Ok(0),
            Err(e) => {
                eprintln!("ark node: {e}; retry in {backoff}s");
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
            let app = ark_app::AppConfig::parse(&cfg.app)?;
            if !app.nodes {
                eprintln!("ark: warning: [app] nodes = false; the app server will not accept nodes until you enable it");
            }
            let url = match a.val("url") {
                Some(u) => u.to_string(),
                None => {
                    let listen = app.listen.replace("0.0.0.0", &std::fs::read_to_string("/etc/hostname").unwrap_or_else(|_| "localhost".into()).trim().to_lowercase());
                    format!("ws://{listen}/node")
                }
            };
            let ttl = a.num::<u64>("ttl").map_err(Fail::Usage)?.unwrap_or(10) * 60_000;
            let mut p = json!({"url": url, "ttlMs": ttl});
            if let Some(f) = a.val("tls-fingerprint") {
                p["tlsFingerprint"] = json!(f);
            }
            let r = daemon::call(&sock, "node.setup.create", p)?;
            let code = r["code"].as_str().unwrap_or("");
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
                return Ok(0);
            }
            match ark_app::qr::Qr::encode(code.as_bytes()) {
                Some(q) => println!("{}", q.render(2)),
                None => eprintln!("(code is too long for a terminal QR code; copy it instead)"),
            }
            println!("setup code (valid {} min, single use) for {}:\n{code}\n\non the device: ark node --setup-code {code}", ttl / 60_000, r["url"].as_str().unwrap_or(""));
            return Ok(0);
        }
        other => return Err(format!("unknown nodes subcommand `{other}` (list, pending, approve <code>, reject <code>, remove <id>, describe <id>, rename <id> <name>, invoke <node> <command> [json] [--queue], queue [id], events [id], rotate <id>, wake <id> [status.request|location.request], setup-code [--url ws://…] [--ttl MIN] [--tls-fingerprint SHA256])").into()),
    };
    println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
    Ok(0)
}

/// App server helpers: token, open the UI, status.
fn cmd_app(a: &Args) -> R {
    let paths = Paths::from_env();
    let ws = workspace(a)?;
    let cfg = load_config(a, &ws, &paths)?;
    let vault = load_vault(&paths)?;
    let app = ark_app::AppConfig::parse(&cfg.app)?;
    let token = app.token.as_deref().map(|t| vault.substitute(t)).filter(|t| !t.contains("{{secret:")).unwrap_or_default();
    let url = format!("http://{}", app.listen);
    match a.pos(0).unwrap_or("status") {
        "token" => {
            if token.is_empty() {
                let t = ark_net::crypto::random_token(24);
                println!("尚未設定 token。最簡單是執行 `ark setup`；或手動：\n  echo {t} | ark secrets set APP_TOKEN\n然後在 config.toml 加上：\n  [app]\n  enabled = true\n  token = \"{{{{secret:APP_TOKEN}}}}\"");
            } else {
                println!("{token}");
            }
            Ok(0)
        }
        "open" => {
            if token.is_empty() {
                return Err("set [app] token first (`ark app token`)".into());
            }
            // The token travels in the fragment, which browsers never send to servers or logs.
            let link = format!("{url}/#token={token}");
            let opened = ["chromium", "google-chrome", "brave-browser"].iter().any(|b| std::process::Command::new(b).arg(format!("--app={link}")).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().is_ok());
            if !opened {
                let _ = std::process::Command::new("xdg-open").arg(&link).spawn();
            }
            println!("{url}");
            Ok(0)
        }
        "status" => {
            println!("[app] {} on {url} · ui {} · openai api {} · nodes {} · a2a {}", if app.enabled { "enabled" } else { "disabled" }, app.ui, app.openai_api, app.nodes, app.a2a.enabled);
            Ok(0)
        }
        other => Err(format!("unknown app subcommand `{other}` (token, open, status)").into()),
    }
}

/// DM pairing: approve the one-time codes unknown senders receive under `dm_policy = "pairing"`.
fn cmd_pairing(a: &Args) -> R {
    let paths = Paths::from_env();
    let p = ark_channel::access::Pairing::open(paths.data.join("channels").join("pairing.json"));
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

fn cmd_channel(a: &Args) -> R {
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            let c = build_agent(a, approver_for(a, false), false)?;
            let e = c.ext.as_ref().unwrap();
            if e.channels.is_empty() {
                println!("no channels (configure [channels.<name>] kind = \"telegram\", \"discord\", \"slack\", \"line\"… — see docs/config-example.toml)");
            }
            for (n, (_, cfg)) in &e.channels {
                let kind = serde_json::to_value(cfg).ok().and_then(|v| v["kind"].as_str().map(String::from)).unwrap_or_default();
                let r = cfg.router();
                let allow = &r.policy.allow;
                println!("{n:<16} {kind:<14} dm: {:?} · allow: {}", r.policy.dm_policy, if allow.is_empty() { "(nobody — set allow)".into() } else { allow.join(",") });
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
            ch.send(&ark_channel::Outbound { chat: chat.into(), text, reply_to: None, ..Default::default() }).map_err(|e| e.message)?;
            println!("sent");
            Ok(0)
        }
        other => usage(format!("unknown `channel {other}`")),
    }
}
