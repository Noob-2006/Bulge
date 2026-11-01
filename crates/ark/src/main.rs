mod args;
mod ext;
mod providers;
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
  ark mcp list | tools [server] | test <server> | refresh <server> | add <name> (--url U | -- cmd args…) | rm <name> | serve
  ark plugin list                      plugins and what they provide (tools, hooks, channels)
  ark channel list | send <channel> <chat> <text…>
  ark commands                         custom /commands and MCP prompts
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

fn dispatch(raw: Vec<String>) -> R {
    let Some(cmd) = raw.first().cloned() else {
        println!("{HELP}");
        return Ok(0);
    };
    let a = Args::parse(&raw[1..]).map_err(Fail::Usage)?;
    if a.flag("help") {
        println!("{HELP}");
        return Ok(0);
    }
    match cmd.as_str() {
        "help" | "--help" | "-h" => {
            println!("{HELP}");
            Ok(0)
        }
        "version" | "--version" | "-V" => {
            println!("ark {} (log v{}, protocol v{})", env!("CARGO_PKG_VERSION"), ark_kernel::event::LOG_VERSION, daemon::PROTOCOL_VERSION);
            Ok(0)
        }
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
        "commands" | "command" => {
            let c = build_agent(&a, approver_for(&a, false), false)?;
            let defs = &c.ext.as_ref().unwrap().commands;
            if defs.is_empty() {
                println!("no commands (add Markdown files to .ark/commands/ or ~/.claude/commands/)");
            }
            for d in defs {
                println!("/{:<20} {}  ({})", d.name, d.description, d.path.display());
            }
            for p in c.ext.as_ref().unwrap().registry.prompts() {
                println!("/mcp__{}__{:<10} {}", p.server, p.name, p.description);
            }
            Ok(0)
        }
        other => usage(format!("unknown command `{other}`")),
    }
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
    let resolver: Arc<dyn Resolver> = Arc::new(Providers::new(&cfg.providers, vault.clone())?);
    let (ext, extra, hooks) = ext::load(&cfg, &paths, &vault, &ws, with_channels);
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
    tools.retain(|t| !disabled.contains(&t.spec().name));
    let k = new_kernel(cfg, paths.clone(), resolver, tools, vault, approver);
    k.add_hooks(hooks);
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
        eprintln!("• {} · {} tokens · {:.1}s · session {id}", term::one_line(&o.reason.label(), 120), o.usage.total(), started.elapsed().as_secs_f32());
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
    let prompt = expand_prompt(&c, &prompt)?;
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
                "help" => eprintln!("/model provider/model · /compact · /status · /undo [id] · /new · /commands · /<custom command> · /exit"),
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
                    id = c.k.create_session(&c.workspace, None, None, Some("chat")).map_err(|e| e.to_string())?;
                    eprintln!("• new session {id}");
                }
                "commands" => {
                    for d in c.ext.iter().flat_map(|e| e.commands.iter()) {
                        eprintln!("/{} — {}", d.name, d.description);
                    }
                }
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
            let r = Arc::new(Daemon::new(c.k, pending)).run();
            stop.cancel();
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
            let req = ark_core::ModelRequest { model: m.into(), system: vec![], messages: vec![ark_core::Message::user("Reply with exactly: pong")], tools: vec![], max_tokens: 2048, temperature: None, cache_after_message: None };
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
            let tools: Vec<Arc<dyn ark_core::Tool>> = ark_tools::builtin_tools().into_iter().filter(|t| !matches!(t.spec().name.as_str(), "spawn" | "ask_user")).collect();
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
            let info = ark_plugin::ServerInfo { name: "ark".into(), version: env!("CARGO_PKG_VERSION").into(), instructions: Some("Ark's file, search, shell and memory tools. Calls pass Ark's privilege and egress gates.".into()) };
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
        println!("{:<16} {tools} tools · hooks: {} · channels: {}", p.name, if p.hooks().is_empty() { "-".into() } else { p.hooks().join(",") }, if p.channels().is_empty() { "-".into() } else { p.channels().join(",") });
    }
    Ok(0)
}

fn cmd_channel(a: &Args) -> R {
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            let c = build_agent(a, approver_for(a, false), false)?;
            let e = c.ext.as_ref().unwrap();
            if e.channels.is_empty() {
                println!("no channels (configure [channels.<name>] kind = \"telegram\" | \"webhook\" | \"plugin\")");
            }
            for (n, (_, cfg)) in &e.channels {
                let kind = serde_json::to_value(cfg).ok().and_then(|v| v["kind"].as_str().map(String::from)).unwrap_or_default();
                let r = cfg.router();
                println!("{n:<16} {kind:<9} allow: {}", if r.allow.is_empty() { "(nobody — set allow)".into() } else { r.allow.join(",") });
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
            ch.send(&ark_channel::Outbound { chat: chat.into(), text, reply_to: None }).map_err(|e| e.message)?;
            println!("sent");
            Ok(0)
        }
        other => usage(format!("unknown `channel {other}`")),
    }
}
