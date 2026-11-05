//! Agent-layer chat commands, tools and services (round-4 g4-D):
//!
//! * slash rows merged into `slash::defs()`: `/retry` (Hermes), `/session idle|max-age|unbind`,
//!   `/subagents list|info|log`, `/agents`, `/dashboard` (OpenClaw), `/kanban` (Hermes),
//!   `/workboard`, `/card` (OpenClaw Workboard);
//! * `ark kanban …` CLI ([`kanban::cli`]);
//! * tools: `session_status` ([`status`]), `conversations_list/send/turn` ([`conversations`]),
//!   `session_share` (`ark_app::session_share`), `logbook` (`ark_app::logbook`);
//! * the monitoring OTLP exporter ([`monitoring`], Hermes `agent/monitoring`).
//!
//! Everything a channel inbound needs (binding activity, idle/max-age expiry, conversation
//! directory, `conversations_turn` reply capture) goes through [`on_inbound`].

pub mod agents;
pub mod bindings;
pub mod conversations;
pub mod debounce;
pub mod kanban;
pub mod moa;
pub mod monitoring;
pub mod retry;
pub mod sessions;
pub mod status;
pub mod subagents;
pub mod workboard;

use crate::slash::{Ctx, Def, Reply};
use ark_kernel::config::Config;
use ark_kernel::event::EventKind;
use ark_kernel::kernel::Kernel;
use std::sync::Arc;

pub(crate) fn text(t: impl Into<String>) -> Result<Reply, String> {
    Ok(Reply { text: Some(t.into()), ..Default::default() })
}

pub(crate) fn sid<'a>(c: &'a Ctx) -> Result<&'a str, String> {
    c.session.as_deref().ok_or_else(|| "no session yet — send a message first".to_string())
}

pub(crate) fn one_line(s: &str, n: usize) -> String {
    let s: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>())
    } else {
        s
    }
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// ISO-8601 UTC for a unix-millis timestamp.
pub(crate) fn iso(ms: u64) -> String {
    let s = ark_kernel::util::fmt_time((ms / 1000) as i64, 0);
    format!("{}:{:02}Z", s.replace(' ', "T"), (ms / 1000) % 60)
}

pub const SLASH: &[Def] = &[
    Def { name: "retry", aliases: &[], args: "", help: "Retry the last message (resend it to the agent)", category: "Session", admin: false, local: false, run: retry::cmd_retry },
    Def { name: "session", aliases: &[], args: "idle <duration|off> | max-age <duration|off> | unbind", help: "Manage this chat's session binding and lifecycle (idle timeout, max age)", category: "Session", admin: false, local: false, run: bindings::cmd_session },
    Def { name: "subagents", aliases: &[], args: "[list|info <id|#>|log <id|#> [limit] [tools]|help]", help: "Inspect sub-agent runs of this session", category: "Session", admin: false, local: false, run: subagents::cmd_subagents },
    Def { name: "agents", aliases: &["tasks"], args: "", help: "List agents (sub-agent sessions) bound to this session", category: "Session", admin: false, local: false, run: subagents::cmd_agents },
    Def { name: "dashboard", aliases: &[], args: "[requirements]", help: "Create or update this session's dashboard", category: "Tools", admin: false, local: false, run: cmd_dashboard },
    Def { name: "kanban", aliases: &[], args: "[boards|list|show|create|assign|comment|complete|block|unblock|archive|dispatch|stats|…]", help: "Multi-profile collaboration board (tasks, links, comments)", category: "Tools", admin: false, local: false, run: kanban::cmd_kanban },
    Def { name: "workboard", aliases: &[], args: "[list|show <id>|create <title>|move <id> --status <s>|dispatch|help]", help: "List, create, inspect, and dispatch Workboard cards", category: "Tools", admin: false, local: false, run: workboard::cmd_workboard },
    Def { name: "card", aliases: &[], args: "[card id]", help: "Show a Workboard card (default: the card this session works on)", category: "Tools", admin: false, local: false, run: workboard::cmd_card },
    Def { name: "moa", aliases: &[], args: "[preset:] <prompt>", help: "Mixture of Agents: ask the preset's reference models, then act with its aggregator", category: "Session", admin: false, local: false, run: moa::cmd_moa },
    Def { name: "branch", aliases: &["fork"], args: "[--at N] [name]", help: "Fork this conversation into a new session and continue there", category: "Session", admin: false, local: false, run: cmd_branch },
    Def { name: "bg", aliases: &[], args: "<prompt>", help: "Run a prompt in a separate background session; the answer arrives here", category: "Session", admin: false, local: false, run: cmd_bg },
];

const DEFAULT_DASHBOARD_REQUEST: &str = "Create a dashboard for this session.";

/// OpenClaw `/dashboard`: run the dashboard operating skill (`control-ui` when one is
/// installed, else ark's built-in dashboard guidance) with the user's requirements.
pub fn dashboard_prompt(c: &Ctx, requirements: &str) -> Result<String, String> {
    let req = requirements.trim();
    let request = if req.is_empty() { DEFAULT_DASHBOARD_REQUEST.to_string() } else { format!("{DEFAULT_DASHBOARD_REQUEST}\n\nDashboard requirements:\n{req}") };
    // An installed `control-ui` skill wins (upstream routes through it).
    if let Some(Ok(r)) = c.k.run_slash(&format!("/control-ui {request}"), c.session.as_deref(), "chat") {
        if let Some(p) = r.prompt {
            return Ok(p);
        }
    }
    let specs = c.k.specs();
    if !specs.iter().any(|s| s.name == "dashboard") {
        return Err("Dashboard support is unavailable because the dashboard tool is not enabled for this agent (enable [surfaces] dashboards).".into());
    }
    Ok(format!(
        "[/dashboard] {request}\n\nUse the `dashboard` tool: start with action=read to see the current tabs and widgets, then create or update tabs (tab_create/tab_update) and place widgets (widget_put/widget_move/widget_resize). Put data reports in `session:report` widgets and live progress in `session:progress`; build custom HTML widgets with `show_widget` and reference them by name. Keep widget names stable so later updates replace them. Reply briefly with what the dashboard now shows."
    ))
}

fn cmd_dashboard(c: &Ctx, a: &str) -> Result<Reply, String> {
    let p = dashboard_prompt(c, a)?;
    Ok(Reply { text: Some("building the dashboard…".into()), prompt: Some(p), action: None })
}

/// `/branch [--at N] [name]` — fork this conversation into a new independent session and
/// continue there (Hermes `/branch`, alias `/fork`). `--at N` forks N user turns back; the
/// parent is ended as `branched`, exactly like upstream.
fn cmd_branch(c: &Ctx, a: &str) -> Result<Reply, String> {
    let id = sid(c)?;
    if c.k.is_running(id) {
        return Err("a turn is still running — stop it before branching".into());
    }
    let mut at: Option<u64> = None;
    let mut name = String::new();
    let mut toks = a.split_whitespace().peekable();
    while let Some(t) = toks.next() {
        if t == "--here" {
            continue; // CLI/chat has no threads: a branch is always in place
        }
        if let Some(v) = t.strip_prefix("--at=") {
            at = Some(v.parse().map_err(|_| format!("--at: `{v}` is not a number of turns"))?);
        } else if t == "--at" {
            let v = toks.next().ok_or("--at needs a number of turns")?;
            at = Some(v.parse().map_err(|_| format!("--at: `{v}` is not a number of turns"))?);
        } else {
            name = std::iter::once(t).chain(toks).collect::<Vec<_>>().join(" ");
            break;
        }
    }
    let new = c.k.branch(id, at)?;
    if !name.is_empty() {
        c.k.record(&new, EventKind::Title { title: name.clone() }).map_err(|e| e.to_string())?;
    }
    c.k.end_session(id, "branched");
    let title = if name.is_empty() { String::new() } else { format!(" ({name})") };
    Ok(Reply { text: Some(format!("branched to {new}{title} — this chat continues in the fork; the original stays as {id}")), prompt: None, action: Some(crate::slash::Action::Local("session".into(), new)) })
}

/// `/bg <prompt>` — run a prompt in a separate background session; the result is delivered
/// here later without touching this conversation (Hermes `/bg`).
fn cmd_bg(c: &Ctx, a: &str) -> Result<Reply, String> {
    let prompt = a.trim();
    if prompt.is_empty() {
        return Err("usage: /bg <prompt> — runs it in a separate background session".into());
    }
    let preview = one_line(prompt, 60);
    let sid = c.k.create_session(&c.workspace, None, None, Some(&format!("bg: {preview}"))).map_err(|e| e.to_string())?;
    c.k.submit(&sid, prompt, "bg").map_err(|e| e.to_string())?;
    let (k, notify, id) = (c.k.clone(), c.notify.clone(), sid.clone());
    std::thread::spawn(move || {
        let text = match k.run(&id, ark_kernel::kernel::RunOpts::default()) {
            Ok(o) => o.text,
            Err(e) => format!("error: {e}"),
        };
        if let Some(n) = notify {
            n(format!("[bg {id}] {}", one_line(&text, 4000)));
        }
    });
    Ok(Reply::text(format!("background task started in {sid}\n{preview}\nkeep chatting — the answer arrives here when it finishes")))
}

/// Host hook for every channel inbound, before routing: refresh the binding's activity and
/// auto-unbind an expired one (`/session idle|max-age`).
pub fn on_inbound(k: &Kernel, router: &ark_channel::router::Router, m: &ark_channel::Inbound) {
    bindings::on_inbound(k, router, m);
}

/// An accepted message about to be submitted: record its conversation and hand it to a
/// pending `conversations_turn` waiter. Returns true when the waiter consumed it.
pub fn on_submit(k: &Kernel, m: &ark_channel::Inbound) -> bool {
    conversations::observe(&k.paths, m);
    conversations::claim(m)
}

/// Which agent (and which registered user) a channel message belongs to: the routing
/// bindings' most specific match (`[agents.*]` + `[[bindings]]`, OpenClaw `src/routing`),
/// else the default agent; the sender's registry entry gives personal instructions.
pub fn inbound_identity(k: &Kernel, m: &ark_channel::Inbound) -> (String, Option<String>) {
    let cfg = k.cfg_now();
    let user = ark_kernel::agents::find_user(&k.paths, &m.channel, &m.sender).map(|u| u.id);
    let kind = if m.thread.is_some() { "thread" } else { match m.chat_type { ark_channel::ChatType::Direct => "direct", _ => "group" } };
    let bindings = ark_kernel::agents::bindings(&cfg, &k.paths);
    let default = ark_kernel::agents::default_agent(&cfg, &k.paths);
    let input = ark_kernel::agents::RouteInput { channel: &m.channel, account: &m.account, chat: &m.chat, sender: &m.sender, kind, user: user.as_deref() };
    let (agent, _matched_by) = ark_kernel::agents::route(&bindings, &default, &input);
    (agent, user)
}

/// Tools this module adds to `build_agent` (channels for the conversation tools).
pub fn tools(k: Arc<std::sync::OnceLock<Kernel>>, paths: &ark_kernel::config::Paths, cfg: &ark_kernel::config::Config, channels: std::collections::BTreeMap<String, Arc<dyn ark_channel::Channel>>) -> Vec<Arc<dyn ark_core::Tool>> {
    let mut v: Vec<Arc<dyn ark_core::Tool>> = vec![Arc::new(status::SessionStatus { k: k.clone() })];
    v.extend(conversations::tools(paths.clone(), channels));
    if ark_app::session_share::ShareConfig::parse(cfg).enabled {
        v.push(Arc::new(ark_app::session_share::SessionShareTool));
    }
    if ark_app::logbook::LogbookConfig::parse(cfg).enabled {
        v.push(Arc::new(ark_app::logbook::LogbookTool { k }));
    }
    v
}

/// After the kernel exists: start background services (monitoring exporter, logbook).
pub fn attach(k: &Kernel) {
    monitoring::attach(k);
}

/// Daemon-only services (arkd): the logbook capture/analysis loop.
pub fn start_daemon_services(k: &Kernel) {
    ark_app::logbook::start(k);
    monitoring::gateway_health(k, "gateway.start", Some("running"));
}


/// `ark agents|moa …` — the named-agent registry / routing bindings and the Mixture of Agents
/// presets. Both take their own flags (`--identity`, `--bind`, `--references`…), so they are
/// dispatched before the global `Args` parser sees them (like `ark kanban`).
pub fn agent_cli(cmd: &str, raw: &[String]) -> Result<i32, String> {
    let paths = ark_kernel::config::Paths::from_env();
    let out = match cmd {
        "agents" => agents::cli_raw(raw, &paths)?,
        "moa" => {
            let a = crate::args::Args::parse(raw).map_err(|e| format!("moa: {e}"))?;
            let cfg = Config::load(Some(&paths.user_config()), None, &[]).unwrap_or_default();
            moa::cli(&a, &paths, &cfg)?
        }
        other => return Err(format!("unknown command `{other}` (agents | moa)")),
    };
    if !out.trim().is_empty() {
        println!("{out}");
    }
    Ok(0)
}

/// Self-registration (`ark_core::registry`): `ark agents|moa …` (named agents, routing bindings,
/// MoA presets) and `ark kanban …` (board CLI over a built kernel). Both take their own flags,
/// so they are dispatched before the binary's argument parser sees `argv`.
pub fn register_routes() {
    ark_core::registry::register_command_route("agents,moa", None, agent_cli);
    ark_core::registry::register_command_route("kanban", None, kanban_cli);
}

fn kanban_cli(_cmd: &str, argv: &[String]) -> Result<i32, String> {
    let a = crate::args::Args::parse(&[])?;
    let c = crate::build(&a, crate::approver_for(&a, false)).map_err(|e| e.to_string())?;
    println!("{}", kanban::cli(&c.k, argv)?);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slash::{self, Surface};
    use crate::testkit::kit;

    pub(crate) fn ctx<'a>(k: &'a Kernel, ws: &std::path::Path, session: Option<String>) -> Ctx<'a> {
        Ctx { k, ext: None, session, workspace: ws.to_path_buf(), surface: Surface::Cli, sender: None, notify: None }
    }

    #[test]
    fn steer_command_reaches_the_running_turn_or_falls_back() {
        assert_eq!(slash::find("tell").unwrap().name, "steer", "`/tell` is the alias");
        let t = kit();
        let id = seed(&t.k, &t.ws, 1);
        let c = ctx(&t.k, &t.ws, Some(id.clone()));
        // Nothing is running: the text is sent as an ordinary message instead of being queue-injected.
        let r = slash::run(&c, "/steer also check the tests").unwrap();
        assert_eq!(r.prompt.as_deref(), Some("also check the tests"));
        assert!(r.text.unwrap().contains("nothing is running"));
        // A running turn gets the text injected at the next step (the kernel path, see
        // `runner::steering_mid_turn_and_interrupt`); a blank steer is a usage error.
        assert!(slash::run(&c, "/steer").unwrap().text.unwrap().contains("/steer: usage"));
    }

    #[test]
    fn inbound_identity_routes_by_binding_and_finds_the_user() {
        use ark_kernel::agents::{self, AgentDef};
        let t = kit();
        agents::add(&t.paths, "ops", AgentDef { name: "Ops".into(), model: "a/b".into(), ..Default::default() }).unwrap();
        agents::bind(&t.k.cfg_now(), &t.paths, agents::parse_bind("ops", "telegram", None).unwrap()).unwrap();
        let u = agents::user_add(&t.paths, "Amy").unwrap();
        agents::user_link(&t.paths, &u.id, "telegram", "42").unwrap();
        agents::user_set_instructions(&t.paths, &u.id, "Reply in 繁體中文.").unwrap();
        let m = ark_channel::Inbound { channel: "telegram".into(), chat: "c1".into(), sender: "42".into(), ..Default::default() };
        let (agent, user) = inbound_identity(&t.k, &m);
        assert_eq!((agent.as_str(), user.as_deref()), ("ops", Some(u.id.as_str())), "binding routes, registry identifies");
        // An unbound channel falls back to the default agent; an unknown sender has no profile.
        let other = ark_channel::Inbound { channel: "slack".into(), chat: "c2".into(), sender: "9".into(), ..Default::default() };
        assert_eq!(inbound_identity(&t.k, &other), ("main".to_string(), None));
    }

    #[test]
    fn output_schema_flag_wires_the_structured_output_tool() {
        assert!(crate::output_schema_arg("off").unwrap().is_none());
        assert_eq!(crate::output_schema_arg(r#"{"type":"object"}"#).unwrap().unwrap()["type"], "object");
        assert!(crate::output_schema_arg("{nope}").unwrap_err().contains("invalid JSON"));
        // Setting the contract makes the kernel expose `structured_output` for that session.
        let t = kit();
        let id = t.k.create_session(&t.ws, None, None, Some("schema")).unwrap();
        assert!(!t.k.specs().iter().any(|s| s.name == "structured_output"), "not a static tool");
        t.k.set_output_schema(&id, Some(serde_json::json!({"type":"object","required":["n"],"properties":{"n":{"type":"integer"}}}))).unwrap();
        let v = ark_kernel::projection::project(&t.k.store.read(&id).unwrap());
        assert!(v.output_schema.is_some(), "the run now has an output contract");
        t.k.set_output_schema(&id, None).unwrap();
        assert!(ark_kernel::projection::project(&t.k.store.read(&id).unwrap()).output_schema.is_none(), "`off` clears it");
    }

    #[test]
    fn agent_rows_are_registered_and_reachable() {
        for n in ["agents", "tasks", "moa", "branch", "fork", "bg"] {
            assert!(slash::find(n).is_some(), "/{n} registered");
        }
        assert_eq!(slash::find("tasks").unwrap().name, "agents", "`/tasks` is the Hermes alias of `/agents`");
        assert_eq!(slash::find("fork").unwrap().name, "branch");
    }

    /// Seed a conversation: `n` user turns, each with an assistant reply.
    fn seed(k: &Kernel, ws: &std::path::Path, turns: usize) -> String {
        let id = k.create_session(ws, None, None, Some("seed")).unwrap();
        let mut log = k.store.open(&id).unwrap();
        for i in 0..turns {
            log.append(ark_kernel::event::EventKind::Message { message: ark_core::Message::user(format!("q{i}")), usage: None, model: None, inbox: None }).unwrap();
            log.append(ark_kernel::event::EventKind::Message { message: ark_core::Message::assistant(format!("a{i}")), usage: None, model: None, inbox: None }).unwrap();
        }
        id
    }

    #[test]
    fn undo_rewinds_turns_and_branch_forks_the_conversation() {
        let t = kit();
        let id = seed(&t.k, &t.ws, 2);
        let c = ctx(&t.k, &t.ws, Some(id.clone()));
        // `/undo 1` backs up one user turn (Hermes `/undo N`), `/undo 0` is refused.
        let r = slash::run(&c, "/undo 1").unwrap();
        assert!(r.text.unwrap().contains("rewound 1 turn(s)"), "conversation rewind");
        let v = ark_kernel::projection::project(&t.k.store.read(&id).unwrap());
        assert_eq!(v.user_turns.len(), 1, "one turn is gone");
        assert!(slash::run(&c, "/undo 5").unwrap().text.unwrap().contains("cannot rewind 5"));
        // `/branch [name]` forks what is left and points the surface at the fork (the REPL switches).
        let c = ctx(&t.k, &t.ws, Some(id.clone()));
        let r = slash::run(&c, "/branch next idea").unwrap();
        let fork = match r.action {
            Some(slash::Action::Local(name, arg)) => {
                assert_eq!(name, "session");
                arg
            }
            other => panic!("expected a session switch, got {other:?}"),
        };
        let fv = ark_kernel::projection::project(&t.k.store.read(&fork).unwrap());
        assert_eq!(fv.title.as_deref(), Some("next idea"));
        assert_eq!(fv.messages.len(), 2, "the fork continues from the current history");
        assert!(r.text.unwrap().contains(&id), "the original session is named");
        // `/branch --at N` forks N user turns back (2 turns → keep the first exchange).
        let two = seed(&t.k, &t.ws, 2);
        let r = slash::run(&ctx(&t.k, &t.ws, Some(two)), "/branch --at 1").unwrap();
        let fork = match r.action {
            Some(slash::Action::Local(_, arg)) => arg,
            other => panic!("expected a session switch, got {other:?}"),
        };
        assert_eq!(ark_kernel::projection::project(&t.k.store.read(&fork).unwrap()).messages.len(), 2);
        assert!(slash::run(&ctx(&t.k, &t.ws, Some(fork)), "/branch --at 9").unwrap().text.unwrap().contains("cannot branch at 9"));
        // `/fork` is the alias and answers with the same switch action.
        let r = slash::run(&ctx(&t.k, &t.ws, Some(id.clone())), "/fork").unwrap();
        assert!(matches!(r.action, Some(slash::Action::Local(ref n, _)) if n == "session"));
    }

    #[test]
    fn bg_runs_the_prompt_in_a_separate_session_and_delivers_later() {
        let t = kit();
        let id = seed(&t.k, &t.ws, 1);
        let got = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = got.clone();
        let c = Ctx { k: &t.k, ext: None, session: Some(id.clone()), workspace: t.ws.clone(), surface: Surface::Cli, sender: None, notify: Some(Arc::new(move |m: String| sink.lock().unwrap().push(m))) };
        let r = slash::run(&c, "/bg summarise the release notes").unwrap();
        let text = r.text.unwrap();
        assert!(text.contains("background task started") && text.contains("summarise the release notes"), "{text}");
        // The side session exists and is independent of the chat's own history…
        let side = t.k.store.list().into_iter().find(|s| s.title.as_deref().is_some_and(|t| t.starts_with("bg: "))).expect("side session");
        assert_ne!(side.id, id);
        // …and its answer is delivered to the surface afterwards.
        for _ in 0..100 {
            if !got.lock().unwrap().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let out = got.lock().unwrap().clone();
        assert_eq!(out.len(), 1, "one delivery");
        assert!(out[0].starts_with(&format!("[bg {}]", side.id)) && out[0].contains("reply:"), "{}", out[0]);
        let chat = ark_kernel::projection::project(&t.k.store.read(&id).unwrap());
        assert_eq!(chat.messages.len(), 2, "the chat's own history is untouched");
        // Without a prompt it is a usage error.
        assert!(slash::run(&c, "/bg").unwrap().text.unwrap().contains("/bg: usage"));
    }

    #[test]
    fn rows_are_reachable_and_dashboard_routes_to_the_tool() {
        for n in ["retry", "session", "subagents", "agents", "dashboard", "kanban", "workboard", "card"] {
            assert!(slash::find(n).is_some(), "/{n} registered");
        }
        let t = kit();
        let c = ctx(&t.k, &t.ws, None);
        // The test kernel has no dashboard tool: the command says why instead of prompting.
        let r = slash::run(&c, "/dashboard sales by week").unwrap();
        assert!(r.text.unwrap().contains("dashboard tool"), "unavailable without the tool");
        let t = kit_tools(vec![Arc::new(FakeDash)]);
        let c = ctx(&t.k, &t.ws, None);
        let r = slash::run(&c, "/dashboard sales by week").unwrap();
        let p = r.prompt.unwrap();
        assert!(p.contains("Create a dashboard for this session.") && p.contains("Dashboard requirements:\nsales by week") && p.contains("`dashboard` tool"), "{p}");
    }

    pub(crate) struct NoHost;
    impl ark_core::ToolHost for NoHost {
        fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &ark_core::Cancel) -> Result<String, String> {
            Err("no".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("no".into())
        }
    }

    struct Res(Arc<crate::testkit::Echo>);
    impl ark_kernel::kernel::Resolver for Res {
        fn provider(&self, _: &str) -> Result<Arc<dyn ark_core::Provider>, String> {
            Ok(self.0.clone())
        }
    }

    /// `testkit::kit` plus extra tools.
    pub(crate) fn kit_tools(extra: Vec<Arc<dyn ark_core::Tool>>) -> crate::testkit::Kit {
        let t = kit();
        let mut tools = ark_tools::builtin_tools();
        tools.extend(extra);
        let echo = t.echo.clone();
        let k = ark_kernel::kernel::new_kernel(t.k.cfg.clone(), t.paths.clone(), Arc::new(Res(echo.clone())), tools, Arc::new(ark_kernel::vault::Vault::empty()), Arc::new(ark_kernel::approver::Policy { allow_privilege: false, allow_egress: false }));
        crate::testkit::Kit { k, ws: t.ws, paths: t.paths, echo }
    }

    struct FakeDash;
    impl ark_core::Tool for FakeDash {
        fn spec(&self) -> ark_core::ToolSpec {
            ark_core::ToolSpec { name: "dashboard".into(), description: "d".into(), input_schema: serde_json::json!({"type": "object"}), parallel_safe: false, idempotent: false, pinned: false }
        }
        fn effects(&self, _: &ark_core::ToolCtx, _: &serde_json::Value) -> Vec<ark_core::Effect> {
            vec![]
        }
        fn call(&self, _: &ark_core::ToolCtx, _: serde_json::Value) -> ark_core::ToolOutput {
            ark_core::ToolOutput::ok("")
        }
    }
}
