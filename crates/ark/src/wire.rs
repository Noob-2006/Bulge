//! Host wiring for the skills, memory and context subsystems: tools registered before the
//! kernel is built, and what is attached to it afterwards (lifecycle observers, native slash
//! commands, background work). Each subsystem owns its own `host` module; this file only
//! calls them so `main.rs` stays a dispatcher.

use ark_core::Tool;
use ark_kernel::config::{project_config, Config, Paths};
use ark_kernel::kernel::Kernel;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Extra tools for `build` / `build_agent`. Tools here replace builtins of the same name.
///
/// The list itself no longer lives here: every subsystem registers its own provider with
/// `ark_core::registry` (skills 100, memory 110, xAI code execution 150, cronjob 200, `[web]`
/// 300, web CLI 310, Google Meet 400, kanban 500, plugin media backends 600), and this
/// function only builds the [`HostEnv`] they read. Adding a tool therefore touches the
/// feature's own file, not this one (audit D1).
pub fn tools(cfg: &Config, paths: &Paths, ws: &Path) -> Vec<Arc<dyn Tool>> {
    // `[files]`: read budget, stale-write guard, lint and post-write security guidance
    // (Hermes `plugins/security-guidance`) for the builtin file tools.
    ark_tools::configure_files(&serde_json::to_value(&cfg.files).unwrap_or(serde_json::Value::Null));
    // Registration is idempotent; a caller that never dispatched a command (tests, `build`)
    // still gets the full set.
    crate::registry_init::register();
    let env = ark_core::registry::HostEnv::new(cfg, ws, paths.data.clone(), paths.config_dir.clone(), paths.runtime.clone());
    let (tools, warnings) = ark_core::registry::collect_tools(&env);
    for w in warnings {
        eprintln!("ark: warning: {w}");
    }
    tools
}

/// Merge `extra` into `tools`: an extra tool with a builtin's name replaces it.
pub fn merge_tools(tools: &mut Vec<Arc<dyn Tool>>, extra: Vec<Arc<dyn Tool>>) {
    for t in extra {
        let name = t.spec().name;
        tools.retain(|x| x.spec().name != name);
        tools.push(t);
    }
}

/// After the kernel exists.
pub fn attach(k: &Kernel, ws: &Path) {
    ark_kernel::ctxhost::attach(k, ws);
    ark_skills::host::attach(k, ws);
    ark_memory::host::attach(k, ws);
    crate::exec_cli::attach(k);
    // `/loop`, `/subgoal`, `/suggestions`; the chronos cron provider's fire endpoint when selected.
    k.add_slash(Arc::new(ark_kernel::cronjob::slash::AutomationSlash));
    ark_app::cron_fire::install(k);
    // Hooks declared by their own subsystem (`ark_kernel::hooks::register_provider`), e.g.
    // leaving a still-running Meet call when its session ends (upstream `on_session_end`).
    crate::registry_init::register();
    for w in ark_kernel::hooks::install_all(k) {
        eprintln!("ark: warning: hook {w}");
    }
    // `[meetings.teams]`: Graph change notifications become pipeline jobs, summaries go back to Teams.
    crate::meetings::teams::install(k, &k.cfg);
    // One `cron_execution` monitoring event per executed job (the scheduler lives in the kernel).
    ark_kernel::automation::set_exec_observer(crate::agentcmds::monitoring::cron_observer());
}

/// Commands this module owns (dispatched before the binary's own argument parser, since
/// they take their own flags). `argv` excludes the command word.
pub fn owns(cmd: &str, argv: &[String]) -> bool {
    let sub = argv.first().map(String::as_str).unwrap_or("");
    match cmd {
        "skills" | "skill" | "bundles" | "bundle" | "curator" | "journey" | "hub" => true,
        // `ark wiki …`: the compiled wiki vault lives in ark-memory.
        "wiki" => true,
        // `ark index status|sync|rebuild|bench`: the SQLite index (ark-kernel sqlindex + ark-memory).
        "index" => true,
        // `ark plugin` / `ark plugin list` stay in main.rs; lifecycle subcommands live in ark-skills.
        "plugin" | "plugins" => !(sub.is_empty() || sub == "list" || sub.starts_with('-')),
        // `ark memory show|add` stay in main.rs; `review`/`pending`/`accept`/`reject` come from
        // `ark-memory`, whose review also prints staged `ops` (patch) payloads.
        "memory" => !matches!(sub, "" | "show" | "add") && !sub.starts_with('-'),
        "sandbox" => true,
        "system" | "suggestions" | "web" => true,
        _ => false,
    }
}

pub fn cli(cmd: &str, argv: &[String]) -> Result<i32, String> {
    let paths = Paths::from_env();
    if cmd == "sandbox" {
        return crate::exec_cli::sandbox(argv, &paths);
    }
    let ws = workspace(argv)?;
    let cfg = Config::load(Some(&paths.user_config()), Some(&project_config(&ws)), &[])?;
    match cmd {
        "system" => crate::system_cli::system(argv, &paths, &cfg),
        "web" => crate::web_cli::cli(argv, &paths, &cfg),
        "suggestions" => crate::system_cli::suggestions(argv, &paths, &cfg, &ws),
        "memory" | "journey" | "wiki" | "index" => ark_memory::host::cli(cmd, argv, &cfg, &paths, &ws),
        _ => ark_skills::host::cli(cmd, argv, &cfg, &paths, &ws),
    }
}

/// `-w/--workspace <dir>` anywhere in argv, else the current directory.
fn workspace(argv: &[String]) -> Result<PathBuf, String> {
    let mut w = None;
    for (i, a) in argv.iter().enumerate() {
        if a == "-w" || a == "--workspace" {
            w = argv.get(i + 1).map(PathBuf::from);
        } else if let Some(v) = a.strip_prefix("--workspace=") {
            w = Some(PathBuf::from(v));
        }
    }
    let w = w.unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    w.canonicalize().map_err(|e| format!("workspace {}: {e}", w.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_core::{Cancel, ToolCtx, ToolHost};
    use std::io::{Read, Write};

    struct NoHost;
    impl ToolHost for NoHost {
        fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &Cancel) -> Result<String, String> {
            Err("no sub-agents in this test".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("no user in this test".into())
        }
    }

    fn temp_paths() -> Paths {
        let root = ark_core::tmp::scratch_path(format!("ark-wire-{}", ark_kernel::util::random_hex(6)));
        std::fs::create_dir_all(root.join("data")).unwrap();
        Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() }
    }

    fn tool_ctx(ws: PathBuf) -> ToolCtx {
        ToolCtx {
            artifacts: ws.join(".artifacts"),
            home: ws.join(".home"),
            workspace: ws,
            session_id: "wire".into(),
            cancel: Cancel::new(),
            host: Arc::new(NoHost),
            secrets: Arc::new(|s: &str| s.to_string()),
        }
    }

    /// The model's `meet_*` tools come from the Google Meet port (`[meetings.google_meet]`).
    #[test]
    fn meet_tools_are_registered() {
        let paths = temp_paths();
        let ws = paths.data.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let cfg = Config::default();
        let names: Vec<String> = tools(&cfg, &paths, &ws).iter().map(|t| t.spec().name).collect();
        for name in ["meet_join", "meet_status", "meet_transcript", "meet_leave", "meet_say"] {
            assert!(names.iter().any(|n| n == name), "{name} is not registered: {names:?}");
        }
    }

    /// `[kanban] enabled` is the one switch that puts the board tools on a session, and
    /// then both vocabularies are there (`kanban::tools::session_tools`).
    #[test]
    fn kanban_tools_follow_the_enabled_flag() {
        let paths = temp_paths();
        let ws = paths.data.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let off: Vec<String> = tools(&Config::default(), &paths, &ws).iter().map(|t| t.spec().name).collect();
        assert!(!off.iter().any(|n| n.starts_with("kanban_") || n.starts_with("workboard_")), "kanban is opt-in: {off:?}");
        let mut cfg = Config::default();
        cfg.kanban.enabled = true;
        let on: Vec<String> = tools(&cfg, &paths, &ws).iter().map(|t| t.spec().name).collect();
        for name in ["kanban_show", "kanban_create", "kanban_complete", "kanban_block", "workboard_read", "workboard_complete", "workboard_sessions_board_read"] {
            assert!(on.iter().any(|n| n == name), "{name} is not registered: {on:?}");
        }
        assert_eq!(on.iter().filter(|n| n.starts_with("kanban_")).count(), 15);
        assert_eq!(on.iter().filter(|n| n.starts_with("workboard_")).count(), 38);
    }

    /// `[web]` (an untyped table in `Config`) builds the web tools and replaces the
    /// default-config `web_fetch` builtin; the model's `web_search` is the configured one.
    #[test]
    fn web_section_reaches_the_models_tools() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let body = r#"{"results":[{"title":"Wired","url":"https://wired.example/1","content":"from the fake searxng"}]}"#;
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        let cfg = Config { web: toml::from_str(&format!("[search]\nprovider = \"searxng\"\n[providers.searxng]\nbase_url = \"{url}\"\n")).unwrap(), ..Default::default() };
        let ws = ark_core::tmp::scratch_path(format!("ark-wire-ws-{}", ark_kernel::util::random_hex(4)));
        std::fs::create_dir_all(&ws).unwrap();
        let extra = tools(&cfg, &temp_paths(), &ws);
        let names: Vec<String> = extra.iter().map(|t| t.spec().name).collect();
        assert!(names.iter().any(|n| n == "web_fetch") && names.iter().any(|n| n == "web_search") && names.iter().any(|n| n == "web_extract"), "{names:?}");
        let mut all = ark_tools::builtin_tools();
        merge_tools(&mut all, extra);
        for n in ["web_fetch", "web_search", "web_extract"] {
            assert_eq!(all.iter().filter(|t| t.spec().name == n).count(), 1, "{n} must be registered once");
        }
        let search = all.iter().find(|t| t.spec().name == "web_search").unwrap().clone();
        let out = search.call(&tool_ctx(ws), serde_json::json!({"query": "is [web] wired"}));
        assert!(!out.is_error, "{}", out.content);
        assert!(out.content.contains("wired.example") && out.content.contains("from the fake searxng"), "{}", out.content);
        assert!(out.content.contains("\"provider\": \"searxng\""), "{}", out.content);
    }

    /// An invalid `[web]` table is a warning at wiring time, never a lost tool set.
    #[test]
    fn bad_web_table_keeps_the_other_tools() {
        let cfg = Config { web: toml::from_str("bogus = 1").unwrap(), ..Default::default() };
        let t = tools(&cfg, &temp_paths(), ark_core::tmp::scratch("ark-ws").as_path());
        assert!(!t.iter().any(|x| x.spec().name == "web_search"), "the web tools are dropped, not guessed");
        let mut all = ark_tools::builtin_tools();
        merge_tools(&mut all, t);
        assert!(all.iter().any(|x| x.spec().name == "web_fetch"), "the builtin web_fetch stays");
    }

    /// `ark memory review` is served by `ark-memory` (it prints staged patch payloads too);
    /// `show`/`add` stay in the binary's own handler.
    #[test]
    fn memory_subcommands_route_to_the_memory_crate() {
        let argv = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        for sub in ["review", "pending", "accept", "reject", "status", "setup", "off", "reset", "query"] {
            assert!(owns("memory", &argv(&[sub])), "`ark memory {sub}` must reach ark-memory");
        }
        for sub in ["", "show", "add", "--help"] {
            assert!(!owns("memory", &argv(&[sub])), "`ark memory {sub}` is the binary's own");
        }
    }
}
