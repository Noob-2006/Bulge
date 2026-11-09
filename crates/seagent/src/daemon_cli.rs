//! `seagent daemon run|start|stop|status`, and the same `run` assembly for the in-process agent
//! the iOS app embeds ([`crate::embed`]): build the full agent, register every host ARP method,
//! start the App Server, then serve until stopped. Embedded, the daemon has no control socket
//! (`Ipc::Off`): the app talks to it through the App Server on 127.0.0.1 only.

use crate::args::Args;
use crate::{agentcmds, build_agent, ext, host_methods, ops, setup_web, slash, usage, PluginMount, HOST_METHODS, R};
use seagent_kernel::config::Paths;
use seagent_kernel::daemon::{self, Daemon, Ipc};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What the embedding app hears from [`run`] (`None` for `seagent daemon run`).
pub(crate) struct Embedded {
    /// Called once the App Server listens: the daemon (for scheduling queries) and its base URL
    /// (empty when `[app]` is disabled).
    pub on_ready: Box<dyn Fn(Arc<Daemon>, String) + Send + Sync>,
}

pub(crate) fn cmd_daemon(a: &Args) -> R {
    let paths = Paths::from_env();
    let sock = paths.socket();
    match a.pos(0).unwrap_or("status") {
        "run" => run(a, None),
        "start" => {
            if daemon::call(&sock, "ping", json!({})).is_ok() {
                println!("seagentd already running");
                return Ok(0);
            }
            std::fs::create_dir_all(&paths.data).map_err(|e| e.to_string())?;
            let log = seagent_core::platform::proc::open_child_log(&paths.daemon_log()).map_err(|e| e.to_string())?;
            let log_start = log.metadata().map(|m| m.len()).unwrap_or(0);
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
                    // What it said on the way out (the desktop app shows this in its splash).
                    let said = std::fs::read(paths.daemon_log()).ok().map(|b| String::from_utf8_lossy(&b[(log_start as usize).min(b.len())..]).lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect::<Vec<_>>()).unwrap_or_default();
                    let tail = said[said.len().saturating_sub(3)..].join("\n");
                    return Err(format!("seagentd exited during startup ({st}); see {}{}", paths.daemon_log().display(), if tail.is_empty() { String::new() } else { format!("\n{tail}") }).into());
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

/// `seagent daemon run`, or (with `embedded`) the in-process agent: the same kernel, host
/// methods, leader services and App Server; only the control socket and the process-level
/// bits (signal handlers, pid file, service bookkeeping, restart helper) are left out.
pub(crate) fn run(a: &Args, embedded: Option<&Embedded>) -> R {
    let paths = Paths::from_env();
    let (pending, cell) = daemon::pending_approver(Duration::from_secs(600));
    let mut c = build_agent(a, pending.clone(), true)?;
    // srv-017: `approvals.timeout_secs` is the wait, not a hard-coded 600 s.
    pending.set_timeout(Duration::from_secs(c.k.cfg.approvals.timeout_secs.max(1)));
    let ext_arc: Option<Arc<ext::Ext>> = c.ext.take().map(Arc::new);
    let _ = cell.set(Arc::downgrade(&c.k));
    if embedded.is_none() {
        eprintln!("seagentd {} listening on {}", env!("CARGO_PKG_VERSION"), paths.socket().display());
        if let Some(w) = ops::service::record_start(&paths) {
            eprintln!("seagentd: warning: {w}");
        }
    } else {
        eprintln!("seagentd {} running in-process (no control socket)", env!("CARGO_PKG_VERSION"));
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
            crate::hooks_ext::start_daemon_services(&k, &ws, t.clone());
            ops::backup::spawn_scheduler(paths2.clone(), k.cfg.backup.clone(), t.clone());
            surf.clone().and_then(|s| seagent_app::surfaces::spawn_daemon(s, t.clone()));
            *term.lock().unwrap() = Some(t);
        }));
    }
    d.add_methods(ops::ui_methods::methods(&paths, c.k.clone(), ext_arc.as_deref()));
    d.add_methods(ops::webui::methods(&paths, c.k.clone(), ext_arc.as_deref()));
    d.add_methods(ops::dock::methods(c.k.clone()));
    // Settings → Connections: MCP / skills / plugins / channels / agents set up from the console.
    d.add_methods(ops::connectors::methods(&paths, &c.k, ext_arc.as_deref()));
    d.add_methods(ops::channels_setup::methods(&paths, &c.k, ext_arc.as_deref()));
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
    let mut app_cfg = seagent_app::lan::effective(&seagent_app::AppConfig::parse(&c.k.cfg.app)?, &paths.data)?;
    if app_cfg.enabled {
        setup_web::move_off_busy_default_port(&paths, &mut app_cfg.listen);
    }
    d.add_methods(ops::lan::methods(&paths, c.k.clone(), app_cfg.clone()));
    let _server = if app_cfg.enabled {
        let token = app_cfg.token.as_deref().map(|t| (c.k.vault_substitute())(t)).unwrap_or_default();
        if token.contains("{{secret:") {
            return Err("[app] token references a secret that is not set (seagent secrets set APP_TOKEN …)".into());
        }
        let mut host: Vec<String> = seagent_app::node::METHODS.iter().map(|s| s.to_string()).collect();
        host.extend(HOST_METHODS.iter().chain(ops::ui_methods::METHODS).chain(ops::webui::METHODS).chain(ops::dock::METHODS).chain(ops::connectors::METHODS).chain(ops::channels_setup::METHODS).map(|s| s.to_string()));
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
        let listen = app_cfg.listen.clone();
        let srv = seagent_app::start(app).map_err(|e| match setup_web::who_listens(&listen).filter(|_| e.contains("cannot listen")) {
            Some(w) => format!("{e} — {w}. Stop it, or choose another port: seagent config set app.listen 127.0.0.1:<port>"),
            None => e,
        })?;
        let scheme = if srv.is_tls() { "https" } else { "http" };
        eprintln!("seagentd: app server on {scheme}://{} (UI, /arp, /v1, {})", srv.local_addr(), if app_cfg.a2a.enabled { "/a2a" } else { "no a2a" });
        let mdns = seagent_app::lan::advertise(&app_cfg, &paths.data).map_err(|e| eprintln!("seagentd: warning: {e}")).ok().flatten();
        if let Some(d) = mdns.as_ref().map(|r| r.status().detail.clone()).filter(|d| !d.is_empty()) {
            eprintln!("seagentd: warning: mDNS discovery limited: {d}");
        }
        if let Some(e) = embedded {
            (e.on_ready)(d.clone(), format!("{scheme}://{}", srv.local_addr()));
        }
        Some((srv, mdns))
    } else {
        if let Some(e) = embedded {
            (e.on_ready)(d.clone(), String::new());
        }
        None
    };
    let r = d.clone().run_with(if embedded.is_some() { Ipc::Off } else { Ipc::On });
    c.k.emit(seagent_kernel::hooks::HookEvent::DaemonStop, json!({"session_id": "", "cwd": c.workspace, "reason": "shutdown"}), "");
    stop.cancel();
    if let Some(t) = services {
        let _ = t.join();
    }
    r?;
    if embedded.is_none() && setup_web::restart_requested() {
        return Ok(setup_web::after_stop());
    }
    Ok(0)
}
