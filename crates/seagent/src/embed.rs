//! The in-process agent: what the iOS app links instead of spawning `seagent daemon run`
//! (iOS allows no child processes). [`start`] runs the very same daemon assembly as the binary
//! (`daemon_cli::run`: kernel, sessions, providers, memory, skills, MCP over HTTP/SSE, chat
//! channels, cron, the App Server on 127.0.0.1) on background threads of the calling process;
//! only the control socket is left out — the app's WebView talks to the App Server like a
//! desktop browser does. [`stop`] drains it; [`background_pass`] is what a BGProcessingTask
//! calls while the app is woken in the background.
//!
//! State is process-wide (one agent per process), configured through the same environment the
//! binary reads: `SEAGENT_HOME` (the app's Application Support directory), `SEAGENT_VAULT_KEY`
//! (from the iOS Keychain), `SEAGENT_SHARE_DIR` (bundled skills / UI). See docs/cross-platform.md.

use crate::args::Args;
use crate::daemon_cli::{self, Embedded};
use seagent_kernel::config::Paths;
use seagent_kernel::daemon::Daemon;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How to run the embedded agent.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// `SEAGENT_HOME`: config, data, cache, logs and runtime all live under it.
    pub home: PathBuf,
    /// The vault key (32 bytes, hex or base64), kept by the host in the platform keystore.
    /// `None` keeps whatever `SEAGENT_VAULT_KEY` already holds.
    pub vault_key: Option<String>,
    /// Bundled `share/` (skills, web UI assets), when the host ships one.
    pub share_dir: Option<PathBuf>,
    /// The agent's default workspace; `<home>/workspace` when `None`.
    pub workspace: Option<PathBuf>,
    /// Extra `--set key=value` overrides for this run (tests, host policy).
    pub set: Vec<String>,
}

/// Where the console is: `base` = `http://127.0.0.1:<port>`, `url` = what the WebView opens
/// (the one-time setup wizard until setup is done, then the console with its token in the
/// fragment — never sent to a server or a log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Console {
    pub base: String,
    pub url: String,
    pub setup: bool,
}

/// What one background pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pass {
    /// Work was still running when the budget ran out (it resumes on the next pass / launch).
    pub unfinished: bool,
    /// Unix seconds of the earliest enabled scheduled job, for the next BGTask request.
    pub next_due: Option<i64>,
}

struct Running {
    thread: JoinHandle<()>,
    daemon: Arc<Mutex<Option<Arc<Daemon>>>>,
    base: Arc<Mutex<String>>,
    opts: Options,
}

static STATE: Mutex<Option<Running>> = Mutex::new(None);

fn workspace_of(o: &Options) -> PathBuf {
    o.workspace.clone().unwrap_or_else(|| o.home.join("workspace"))
}

fn args_for(o: &Options) -> Result<Args, String> {
    let mut raw = vec!["run".to_string(), "--workspace".to_string(), workspace_of(o).display().to_string()];
    for s in &o.set {
        raw.push("--set".into());
        raw.push(s.clone());
    }
    Args::parse(&raw)
}

/// Is the embedded agent running in this process?
pub fn running() -> bool {
    STATE.lock().unwrap().as_ref().is_some_and(|r| !r.thread.is_finished())
}

/// Start the agent in this process (idempotent: a running agent just reports its console).
/// Returns once the App Server accepts connections.
pub fn start(opts: Options) -> Result<Console, String> {
    let mut st = STATE.lock().unwrap();
    if let Some(r) = st.as_ref() {
        if !r.thread.is_finished() {
            let base = r.base.lock().unwrap().clone();
            drop(st);
            return console_at(&base);
        }
    }
    if opts.home.as_os_str().is_empty() {
        return Err("embed: no home directory given".into());
    }
    std::fs::create_dir_all(&opts.home).map_err(|e| format!("{}: {e}", opts.home.display()))?;
    std::fs::create_dir_all(workspace_of(&opts)).map_err(|e| format!("{}: {e}", workspace_of(&opts).display()))?;
    // One agent per process, configured exactly like the binary: through its environment. Set
    // before any thread of ours reads it.
    std::env::set_var("SEAGENT_HOME", &opts.home);
    if let Some(k) = opts.vault_key.as_deref().filter(|k| !k.trim().is_empty()) {
        std::env::set_var(seagent_kernel::secretstore::ENV_KEY, k.trim());
    }
    if let Some(s) = &opts.share_dir {
        std::env::set_var("SEAGENT_SHARE_DIR", s);
    }
    crate::registry_init::register();
    // No `--yolo` in an app: approvals go to the console like on a desktop daemon.
    seagent_security::approvals::freeze_process_yolo(false);
    let paths = Paths::from_env();
    std::fs::create_dir_all(&paths.data).map_err(|e| format!("{}: {e}", paths.data.display()))?;
    // `[app] enabled` + a loopback listener + a minted console token (idempotent).
    crate::setup_web::bootstrap(&paths, None)?;
    let args = args_for(&opts)?;

    let daemon: Arc<Mutex<Option<Arc<Daemon>>>> = Arc::default();
    let base: Arc<Mutex<String>> = Arc::default();
    let (tx, rx) = mpsc::channel::<Result<String, String>>();
    let (d2, b2) = (daemon.clone(), base.clone());
    let thread = std::thread::Builder::new()
        .name("seagent-embed".into())
        .spawn(move || {
            let tx = Mutex::new(Some(tx));
            loop {
                let (d3, b3, tx3) = (d2.clone(), b2.clone(), tx.lock().unwrap().clone());
                let embedded = Embedded {
                    on_ready: Box::new(move |d, url| {
                        *d3.lock().unwrap() = Some(d);
                        *b3.lock().unwrap() = url.clone();
                        if let Some(t) = &tx3 {
                            let _ = t.send(Ok(url));
                        }
                    }),
                };
                let r = daemon_cli::run(&args, Some(&embedded));
                *d2.lock().unwrap() = None;
                if let Err(e) = &r {
                    eprintln!("seagent: embedded agent stopped: {e}");
                    if let Some(t) = tx.lock().unwrap().take() {
                        let _ = t.send(Err(e.to_string()));
                    }
                }
                // The setup wizard applied a new config: run again with it (what the service
                // manager does for the binary). Anything else is a real stop.
                if r.is_ok() && crate::setup_web::take_restart() {
                    // Only the first start reports to `start()`; later ones are silent.
                    tx.lock().unwrap().take();
                    continue;
                }
                break;
            }
        })
        .map_err(|e| format!("embed: cannot start the agent thread: {e}"))?;
    *st = Some(Running { thread, daemon, base, opts });
    drop(st);
    let url = match rx.recv_timeout(Duration::from_secs(120)) {
        Ok(Ok(u)) => u,
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err("embed: the agent did not come up within 120 s".into()),
    };
    if url.is_empty() {
        return Err("embed: [app] is disabled in the configuration, so there is no console to show".into());
    }
    wait_listening(&url, Duration::from_secs(10))?;
    console_at(&url)
}

/// TCP connect to the App Server (it bound before reporting ready; this guards a slow accept loop).
fn wait_listening(base: &str, limit: Duration) -> Result<(), String> {
    let hostport = base.split("://").nth(1).unwrap_or(base).trim_end_matches('/');
    let addr: std::net::SocketAddr = hostport.parse().map_err(|_| format!("embed: unexpected console address {base}"))?;
    let until = Instant::now() + limit;
    while Instant::now() < until {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!("embed: nothing answers at {base}"))
}

/// The console of the running agent (a fresh one-time setup link while setup is not done).
pub fn console() -> Result<Console, String> {
    let base = STATE.lock().unwrap().as_ref().map(|r| r.base.lock().unwrap().clone()).unwrap_or_default();
    if base.is_empty() {
        return Err("embed: the agent is not running".into());
    }
    console_at(&base)
}

fn console_at(base: &str) -> Result<Console, String> {
    let paths = Paths::from_env();
    if !crate::setup_web::locked(&paths) {
        let (token, _) = crate::setup_web::issue(&paths, 30 * 60, false)?;
        return Ok(Console { base: base.into(), url: format!("{base}/setup#token={token}"), setup: true });
    }
    let opts = STATE.lock().unwrap().as_ref().map(|r| r.opts.clone()).unwrap_or_default();
    let a = args_for(&opts)?;
    let ws = workspace_of(&opts);
    let cfg = crate::load_config(&a, &ws, &paths).map_err(|e| e.to_string())?;
    let vault = crate::load_vault(&paths).map_err(|e| e.to_string())?;
    let app = seagent_app::AppConfig::parse(&cfg.app)?;
    let token = app.token.as_deref().map(|t| vault.substitute(t)).filter(|t| !t.is_empty() && !t.contains("{{secret:")).ok_or("embed: no [app] token is configured")?;
    Ok(Console { base: base.into(), url: format!("{base}/#token={token}"), setup: false })
}

/// Stop the agent: interrupt running turns (their logs stay consistent), wait up to `limit`.
/// Returns whether it is down.
pub fn stop(limit: Duration) -> bool {
    let Some(r) = STATE.lock().unwrap().take() else { return true };
    Daemon::stop();
    let until = Instant::now() + limit;
    while !r.thread.is_finished() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(50));
    }
    let done = r.thread.is_finished();
    if done {
        let _ = r.thread.join();
    } else {
        // Keep the handle so `running()` stays honest until it is down.
        *STATE.lock().unwrap() = Some(r);
    }
    done
}

/// Earliest `next_run` of the enabled scheduled jobs (unix seconds).
pub fn next_due() -> Option<i64> {
    let data = Paths::from_env().data;
    seagent_kernel::automation::read_list::<seagent_kernel::automation::Job>(&seagent_kernel::automation::jobs_path(&data)).ok()?.into_iter().filter(|j| j.enabled).map(|j| j.next_run).min()
}

/// One background pass (iOS BGProcessingTask): the agent must already be running (the host
/// calls [`start`] first). Its scheduler claims whatever became due while the app was
/// suspended; this waits for that work — scheduled jobs, goals and every running turn — to
/// finish, at most `budget`. Unfinished work is not lost: an open turn resumes on the next
/// start, a claimed job on the next pass.
pub fn background_pass(budget: Duration) -> Pass {
    let until = Instant::now() + budget;
    let daemon = STATE.lock().unwrap().as_ref().and_then(|r| r.daemon.lock().unwrap().clone());
    let Some(d) = daemon else { return Pass { unfinished: false, next_due: next_due() } };
    // One scheduler tick (plus slack) so jobs that came due while suspended are claimed.
    let tick = Duration::from_secs(d.k.cfg.schedule.tick_secs.max(1)) + Duration::from_millis(500);
    std::thread::sleep(tick.min(budget));
    let unfinished = loop {
        if d.busy() == 0 && d.k.running_ids().is_empty() {
            break false;
        }
        if Instant::now() >= until {
            break true;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    Pass { unfinished, next_due: next_due() }
}

/// Test support for `tests/embed_inprocess.rs` (not part of the app contract).
#[doc(hidden)]
pub fn mark_setup_done_for_tests() {
    crate::setup_web::mark_done(&Paths::from_env(), "test");
}
