//! `seagent gateway multiplex` (Hermes `gateway.multiplex_profiles`,
//! `gateway_multiplex_mode.py` / `gateway_runtime_multiplex.py`): one supervising
//! process per host serves every profile, so profiles never run competing gateways
//! (two pollers on one bot token, port fights).
//!
//! - `plan [--json]` runs the preflight: which profiles would be served, which are
//!   standalone (`"standalone": true` in the profile's `profile.json`, the temporary
//!   per-profile shim), and blockers — a bot/app token or listen address shared by two
//!   served profiles, or a profile daemon already running outside the multiplexer.
//! - `run [--force]` refuses on blockers (unless `--force`), then starts and supervises
//!   one `seagent -p <profile> daemon run` per served profile (crash → restart with
//!   backoff, at most 5 restarts in 10 minutes per profile), records
//!   `gateway_state.json` (`served_profiles`, pid) in the default profile's data dir and
//!   stops all children on SIGINT/SIGTERM.
//! - `status [--json]` reads the recorded state and pings each served daemon.

use crate::args::Args;
use crate::R;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const COMMANDS: &[&str] = &["gateway"];
pub const VALUE_FLAGS: &[&str] = &[];
pub const BOOL_FLAGS: &[&str] = &["force"];

const SINGLE: &str = "only one profile exists (nothing to multiplex)";
const MAX_RESTARTS: usize = 5;
const RESTART_WINDOW: Duration = Duration::from_secs(600);

/// One profile's facts for the preflight.
#[derive(Debug, Clone, Default)]
pub struct ProfileFacts {
    pub name: String,
    pub config: String,
    pub standalone: bool,
    /// A daemon answers on this profile's socket and it is not ours.
    pub running_elsewhere: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Plan {
    pub served: Vec<String>,
    pub standalone: Vec<String>,
    pub blockers: Vec<String>,
    pub note: Option<String>,
}

const TOKEN_KEYS: &[&str] = &["token", "bot_token", "app_token", "access_token", "api_key"];
const LISTEN_KEYS: &[&str] = &["listen", "webhook_listen"];

pub fn plan(profiles: &[ProfileFacts]) -> Plan {
    let mut p = Plan { served: vec![], standalone: vec![], blockers: vec![], note: None };
    let mut tokens: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut listens: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for f in profiles {
        if f.standalone {
            p.standalone.push(f.name.clone());
            continue;
        }
        p.served.push(f.name.clone());
        if f.running_elsewhere {
            p.blockers.push(format!("profile {} already runs its own daemon; stop it (`seagent -p {} daemon stop`) so the multiplexer can own it", f.name, f.name));
        }
        let t: toml::Table = match f.config.parse() {
            Ok(t) => t,
            Err(e) => {
                p.blockers.push(format!("profile {}: config.toml does not parse ({})", f.name, e.message()));
                continue;
            }
        };
        for (ch, v) in t.get("channels").and_then(|c| c.as_table()).into_iter().flatten() {
            let Some(ct) = v.as_table() else { continue };
            let kind = ct.get("kind").and_then(|k| k.as_str()).unwrap_or("?");
            for k in TOKEN_KEYS {
                if let Some(tok) = ct.get(*k).and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                    tokens.entry(format!("{kind}:{tok}")).or_default().push(format!("{}.{ch}", f.name));
                }
            }
            for k in LISTEN_KEYS {
                if let Some(l) = ct.get(*k).and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                    listens.entry(l.to_string()).or_default().push(format!("{}.{ch}", f.name));
                }
            }
        }
    }
    for (k, users) in tokens.iter().filter(|(_, u)| u.len() > 1) {
        let kind = k.split(':').next().unwrap_or("");
        p.blockers.push(format!("one {kind} bot token is configured in {} — two pollers on one token would fight; give each profile its own bot", users.join(" and ")));
    }
    for (l, users) in listens.iter().filter(|(_, u)| u.len() > 1) {
        p.blockers.push(format!("listen address {l} is used by {}", users.join(" and ")));
    }
    if profiles.len() <= 1 {
        p.note = Some(SINGLE.into());
    }
    p
}

/// Does a daemon answer for this profile? (`seagent [-p NAME] health`, which resolves the
/// profile's socket exactly as the daemon does.)
pub fn profile_running(name: &str) -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let mut c = Command::new(exe);
    c.env_remove("SEAGENT_HOME").env_remove("SEAGENT_PROFILE").stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    if name != "default" {
        c.args(["-p", name]);
    }
    c.arg("health").status().is_ok_and(|s| s.success())
}

fn pid_alive(pid: i64) -> bool {
    // SAFETY: signal 0 only checks existence/permission.
    pid > 0 && unsafe { libc::kill(pid as i32, 0) } == 0
}

pub fn facts() -> Vec<ProfileFacts> {
    let st: Value = std::fs::read_to_string(state_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}));
    let ours: Vec<String> = if st["pid"].as_i64().is_some_and(pid_alive) { st["served_profiles"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect() } else { vec![] };
    crate::ops::profile::list()
        .into_iter()
        .map(|name| {
            let (config_dir, _) = crate::ops::profile::home_of(&name);
            let meta = crate::ops::profile::meta(&name);
            let running = !ours.contains(&name) && profile_running(&name);
            ProfileFacts { config: std::fs::read_to_string(config_dir.join("config.toml")).unwrap_or_default(), standalone: meta["standalone"] == true, running_elsewhere: running, name }
        })
        .collect()
}

fn state_path() -> PathBuf {
    crate::ops::profile::home_of("default").1.join("gateway_state.json")
}

pub fn plan_text(p: &Plan) -> String {
    let mut o = format!("serves: {}\n", if p.served.is_empty() { "(none)".into() } else { p.served.join(", ") });
    if !p.standalone.is_empty() {
        o.push_str(&format!("standalone (own daemon, temporary shim): {}\n", p.standalone.join(", ")));
    }
    if let Some(n) = &p.note {
        o.push_str(&format!("note: {n}\n"));
    }
    if p.blockers.is_empty() {
        o.push_str("preflight: ok — `seagent gateway multiplex run` can serve these profiles\n");
    } else {
        o.push_str("preflight: blocked\n");
        for b in &p.blockers {
            o.push_str(&format!("  - {b}\n"));
        }
    }
    o
}

/// A supervised child: name, how to (re)spawn it, its restart history.
pub struct Slot {
    pub name: String,
    pub spawn: Box<dyn Fn() -> std::io::Result<Child> + Send>,
    pub child: Option<Child>,
    pub restarts: Vec<Instant>,
    pub gave_up: bool,
}

fn term(c: &mut Child) {
    // SAFETY: plain kill(2) on a pid we spawned.
    unsafe {
        libc::kill(c.id() as i32, libc::SIGTERM);
    }
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if c.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = c.kill();
    let _ = c.wait();
}

/// Run until `stop`: keep every slot alive (bounded restarts), then stop them all.
pub fn supervise(slots: &mut [Slot], stop: &AtomicBool, tick: Duration, log: &mut dyn FnMut(String)) {
    for s in slots.iter_mut() {
        match (s.spawn)() {
            Ok(c) => s.child = Some(c),
            Err(e) => log(format!("{}: could not start: {e}", s.name)),
        }
    }
    while !stop.load(Ordering::SeqCst) {
        for s in slots.iter_mut() {
            let exited = match s.child.as_mut() {
                Some(c) => c.try_wait().ok().flatten(),
                None => None,
            };
            if let Some(st) = exited {
                s.child = None;
                let now = Instant::now();
                s.restarts.retain(|t| now.duration_since(*t) < RESTART_WINDOW);
                if s.restarts.len() >= MAX_RESTARTS {
                    if !s.gave_up {
                        log(format!("{}: exited ({st}) {MAX_RESTARTS} times in {} minutes; not restarting", s.name, RESTART_WINDOW.as_secs() / 60));
                        s.gave_up = true;
                    }
                    continue;
                }
                s.restarts.push(now);
                log(format!("{}: exited ({st}); restarting", s.name));
                match (s.spawn)() {
                    Ok(c) => s.child = Some(c),
                    Err(e) => log(format!("{}: could not restart: {e}", s.name)),
                }
            }
        }
        std::thread::sleep(tick);
    }
    for s in slots.iter_mut() {
        if let Some(mut c) = s.child.take() {
            term(&mut c);
        }
    }
}

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "gateway" {
        return None;
    }
    match a.pos(0) {
        Some("multiplex") => {}
        // Hermes' bare `gateway run|status|list` lives under `seagent daemon`/`seagent health` here; the
        // only gateway surface in this module is the multiplexer, so say so.
        None => return Some(crate::usage("usage: seagent gateway multiplex (plan [--json] | run [--force] | status [--json])")),
        _ => return None,
    }
    Some((|| -> R {
        let js = a.flag("json");
        match a.pos(1).unwrap_or("plan") {
            "plan" => {
                let p = plan(&facts());
                if js {
                    println!("{}", serde_json::to_string_pretty(&p).unwrap_or_default());
                } else {
                    print!("{}", plan_text(&p));
                }
                Ok(if p.blockers.is_empty() { 0 } else { 1 })
            }
            "status" => {
                let st: Value = std::fs::read_to_string(state_path()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(json!({}));
                let served: Vec<String> = st["served_profiles"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(String::from)).collect();
                let live: Vec<Value> = served.iter().map(|n| json!({"profile": n, "running": profile_running(n)})).collect();
                if js {
                    println!("{}", json!({"state": st, "profiles": live}));
                } else if served.is_empty() {
                    println!("no multiplexer has run on this host (start one with `seagent gateway multiplex run`)");
                } else {
                    println!("multiplexer pid {} serving {}", st["pid"], served.join(", "));
                    for l in live {
                        println!("  {:<20} {}", l["profile"].as_str().unwrap_or(""), if l["running"] == true { "running" } else { "down" });
                    }
                }
                Ok(0)
            }
            "run" => {
                let p = plan(&facts());
                if !p.blockers.is_empty() && !a.flag("force") {
                    eprint!("{}", plan_text(&p));
                    return Err("multiplex preflight failed; fix the blockers above or pass --force".into());
                }
                let exe = std::env::current_exe().map_err(|e| e.to_string())?;
                let mut slots: Vec<Slot> = p
                    .served
                    .iter()
                    .map(|n| {
                        let (exe, n2) = (exe.clone(), n.clone());
                        Slot {
                            name: n.clone(),
                            spawn: Box::new(move || {
                                let mut c = Command::new(&exe);
                                c.env_remove("SEAGENT_HOME").env_remove("SEAGENT_PROFILE").env("SEAGENT_MULTIPLEX", "1");
                                if n2 != "default" {
                                    c.args(["-p", &n2]);
                                }
                                c.args(["daemon", "run"]).spawn()
                            }),
                            child: None,
                            restarts: vec![],
                            gave_up: false,
                        }
                    })
                    .collect();
                let sp = state_path();
                let _ = std::fs::create_dir_all(sp.parent().unwrap());
                let _ = seagent_kernel::util::atomic_write(&sp, json!({"pid": std::process::id(), "served_profiles": p.served, "standalone": p.standalone, "started_at": seagent_kernel::util::unix_now()}).to_string().as_bytes());
                // SAFETY: installing an async-signal-safe handler that only stores an atomic.
                unsafe {
                    libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
                    libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
                }
                eprintln!("seagent gateway multiplex: serving {}", p.served.join(", "));
                supervise(&mut slots, &STOP, Duration::from_millis(500), &mut |m| eprintln!("seagent gateway multiplex: {m}"));
                let _ = seagent_kernel::util::atomic_write(&sp, json!({"pid": null, "served_profiles": p.served, "stopped_at": seagent_kernel::util::unix_now()}).to_string().as_bytes());
                Ok(0)
            }
            other => crate::usage(format!("unknown `gateway multiplex {other}` (plan | run [--force] | status)")),
        }
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn pf(name: &str, config: &str) -> ProfileFacts {
        ProfileFacts { name: name.into(), config: config.into(), ..Default::default() }
    }

    #[test]
    fn preflight_finds_shared_tokens_listens_and_standalone() {
        let a = pf("default", "[channels.tg]\nkind = \"telegram\"\ntoken = \"{{secret:TG}}\"\n");
        let b = pf("work", "[channels.tg2]\nkind = \"telegram\"\ntoken = \"{{secret:TG}}\"\n[channels.hook]\nkind = \"webhook\"\nlisten = \"127.0.0.1:9000\"\n");
        let c = pf("lab", "[channels.hook]\nkind = \"webhook\"\nlisten = \"127.0.0.1:9000\"\n");
        let p = plan(&[a.clone(), b.clone(), c.clone()]);
        assert_eq!(p.served, ["default", "work", "lab"]);
        assert_eq!(p.blockers.len(), 2, "{:?}", p.blockers);
        assert!(p.blockers[0].contains("telegram bot token") && p.blockers[0].contains("default.tg and work.tg2"));
        assert!(p.blockers[1].contains("127.0.0.1:9000"));
        let mut c2 = c.clone();
        c2.standalone = true;
        let mut b2 = b.clone();
        b2.config = "[channels.x]\nkind = \"slack\"\nbot_token = \"other\"\n".into();
        let p = plan(&[a.clone(), b2, c2]);
        assert!(p.blockers.is_empty(), "{:?}", p.blockers);
        assert_eq!(p.standalone, ["lab"]);
        assert!(plan_text(&p).contains("preflight: ok"));
        let mut r = a.clone();
        r.running_elsewhere = true;
        assert!(plan(&[r]).blockers[0].contains("already runs its own daemon"));
        assert_eq!(plan(&[a]).note.as_deref(), Some(SINGLE));
        assert!(!plan(&[pf("x", "not = = toml")]).blockers.is_empty());
    }

    #[test]
    fn supervisor_restarts_with_a_cap_and_stops_children() {
        let stop = Arc::new(AtomicBool::new(false));
        let mut slots = vec![
            Slot { name: "crashy".into(), spawn: Box::new(|| Command::new("sh").args(["-c", "exit 3"]).spawn()), child: None, restarts: vec![], gave_up: false },
            Slot { name: "steady".into(), spawn: Box::new(|| Command::new("sleep").arg("30").spawn()), child: None, restarts: vec![], gave_up: false },
        ];
        let s2 = stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(1500));
            s2.store(true, Ordering::SeqCst);
        });
        let mut logs = vec![];
        let t = Instant::now();
        supervise(&mut slots, &stop, Duration::from_millis(20), &mut |m| logs.push(m));
        assert!(t.elapsed() < Duration::from_secs(8), "children stopped promptly");
        assert_eq!(slots[0].restarts.len(), MAX_RESTARTS);
        assert!(slots[0].gave_up && logs.iter().any(|l| l.contains("not restarting")));
        assert!(slots[1].restarts.is_empty() && slots[1].child.is_none());
    }

    #[test]
    fn dispatch_is_reachable_from_ops_and_only_claims_gateway_multiplex() {
        let raw = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // `ops::dispatch` walks MODULES (ops/mod.rs) in order: no earlier module claims `gateway`,
        // so `seagent gateway multiplex …` reaches this dispatcher (main.rs calls ops::dispatch).
        let a = Args::parse(&["multiplex".into(), "serve".into()]).unwrap();
        match crate::ops::dispatch("gateway", &a, &raw(&["gateway", "multiplex", "serve"])) {
            Some(Err(crate::Fail::Usage(m))) => assert!(m.contains("unknown `gateway multiplex serve`"), "{m}"),
            Some(Err(e)) => panic!("`gateway multiplex serve` is not a usage error: {e}"),
            Some(Ok(code)) => panic!("`gateway multiplex serve` unexpectedly exited {code}"),
            None => panic!("`seagent gateway multiplex <verb>` is not routed to ops::multiplex"),
        }
        // Bare `seagent gateway` explains the real surface instead of falling through to the plugin CLI.
        let a = Args::parse(&[]).unwrap();
        match crate::ops::dispatch("gateway", &a, &raw(&["gateway"])) {
            Some(Err(crate::Fail::Usage(m))) => assert!(m.contains("seagent gateway multiplex (plan"), "{m}"),
            Some(Err(e)) => panic!("bare `gateway` is not a usage error: {e}"),
            Some(Ok(code)) => panic!("bare `gateway` unexpectedly exited {code}"),
            None => panic!("bare `seagent gateway` is not routed to ops::multiplex"),
        }
        // Other commands stay untouched, and the multiplex flag is accepted by the parser.
        assert!(dispatch("dns", &a, &[]).is_none());
        assert!(Args::parse(&["multiplex".into(), "run".into(), "--force".into()]).unwrap().flag("force"));
        assert!(crate::ops::owns("gateway"), "`seagent gateway` is a built-in, so plugins cannot take it");
    }
}
