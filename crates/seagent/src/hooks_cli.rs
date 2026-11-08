//! `seagent hooks …` (Hermes `hooks list|test|revoke|doctor` + first-use consent; OpenClaw
//! `hooks list|info|check|enable|disable|install`) and `seagent webhook test` (Hermes).

use crate::args::Args;
use crate::hooks_ext::{self as hx, HooksExtra, Pack, BUNDLED};
use seagent_kernel::config::{project_config, Config, Paths};
use seagent_kernel::hooks::{HookConfig, HookDecision, HookEvent, ShellHook, Hook};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const USAGE: &str = "usage: seagent hooks list [--json] | test <event> [--for-tool T] [--payload-file F] | approve <command>|--all | revoke <command> | doctor | info <name> | check | enable <name> | disable <name> | install <dir> [--link]";

struct Ctx {
    cfg: Config,
    x: HooksExtra,
    paths: Paths,
    ws: PathBuf,
}

fn ctx(a: &Args) -> Result<Ctx, String> {
    let paths = Paths::from_env();
    let ws = PathBuf::from(a.val("workspace").unwrap_or(".")).canonicalize().map_err(|e| format!("workspace: {e}"))?;
    let cfg = Config::load(Some(&paths.user_config()), Some(&project_config(&ws)), &a.vals("set"))?;
    let x = HooksExtra::parse(&cfg)?;
    Ok(Ctx { cfg, x, paths, ws })
}

fn approval_of<'a>(c: &'a [hx::Approval], h: &HookConfig) -> Option<&'a hx::Approval> {
    c.iter().find(|a| a.event == h.event.name() && a.command == h.command)
}

/// Every hook entry `seagent hooks list` shows.
fn listing(c: &Ctx) -> Value {
    let (allow, _) = hx::load_allowlist(&c.paths);
    let over = hx::enabled_overrides(&c.paths);
    let shell: Vec<Value> = c
        .cfg
        .hooks
        .iter()
        .map(|h| {
            let ap = approval_of(&allow, h);
            json!({"event": h.event.name(), "matcher": h.matcher, "command": h.command, "timeout_secs": h.timeout_secs,
                "consent": if ap.is_some() { "approved" } else if hx::accept_all(&c.x) { "auto-accept" } else { "not approved" }, "approved_at": ap.map(|a| a.approved_at.clone())})
        })
        .collect();
    let bundled: Vec<Value> = BUNDLED.iter().map(|(n, ev, d)| json!({"name": n, "events": ev, "description": d, "enabled": hx::bundled_enabled(&c.x, &c.paths, n)})).collect();
    let (packs, _) = hx::discover_packs(&c.paths, &c.ws);
    let packs: Vec<Value> = packs.iter().map(|p| json!({"name": p.name, "events": p.events, "description": p.description, "source": p.source, "dir": p.dir, "enabled": over.get(&p.name).copied().unwrap_or(false), "handler": p.handler})).collect();
    let (targets, _) = crate::hooks_outbound::targets(&c.x.outbound, &c.cfg);
    let outbound: Vec<Value> = targets.iter().map(|t| json!({"name": t.label(), "url": t.url, "events": t.events.iter().map(|e| e.name()).collect::<Vec<_>>(), "matcher": t.matcher, "timeout": t.timeout, "signed": t.secret.is_some()})).collect();
    let plugins: Vec<Value> = c.cfg.plugins.keys().map(|n| json!({"name": n})).collect();
    json!({"shell": shell, "bundled": bundled, "packs": packs, "outbound": outbound, "plugins": plugins, "gmail": c.x.gmail.as_ref().map(|g| json!({"enabled": g.enabled, "account": g.account}))})
}

fn print_listing(v: &Value) {
    let rows = |k: &str| v[k].as_array().cloned().unwrap_or_default();
    println!("shell hooks ([[hooks]], first-use consent):");
    if rows("shell").is_empty() {
        println!("  (none)");
    }
    for h in rows("shell") {
        let m = h["matcher"].as_str().filter(|m| !m.is_empty()).map(|m| format!(" [{m}]")).unwrap_or_default();
        println!("  {:<22} {}{m}  timeout {}s  · {}", h["event"].as_str().unwrap_or(""), h["command"].as_str().unwrap_or(""), h["timeout_secs"], h["consent"].as_str().unwrap_or(""));
    }
    println!("bundled hooks:");
    for b in rows("bundled") {
        println!("  {} {:<22} {} — {}", if b["enabled"] == json!(true) { "✓" } else { "·" }, b["name"].as_str().unwrap_or(""), b["events"].as_str().unwrap_or(""), b["description"].as_str().unwrap_or(""));
    }
    if !rows("packs").is_empty() {
        println!("installed hook packs:");
        for p in rows("packs") {
            println!("  {} {:<22} {} ({}) — {}", if p["enabled"] == json!(true) { "✓" } else { "·" }, p["name"].as_str().unwrap_or(""), p["events"], p["source"].as_str().unwrap_or(""), p["description"].as_str().unwrap_or(""));
        }
    }
    if !rows("outbound").is_empty() {
        println!("outbound webhooks:");
        for o in rows("outbound") {
            println!("  {:<22} {} {} timeout {}s{}", o["name"].as_str().unwrap_or(""), o["url"].as_str().unwrap_or(""), o["events"], o["timeout"], if o["signed"] == json!(true) { " · signed" } else { " · UNSIGNED" });
        }
    }
    if !rows("plugins").is_empty() {
        println!("plugin hooks: see `seagent plugin list`");
    }
}

/// A synthetic payload like Hermes `_synthetic_payload`, merged with `--payload-file`.
pub fn synthetic_payload(event: HookEvent, tool: Option<&str>, cwd: &Path, extra: Option<Value>) -> Value {
    let mut p = json!({"session_id": "test-session", "cwd": cwd, "hook_event_name": event.claude_name(), "test": true});
    match event {
        HookEvent::PreTool | HookEvent::PostTool | HookEvent::ToolRequest | HookEvent::ToolExecution => {
            p["tool_name"] = tool.unwrap_or("shell").into();
            p["tool_input"] = json!({"command": "echo hello"});
            if event == HookEvent::PostTool {
                p["tool_response"] = json!({"content": "hello", "is_error": false});
            }
        }
        HookEvent::UserPrompt | HookEvent::MessageReceived | HookEvent::MessageSending | HookEvent::BeforeDispatch | HookEvent::InboundClaim => p["prompt"] = "hello from seagent hooks test".into(),
        HookEvent::TurnEnd => p["last_assistant_message"] = "done".into(),
        HookEvent::SessionEnd | HookEvent::BeforeReset => p["reason"] = "test".into(),
        _ => {}
    }
    if let (Some(Value::Object(m)), Some(o)) = (extra, p.as_object_mut()) {
        o.extend(m);
    }
    p
}

fn describe(d: &Result<HookDecision, String>) -> String {
    match d {
        Ok(HookDecision::Allow) => "allow".into(),
        Ok(HookDecision::Block(r)) => format!("block: {r}"),
        Ok(HookDecision::Modify(v)) => format!("modify: {}", v.to_string().chars().take(200).collect::<String>()),
        Ok(HookDecision::Context(c)) => format!("context: {}", c.chars().take(200).collect::<String>()),
        Err(e) => format!("error: {e}"),
    }
}

fn run_one(h: &HookConfig, p: &Value) -> (Result<HookDecision, String>, u128) {
    let t = Instant::now();
    let r = ShellHook::new(h.clone()).and_then(|s| s.run(h.event, p));
    (r, t.elapsed().as_millis())
}

pub fn cmd(a: &Args) -> Result<i32, String> {
    let c = ctx(a)?;
    match a.pos(0).unwrap_or("list") {
        "list" | "ls" => {
            let v = listing(&c);
            if a.flag("json") {
                println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            } else {
                print_listing(&v);
            }
            Ok(0)
        }
        "test" => {
            let name = a.need(1, "event")?;
            let event = HookEvent::parse(name).ok_or_else(|| format!("unknown hook event `{name}`"))?;
            let extra = match a.val("payload-file") {
                Some(f) => Some(serde_json::from_str::<Value>(&std::fs::read_to_string(f).map_err(|e| format!("{f}: {e}"))?).map_err(|e| format!("{f}: {e}"))?),
                None => None,
            };
            let tool = a.val("for-tool");
            let p = synthetic_payload(event, tool, &c.ws, extra);
            let mut n = 0;
            for h in c.cfg.hooks.iter().filter(|h| h.event == event) {
                let Ok(s) = ShellHook::new(h.clone()) else { continue };
                if !s.wants(event, tool.or(p["tool_name"].as_str())) {
                    continue;
                }
                let (r, ms) = run_one(h, &p);
                println!("{} ({ms} ms): {}", h.command, describe(&r));
                n += 1;
            }
            let over = hx::enabled_overrides(&c.paths);
            for pk in hx::discover_packs(&c.paths, &c.ws).0.iter().filter(|p| over.get(&p.name).copied().unwrap_or(false) && p.events.iter().any(|e| HookEvent::parse(e) == Some(event))) {
                if let Some(hd) = &pk.handler {
                    let h = HookConfig { event, matcher: String::new(), command: format!("'{}'", hd.display()), timeout_secs: 30 };
                    let (r, ms) = run_one(&h, &p);
                    println!("pack {} ({ms} ms): {}", pk.name, describe(&r));
                    n += 1;
                }
            }
            if n == 0 {
                println!("no shell hooks or enabled packs for {}", event.name());
            }
            Ok(0)
        }
        "approve" | "accept" => {
            let all = a.flag("all");
            let target = a.pos(1);
            if !all && target.is_none() {
                return Err("usage: seagent hooks approve <command> | --all".into());
            }
            let mut n = 0;
            for h in c.cfg.hooks.iter().filter(|h| all || Some(h.command.as_str()) == target) {
                hx::record_approval(&c.paths, &h.event.name(), &h.command)?;
                println!("approved {} → {}", h.event.name(), h.command);
                n += 1;
            }
            if n == 0 {
                return Err(format!("no configured [[hooks]] command matches `{}`", target.unwrap_or("")));
            }
            Ok(0)
        }
        "revoke" | "remove" | "rm" => {
            let command = a.need(1, "command")?;
            let n = hx::revoke(&c.paths, command)?;
            println!("removed {n} allowlist entr{} for {command}", if n == 1 { "y" } else { "ies" });
            if n > 0 {
                println!("note: a running seagentd keeps it until restart (seagent daemon stop && seagent daemon start)");
            }
            Ok(if n > 0 { 0 } else { 1 })
        }
        "doctor" => Ok(doctor(&c)),
        "info" => {
            let name = a.need(1, "name")?;
            if let Some((n, ev, d)) = BUNDLED.iter().find(|b| b.0 == name) {
                println!("{n} (bundled)\nevents: {ev}\n{d}\nenabled: {}", hx::bundled_enabled(&c.x, &c.paths, n));
                return Ok(0);
            }
            let (packs, _) = hx::discover_packs(&c.paths, &c.ws);
            let p = packs.iter().find(|p| p.name == name).ok_or_else(|| format!("no hook named `{name}` (seagent hooks list)"))?;
            println!("{} ({} pack at {})\nevents: {}\n{}\nhandler: {}\nenabled: {}", p.name, p.source, p.dir.display(), p.events.join(", "), p.description, p.handler.as_ref().map(|h| h.display().to_string()).unwrap_or("MISSING".into()), hx::enabled_overrides(&c.paths).get(&p.name).copied().unwrap_or(false));
            Ok(0)
        }
        "check" => {
            let (packs, warns) = hx::discover_packs(&c.paths, &c.ws);
            for w in &warns {
                println!("✗ {w}");
            }
            for p in &packs {
                match &p.handler {
                    Some(h) if is_exec(h) => println!("✓ {} eligible", p.name),
                    Some(h) => println!("✗ {}: handler {} is not executable", p.name, h.display()),
                    None => println!("✗ {}: no handler", p.name),
                }
            }
            for (n, _, _) in BUNDLED {
                println!("✓ {n} eligible (bundled)");
            }
            Ok(if warns.is_empty() { 0 } else { 1 })
        }
        "enable" | "disable" => {
            let on = a.pos(0) == Some("enable");
            let name = a.need(1, "name")?;
            let known = BUNDLED.iter().any(|b| b.0 == name) || hx::discover_packs(&c.paths, &c.ws).0.iter().any(|p| p.name == name);
            if !known {
                return Err(format!("no hook named `{name}` (seagent hooks list)"));
            }
            hx::set_enabled(&c.paths, name, on)?;
            println!("{} {name}; restart seagentd to apply (seagent daemon stop && seagent daemon start)", if on { "enabled" } else { "disabled" });
            Ok(0)
        }
        "install" => install(a, &c),
        other => Err(format!("unknown hooks subcommand `{other}`\n{USAGE}")),
    }
}

fn is_exec(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| crate::ops::hostos::is_executable(p, &m))
}

/// Hermes `hooks doctor`: exec bit, allowlist, mtime drift, JSON validity, synthetic run timing.
fn doctor(c: &Ctx) -> i32 {
    let (allow, readable) = hx::load_allowlist(&c.paths);
    let mut bad = 0;
    // A8/A9: a listener that left loopback without the public-exposure layers (the app server
    // refuses such a bind; channel callbacks can only be reported here).
    for w in crate::security_cli::exposure_warnings(&c.cfg) {
        println!("{w}");
        bad += 1;
    }
    // LAN interconnect posture (informational).
    for l in crate::security_cli::lan_findings(&c.cfg, &c.paths.data) {
        println!("{} {}", if l.severity == "warn" { "⚠" } else { "•" }, l.title);
    }
    if !readable {
        println!("✗ allowlist {} is unreadable or malformed", hx::allowlist_path(&c.paths).display());
        bad += 1;
    }
    if c.cfg.hooks.is_empty() {
        println!("no [[hooks]] configured");
    }
    for h in &c.cfg.hooks {
        println!("{} → {}", h.event.name(), h.command);
        let script = hx::script_path(&h.command);
        let looks_like_file = script.contains('/') || script.starts_with('~');
        if looks_like_file {
            if hx::script_is_executable(&h.command) {
                println!("  ✓ {script} is runnable");
            } else {
                println!("  ✗ {script} is missing or not executable");
                bad += 1;
            }
        }
        match approval_of(&allow, h) {
            Some(ap) => {
                println!("  ✓ approved {}", ap.approved_at);
                let now = hx::script_mtime(&h.command);
                if looks_like_file && ap.script_mtime_at_approval.is_some() && now != ap.script_mtime_at_approval {
                    println!("  ⚠ script changed since approval ({} → {}); re-check it and re-approve", ap.script_mtime_at_approval.clone().unwrap_or_default(), now.unwrap_or("missing".into()));
                    bad += 1;
                }
            }
            None if hx::accept_all(&c.x) => println!("  ✓ auto-accepted (auto_accept / SEAGENT_ACCEPT_HOOKS)"),
            None => {
                println!("  ✗ not approved (seagent hooks approve '{}')", h.command);
                bad += 1;
            }
        }
        let p = synthetic_payload(h.event, None, &c.ws, None);
        let t = Instant::now();
        let out = std::process::Command::new("bash")
            .arg("-c")
            .arg(&h.command)
            .current_dir(&c.ws)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut ch| {
                use std::io::Write;
                if let Some(mut i) = ch.stdin.take() {
                    let _ = i.write_all(p.to_string().as_bytes());
                }
                ch.wait_with_output()
            });
        let ms = t.elapsed().as_millis();
        match out {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let s = stdout.trim();
                let json_ok = s.is_empty() || serde_json::from_str::<Value>(s).is_ok();
                println!("  {} synthetic run: exit {} in {ms} ms{}", if o.status.code().is_some_and(|c| c == 0 || c == 2) { "✓" } else { "✗" }, o.status.code().map(|c| c.to_string()).unwrap_or("signal".into()), if json_ok { "" } else { " · stdout is not JSON (ignored except as context for prompt/session hooks)" });
                if !o.status.code().is_some_and(|c| c == 0 || c == 2) {
                    bad += 1;
                }
                if ms as u64 > h.timeout_secs * 1000 {
                    println!("  ⚠ took longer than its {}s timeout", h.timeout_secs);
                    bad += 1;
                }
            }
            Err(e) => {
                println!("  ✗ could not run: {e}");
                bad += 1;
            }
        }
    }
    if bad == 0 {
        println!("all hooks look healthy");
        0
    } else {
        1
    }
}

/// OpenClaw `hooks install`: copy (or `--link`) a hook pack into `<data>/hooks/<name>`, after
/// the built-in scan and `before_install` hooks. Installed packs start disabled.
fn install(a: &Args, c: &Ctx) -> Result<i32, String> {
    let src = PathBuf::from(a.need(1, "dir")?).canonicalize().map_err(|e| format!("source: {e}"))?;
    let pack: Pack = hx::read_pack(&src, "managed")?;
    let scan = hx::builtin_scan(&src);
    if scan["critical"].as_u64().unwrap_or(0) > 0 && !a.flag("yes") {
        for f in scan["findings"].as_array().into_iter().flatten().filter(|f| f["severity"] == "critical") {
            println!("✗ {}:{} {} ({})", f["file"].as_str().unwrap_or(""), f["line"], f["message"].as_str().unwrap_or(""), f["rule_id"].as_str().unwrap_or(""));
        }
        return Err("built-in scan found critical issues; re-run with --yes to install anyway".into());
    }
    // before_install hooks (shell, packs, plugins) get the final say.
    let built = crate::build_agent_for_hooks(a)?;
    let dest = hx::hooks_dir(&c.paths).join(&pack.name);
    hx::before_install(&built, "hook", &pack.name, &src, if dest.exists() { "update" } else { "install" }, &scan).map_err(|e| format!("install blocked by {e}"))?;
    if dest.exists() || std::fs::symlink_metadata(&dest).is_ok() {
        if std::fs::symlink_metadata(&dest).is_ok_and(|m| m.file_type().is_symlink()) {
            std::fs::remove_file(&dest).map_err(|e| e.to_string())?;
        } else {
            std::fs::remove_dir_all(&dest).map_err(|e| e.to_string())?;
        }
    }
    std::fs::create_dir_all(hx::hooks_dir(&c.paths)).map_err(|e| e.to_string())?;
    if a.flag("link") {
        crate::ops::hostos::symlink(&src, &dest).map_err(|e| format!("link: {e}"))?;
    } else {
        copy_dir(&src, &dest)?;
    }
    println!("installed hook pack {} → {} (disabled; enable with `seagent hooks enable {}`)", pack.name, dest.display(), pack.name);
    Ok(0)
}

fn copy_dir(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("{}: {e}", dst.display()))?;
    for e in std::fs::read_dir(src).map_err(|e| e.to_string())?.flatten() {
        let (from, to) = (e.path(), dst.join(e.file_name()));
        let ft = e.file_type().map_err(|e| e.to_string())?;
        if ft.is_dir() {
            if e.file_name() != ".git" {
                copy_dir(&from, &to)?;
            }
        } else if ft.is_file() {
            std::fs::copy(&from, &to).map_err(|e| format!("{}: {e}", from.display()))?;
        }
    }
    Ok(())
}

// ───────────────────────── seagent webhook test ─────────────────────────

pub const DEFAULT_TEST_PAYLOAD: &str = r#"{"test": true, "event_type": "test", "message": "Hello from seagent webhook test"}"#;

/// Where a route listens and its secret: dynamic subscriptions first, then static routes.
pub fn route_target(cfg: &Config, paths: &Paths, channel: &str, route: &str, secrets: &dyn Fn(&str) -> String) -> Result<(String, String), String> {
    let ch = cfg.channels.get(channel).ok_or_else(|| format!("no channel `{channel}` in config"))?;
    let listen = ch.get("listen").and_then(|v| v.as_str()).ok_or_else(|| format!("channel {channel} has no `listen` address"))?;
    let host = listen.replace("0.0.0.0", "127.0.0.1").replace("[::]", "[::1]");
    let subs = seagent_channel::webhook::list_subscriptions(&seagent_channel::webhook::subscriptions_path(&paths.data.join("channels"), channel)).unwrap_or_default();
    let (path, secret) = if let Some(r) = subs.get(route) {
        (r["path"].as_str().map(String::from), r["secret"].as_str().map(String::from))
    } else if let Some(r) = ch.get("routes").and_then(|r| r.get(route)) {
        (r.get("path").and_then(|v| v.as_str()).map(String::from), r.get("secret").and_then(|v| v.as_str()).map(String::from))
    } else {
        return Err(format!("no route named `{route}` on {channel} (seagent webhook list {channel})"));
    };
    let secret = secret.or_else(|| ch.get("secret").and_then(|v| v.as_str()).map(String::from)).map(|s| secrets(&s)).unwrap_or_default();
    Ok((format!("http://{host}{}", path.unwrap_or_else(|| format!("/webhooks/{route}"))), secret))
}

/// Hermes `_cmd_test`: POST with a GitHub-style signature; returns (status, body).
pub fn webhook_test(url: &str, secret: &str, payload: &str) -> Result<(u16, String), String> {
    let sig = format!("sha256={}", seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(secret.as_bytes(), payload.as_bytes())));
    let agent: ureq::Agent = seagent_net::http::builder().http_status_as_error(false).timeout_global(Some(std::time::Duration::from_secs(10))).build().into();
    let mut r = agent.post(url).header("content-type", "application/json").header("X-Hub-Signature-256", &sig).header("X-GitHub-Event", "test").send(payload.as_bytes()).map_err(|e| format!("{e} — is the daemon running? (seagent daemon start)"))?;
    let s = r.status().as_u16();
    Ok((s, r.body_mut().read_to_string().unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use seagent_net::httpd::{Opts, Request, Response, Server};
    use std::sync::{Arc, Mutex};

    #[test]
    fn synthetic_payloads_follow_the_event() {
        let p = synthetic_payload(HookEvent::PreTool, Some("write"), Path::new("/w"), Some(json!({"extra": 1})));
        assert_eq!((p["tool_name"].as_str(), p["hook_event_name"].as_str(), p["extra"].as_i64()), (Some("write"), Some("PreToolUse"), Some(1)));
        assert_eq!(synthetic_payload(HookEvent::UserPrompt, None, Path::new("/"), None)["prompt"], "hello from seagent hooks test");
    }

    #[test]
    fn doctor_warns_about_a_public_listener() {
        let root = seagent_core::tmp::scratch_path(format!("seagent-hooks-doctor-{}", seagent_kernel::util::random_hex(8)));
        std::fs::create_dir_all(root.join("data")).unwrap();
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        let cfg = Config { app: toml::from_str("enabled = true\nlisten = \"0.0.0.0:8640\"\ntoken = \"t\"").unwrap(), ..Default::default() };
        let c = Ctx { x: HooksExtra::parse(&cfg).unwrap(), cfg, paths, ws: root.clone() };
        assert_eq!(doctor(&c), 1, "a non-loopback app server without the layers is a warning");
        // The default config (no listeners) is healthy.
        let cfg = Config::default();
        let c = Ctx { x: HooksExtra::parse(&cfg).unwrap(), cfg, paths: Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() }, ws: root.clone() };
        assert_eq!(doctor(&c), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn webhook_test_signs_like_github_against_a_fake_listener() {
        let seen: Arc<Mutex<Vec<Request>>> = Arc::default();
        let s2 = seen.clone();
        let srv = Server::bind("127.0.0.1:0", Opts::default(), Arc::new(move |r: Request| {
            s2.lock().unwrap().push(r);
            Response::text(202, "accepted")
        }))
        .unwrap();
        let root = seagent_core::tmp::scratch_path(format!("seagent-whtest-{}", seagent_kernel::util::random_hex(8)));
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run"), ..Default::default() };
        let cfg: Config = toml::from_str(&format!("[channels.hooks]\nkind = \"webhook\"\nlisten = \"{}\"\nsecret = \"{{{{secret:WH}}}}\"\n[channels.hooks.routes.gh]\nprompt = \"x\"\n", srv.local_addr())).unwrap();
        let file = seagent_channel::webhook::subscriptions_path(&paths.data.join("channels"), "hooks");
        seagent_channel::webhook::subscribe(&file, "dyn", json!({"secret": "dsecret"})).unwrap();
        let resolve = |s: &str| s.replace("{{secret:WH}}", "chan-secret");
        let (url, secret) = route_target(&cfg, &paths, "hooks", "gh", &resolve).unwrap();
        assert_eq!((url.ends_with("/webhooks/gh"), secret.as_str()), (true, "chan-secret"));
        assert_eq!(route_target(&cfg, &paths, "hooks", "dyn", &resolve).unwrap().1, "dsecret");
        assert!(route_target(&cfg, &paths, "hooks", "nope", &resolve).is_err());
        let (status, body) = webhook_test(&url, &secret, DEFAULT_TEST_PAYLOAD).unwrap();
        assert_eq!((status, body.as_str()), (202, "accepted"));
        let r = &seen.lock().unwrap()[0];
        assert_eq!(r.header("x-github-event"), Some("test"));
        let want = format!("sha256={}", seagent_net::crypto::hex(&seagent_net::crypto::hmac_sha256(b"chan-secret", DEFAULT_TEST_PAYLOAD.as_bytes())));
        assert_eq!(r.header("x-hub-signature-256"), Some(want.as_str()));
    }
}
