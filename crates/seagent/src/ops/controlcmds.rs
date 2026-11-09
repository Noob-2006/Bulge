//! Chat commands for running the host from a conversation (OpenClaw §5): `/diagnostics`, `/seagent` (the OpenClaw `/openclaw` setup-and-repair rescue helper),
//! `/restart`, `/pair` (extensions/device-pair) and `/controlui` (Telegram Mini App).
//! Rows are merged into the shared slash table through `slashops::SLASH`.

use crate::slash::{Ctx, Reply, Surface};
use serde_json::{json, Value};
use std::path::PathBuf;

fn text(t: impl Into<String>) -> Result<Reply, String> {
    Ok(Reply { text: Some(t.into()), ..Default::default() })
}

fn in_group(c: &Ctx) -> bool {
    c.sender.as_ref().is_some_and(|s| s.group)
}

// ───────────────────────── /diagnostics ─────────────────────────

pub const DIAGNOSTICS_PRIVATE_ROUTE_UNAVAILABLE: &str = "I couldn't find a private owner route for diagnostics. Run /diagnostics from an owner DM so the sensitive diagnostics details are not posted in this chat.";

/// A diagnostics bundle (JSON, 0600) under `<data>/diagnostics/`: versions, paths, redacted
/// config + validation, service audit, recent starts, recent warnings/errors, channels.
pub fn diagnostics_bundle(c: &Ctx, note: &str) -> Result<(PathBuf, Value), String> {
    let paths = &c.k.paths;
    let text = std::fs::read_to_string(paths.user_config()).unwrap_or_default();
    let valid = seagent_kernel::config::Config::load(Some(&paths.user_config()), Some(&seagent_kernel::config::project_config(&c.workspace)), &[]).err();
    let log = crate::ops::logs::dir(paths).join("seagent.jsonl");
    let recent: Vec<Value> = std::fs::read_to_string(&log).unwrap_or_default().lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()).filter(|r| r["level"] == "error" || r["level"] == "warn").collect();
    let recent: Vec<Value> = recent.into_iter().rev().take(50).collect();
    let now = seagent_kernel::event::now_ms();
    let b = json!({
        "generated_ms": now,
        "version": env!("CARGO_PKG_VERSION"),
        "target": crate::ops::update::target(),
        "profile": crate::ops::profile::current(),
        "paths": {"config": paths.config_dir, "data": paths.data, "runtime": paths.runtime},
        "config": {"text": crate::slash::redact(&text), "error": valid},
        "model": {"default": c.k.cfg.model.default, "fallback": c.k.cfg.model.fallback},
        "sessions": c.k.store.list().len(),
        "service": crate::ops::service::audit(&c.workspace).iter().map(|i| format!("{i:?}")).collect::<Vec<_>>(),
        "recent_starts": crate::ops::service::recent_starts(paths, (now / 1000) as i64),
        "recent_log": recent,
        // The last tool calls that failed (tool, args summary and error, already redacted).
        "tool_failures": crate::ops::toollog::recent_failures(paths, &c.k.cfg, 50, now),
        "channels": c.k.cfg.channels.iter().map(|(n, t)| json!({"name": n, "kind": t.get("kind").and_then(|k| k.as_str()).unwrap_or(n)})).collect::<Vec<_>>(),
        "note": note.trim(),
    });
    let dir = paths.data.join("diagnostics");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let p = dir.join(format!("diag-{now}.json"));
    seagent_kernel::util::atomic_write(&p, serde_json::to_string_pretty(&b).unwrap_or_default().as_bytes()).map_err(|e| e.to_string())?;
    let _ = crate::ops::hostos::set_mode(&p, 0o600);
    Ok((p, b))
}

pub fn cmd_diagnostics(c: &Ctx, a: &str) -> Result<Reply, String> {
    if in_group(c) {
        return text(DIAGNOSTICS_PRIVATE_ROUTE_UNAVAILABLE);
    }
    let (p, b) = diagnostics_bundle(c, a)?;
    let errors = b["recent_log"].as_array().map(|v| v.iter().filter(|r| r["level"] == "error").count()).unwrap_or(0);
    let tool_failures = b["tool_failures"].as_array().map(Vec::len).unwrap_or(0);
    text(format!(
        "Diagnostics can include sensitive local logs and host-level runtime metadata.\nTreat diagnostics bundles like secrets and review what they contain before sharing.\n\nbundle: {}\nseagent {} ({}) · profile {} · {} session(s) · config {} · {} recent error(s), {} failed tool call(s), {} service issue(s)\nShare it with `seagent debug share` only after reviewing it.",
        p.display(),
        b["version"].as_str().unwrap_or(""),
        b["target"].as_str().unwrap_or(""),
        b["profile"].as_str().unwrap_or(""),
        b["sessions"],
        if b["config"]["error"].is_null() { "valid" } else { "INVALID" },
        errors,
        tool_failures,
        b["service"].as_array().map(|a| a.len()).unwrap_or(0),
    ))
}

// ───────────────────────── /seagent (rescue) ─────────────────────────

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Op {
    None { message: String },
    Status,
    Overview,
    Doctor,
    Models,
    ConfigGet { path: String },
    ConfigValidate,
    SetDefaultModel { model: String },
    ConfigSet { path: String, value: String },
    Channels,
    Channel { name: String },
    GatewayStatus,
    GatewayRestart,
    Agents,
    Plugins,
    /// Refused remotely (message explains the local alternative).
    Unsupported { message: String },
}

/// The read-only verbs rescue answers without a model and without writing anything
/// (OpenClaw `system-agent` read operations).
pub const READ_VERBS: &str = "status, overview, doctor, models, config get <key>, config validate, channels, channel <name>, gateway status, agents, plugins";

impl Op {
    fn persistent(&self) -> bool {
        matches!(self, Op::SetDefaultModel { .. } | Op::ConfigSet { .. } | Op::GatewayRestart)
    }
}

const RESCUE_TTL_MS: u64 = 15 * 60_000;
const RESCUE_MAX: usize = 1024;

pub fn approval_intent(m: &str) -> Option<bool> {
    let n = m.trim().trim_end_matches(|c: char| ".!?, ".contains(c)).to_lowercase();
    const YES: &[&str] = &["y", "yes", "yeah", "yep", "yup", "sure", "ok", "okay", "approve", "approved", "apply", "confirm", "confirmed", "do it", "go ahead", "sounds good", "yes please", "please do"];
    const NO: &[&str] = &["n", "no", "nope", "nah", "skip", "not now", "cancel", "stop", "abort", "later", "decline", "dont", "don't"];
    if YES.contains(&n.as_str()) {
        Some(true)
    } else if NO.iter().any(|w| n == *w || n.starts_with(&format!("{w} "))) {
        Some(false)
    } else {
        None
    }
}

/// Deterministic parser: remote rescue never consults a model (a broken agent path must
/// not become a config editor).
pub fn parse_op(s: &str) -> Op {
    let t = s.trim();
    let l = t.to_lowercase();
    let words: Vec<&str> = t.split_whitespace().collect();
    if t.is_empty() {
        return Op::None { message: format!("Tiny claw tap: say {READ_VERBS}, config set <key> <value>, set model <provider/model>, or restart.") };
    }
    match l.as_str() {
        "status" | "health" | "check" => return Op::Status,
        "overview" | "summary" | "about" => return Op::Overview,
        "doctor" | "doctor status" | "doctor lint" => return Op::Doctor,
        "models" | "model" | "list models" => return Op::Models,
        "config validate" | "config check" | "validate config" => return Op::ConfigValidate,
        "channels" | "channel list" | "list channels" => return Op::Channels,
        "gateway status" | "gateway" | "daemon status" => return Op::GatewayStatus,
        "agents" | "agents list" | "list agents" => return Op::Agents,
        "plugins" | "plugin list" | "plugins list" => return Op::Plugins,
        "restart" | "gateway restart" | "restart gateway" | "daemon restart" => return Op::GatewayRestart,
        "doctor fix" | "doctor --fix" | "fix" | "repair" => return Op::Unsupported { message: "seagent rescue cannot run doctor repairs from a message channel because they can change the inference route powering this session. On the machine running seagent, with the daemon stopped, run `seagent doctor --fix`.".into() },
        "tui" | "open tui" | "chat" => return Op::Unsupported { message: "seagent rescue cannot open the local TUI from a message channel. Use `seagent tui` locally, or ask for status, config, models or restart.".into() },
        _ => {}
    }
    if l.starts_with("gateway start") || l.starts_with("gateway stop") || l.starts_with("daemon start") || l.starts_with("daemon stop") {
        return Op::Unsupported { message: "seagent rescue cannot start or stop the daemon from a message channel because the daemon serves this conversation. Run `seagent daemon start` / `seagent daemon stop` locally, or say `restart`.".into() };
    }
    if l.starts_with("plugin install") || l.starts_with("plugins install") || l.starts_with("install plugin") {
        return Op::Unsupported { message: "seagent rescue cannot install plugins from a message channel because plugin install downloads executable code. Use `seagent plugins install` locally instead.".into() };
    }
    if l.starts_with("config unset") || l.starts_with("unset ") {
        return Op::Unsupported { message: "seagent rescue cannot remove configuration settings. Ask your regular agent, or run `seagent config unset <key>` locally.".into() };
    }
    if l.starts_with("connect ") || l.starts_with("setup channel") {
        return Op::Unsupported { message: "seagent rescue cannot host the interactive channel setup from a message channel. Run `seagent setup` locally.".into() };
    }
    if (l.starts_with("set model ") || l.starts_with("use model ") || l.starts_with("set default model ")) && words.len() >= 3 {
        let model = words.last().unwrap().to_string();
        return if model.contains('/') { Op::SetDefaultModel { model } } else { Op::None { message: "models are provider/model (for example anthropic/claude-sonnet-4-5)".into() } };
    }
    if l.starts_with("channel ") && words.len() == 2 {
        return Op::Channel { name: words[1].into() };
    }
    if l.starts_with("config get ") && words.len() == 3 {
        return Op::ConfigGet { path: words[2].into() };
    }
    if l.starts_with("config set ") && words.len() >= 4 {
        let rest = t.splitn(4, char::is_whitespace).nth(3).unwrap_or("").trim().to_string();
        return Op::ConfigSet { path: words[2].into(), value: rest };
    }
    Op::None { message: format!("seagent rescue did not understand `{t}`. Say {READ_VERBS}, config set <key> <value>, set model <provider/model>, or restart.") }
}

pub fn plan_text(op: &Op) -> String {
    let what = match op {
        Op::SetDefaultModel { model } => format!("set model.default = {model}"),
        Op::ConfigSet { path, value } => format!("set {path} = {value}"),
        Op::GatewayRestart => "restart the seagent daemon (running turns finish first, up to 60s)".into(),
        _ => String::new(),
    };
    format!("Planned change: {what}.\nReply /seagent yes to apply, or /seagent no to drop it (expires in 15 minutes).")
}

fn pending_path(c: &Ctx) -> PathBuf {
    c.k.paths.data.join("rescue-pending.json")
}

/// Pending approval is scoped by channel, chat and sender so one route cannot approve
/// a change proposed through another.
fn pending_key(c: &Ctx) -> String {
    let s = c.sender.clone().unwrap_or_default();
    let raw = json!({"channel": s.channel, "chat": s.chat, "sender": s.sender, "surface": format!("{:?}", c.surface)}).to_string();
    seagent_net::crypto::hex(&seagent_net::crypto::sha256(raw.as_bytes()))[..32].to_string()
}

fn pending_load(c: &Ctx) -> serde_json::Map<String, Value> {
    let now = seagent_kernel::event::now_ms();
    let mut m: serde_json::Map<String, Value> = std::fs::read(pending_path(c)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    m.retain(|_, v| v["expires_ms"].as_u64().unwrap_or(0) > now);
    m
}

fn pending_save(c: &Ctx, m: &serde_json::Map<String, Value>) -> Result<(), String> {
    seagent_kernel::util::atomic_write(&pending_path(c), Value::Object(m.clone()).to_string().as_bytes()).map_err(|e| e.to_string())
}

/// Consume (remove and return) this route's pending operation.
fn pending_take(c: &Ctx) -> Result<Option<Op>, String> {
    let mut m = pending_load(c);
    let v = m.remove(&pending_key(c));
    pending_save(c, &m)?;
    Ok(v.and_then(|v| serde_json::from_value::<Op>(v["op"].clone()).ok()).filter(Op::persistent))
}

fn pending_put(c: &Ctx, op: Option<&Op>) -> Result<(), String> {
    let mut m = pending_load(c);
    let k = pending_key(c);
    match op {
        Some(op) => {
            if !m.contains_key(&k) && m.len() >= RESCUE_MAX {
                return Err("too many pending rescue changes; try again later".into());
            }
            m.insert(k, json!({"op": op, "expires_ms": seagent_kernel::event::now_ms() + RESCUE_TTL_MS}));
        }
        None => {
            m.remove(&k);
        }
    }
    pending_save(c, &m)
}

/// Rescue opens only for owners in DMs with sandboxing off (OpenClaw rescue policy);
/// local surfaces (`seagent chat`, TUI, web UI) are the operator already.
pub fn rescue_policy(c: &Ctx) -> Result<(), String> {
    let raw: toml::Table = std::fs::read_to_string(c.k.paths.user_config()).ok().and_then(|t| t.parse().ok()).unwrap_or_default();
    let mode = raw.get("exec").and_then(|e| e.get("sandbox")).and_then(|s| s.get("mode")).and_then(|m| m.as_str()).unwrap_or("off");
    if mode != "off" && !mode.is_empty() {
        return Err("seagent rescue is blocked because exec sandboxing is active. Fix the install locally or turn [exec.sandbox] mode off before using remote rescue.".into());
    }
    if c.surface == Surface::Channel {
        let s = c.sender.clone().unwrap_or_default();
        if !s.admin {
            return Err("seagent rescue only accepts commands from an owner (allow_admin_from).".into());
        }
        if s.group {
            return Err("seagent rescue is restricted to owner DMs.".into());
        }
    }
    Ok(())
}

/// Restart spawner (replaced in tests).
pub type Spawn = fn(u64) -> Result<String, String>;

fn daemon_up(c: &Ctx) -> bool {
    crate::ops::hostos::daemon_reachable(&c.k.paths.socket())
}

fn kind_of(name: &str, t: &toml::Table) -> String {
    t.get("kind").and_then(|k| k.as_str()).unwrap_or(name).to_string()
}

fn allow_len(t: &toml::Table, key: &str) -> usize {
    t.get(key).and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0)
}

fn list_of(t: &toml::Table, key: &str) -> String {
    let v: Vec<String> = t.get(key).and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string()).or_else(|| x.as_integer().map(|i| i.to_string()))).collect()).unwrap_or_default();
    if v.is_empty() { "-".into() } else { v.join(", ") }
}

fn config_state(c: &Ctx) -> Result<(), String> {
    seagent_kernel::config::Config::load(Some(&c.k.paths.user_config()), Some(&seagent_kernel::config::project_config(&c.workspace)), &[]).map(|_| ())
}

/// Read-only doctor lint (never repairs): the same checks `seagent doctor` runs.
fn rescue_doctor(c: &Ctx) -> crate::ops::doctor::Lint {
    let dcx = crate::ops::doctor::Ctx {
        paths: c.k.paths.clone(),
        cfg: c.k.cfg.clone(),
        ws: c.workspace.clone(),
        specs: Ok(c.k.specs()),
        secret_names: seagent_kernel::vault::Vault::load(&c.k.paths.secrets()).map(|v| v.names()).unwrap_or_default(),
        daemon_running: daemon_up(c),
    };
    crate::ops::doctor::lint(&dcx, &crate::ops::doctor::checks(), &[], &[])
}

pub fn execute(c: &Ctx, op: &Op, restart: Spawn) -> Result<String, String> {
    match op {
        Op::None { message } | Op::Unsupported { message } => Ok(message.clone()),
        Op::Status => {
            let running = c.k.store.list().iter().filter(|s| c.k.is_running(&s.id)).count();
            let jobs: Vec<seagent_kernel::automation::Job> = seagent_kernel::automation::read_list(&seagent_kernel::automation::jobs_path(&c.k.paths.data)).unwrap_or_default();
            let valid = seagent_kernel::config::Config::load(Some(&c.k.paths.user_config()), None, &[]).err();
            Ok(format!(
                "seagent {} · profile {}\nmodel {}\n{} running turn(s) · {} cron job(s) · channels: {}\nconfig: {}",
                env!("CARGO_PKG_VERSION"),
                crate::ops::profile::current(),
                c.k.cfg.model.default,
                running,
                jobs.len(),
                c.k.cfg.channels.keys().cloned().collect::<Vec<_>>().join(", "),
                valid.unwrap_or_else(|| "valid".into())
            ))
        }
        Op::Models => Ok(format!("default {}\nfallback {}\nproviders {}", c.k.cfg.model.default, if c.k.cfg.model.fallback.is_empty() { "-".into() } else { c.k.cfg.model.fallback.join(", ") }, c.k.cfg.providers.keys().cloned().collect::<Vec<_>>().join(", "))),
        Op::Overview => {
            let sessions = c.k.store.list();
            let running = sessions.iter().filter(|s| c.k.is_running(&s.id)).count();
            let lint = rescue_doctor(c);
            let errors = lint.findings.iter().filter(|f| f.severity == crate::ops::doctor::Severity::Error).count();
            let channels = if c.k.cfg.channels.is_empty() { "-".to_string() } else { c.k.cfg.channels.keys().cloned().collect::<Vec<_>>().join(", ") };
            Ok(format!(
                "seagent {} · profile {}\nmodel {} · fallback {}\n{} session(s) · {} running turn(s) · {} channel(s): {}\ndaemon {} · config {} · doctor {} finding(s) ({} error(s), {} check(s) run)",
                env!("CARGO_PKG_VERSION"),
                crate::ops::profile::current(),
                c.k.cfg.model.default,
                if c.k.cfg.model.fallback.is_empty() { "-".into() } else { c.k.cfg.model.fallback.join(", ") },
                sessions.len(),
                running,
                c.k.cfg.channels.len(),
                channels,
                if daemon_up(c) { "running" } else { "not reachable from this process" },
                if config_state(c).is_ok() { "valid" } else { "INVALID" },
                lint.findings.len(),
                errors,
                lint.run,
            ))
        }
        Op::Doctor => {
            let lint = rescue_doctor(c);
            let mut lines = vec![if lint.findings.is_empty() {
                format!("seagent doctor: no findings ({} health check(s) run).", lint.run)
            } else {
                format!("seagent doctor: {} finding(s) across {} health check(s).", lint.findings.len(), lint.run)
            }];
            for f in lint.findings.iter().take(20) {
                lines.push(format!("- [{}] {}: {}{}", f.severity.as_str(), f.check, f.message, f.fix_hint.as_ref().map(|h| format!(" (fix: {h})")).unwrap_or_default()));
            }
            if lint.findings.len() > 20 {
                lines.push(format!("… {} more finding(s)", lint.findings.len() - 20));
            }
            if !lint.findings.is_empty() {
                lines.push("Read-only: run `seagent doctor --fix` locally on the host to repair.".into());
            }
            Ok(lines.join("\n"))
        }
        Op::ConfigValidate => Ok(match config_state(c) {
            Ok(()) => format!("config valid: {}", c.k.paths.user_config().display()),
            Err(e) => format!("config INVALID: {}\n{}", c.k.paths.user_config().display(), crate::slash::redact(&e)),
        }),
        Op::Channels => Ok(if c.k.cfg.channels.is_empty() {
            "no channels configured (run `seagent setup` locally)".into()
        } else {
            let mut lines = vec![format!("{} channel(s):", c.k.cfg.channels.len())];
            for (n, t) in &c.k.cfg.channels {
                lines.push(format!("- {n} ({}) · allow {} · admin {}", kind_of(n, t), allow_len(t, "allow"), allow_len(t, "allow_admin_from")));
            }
            lines.join("\n")
        }),
        Op::Channel { name } => {
            let Some(t) = c.k.cfg.channels.get(name) else {
                return Err(format!("unknown channel `{name}` (configured: {})", if c.k.cfg.channels.is_empty() { "none".to_string() } else { c.k.cfg.channels.keys().cloned().collect::<Vec<_>>().join(", ") }));
            };
            let token = t.get("token").and_then(|v| v.as_str()).unwrap_or("");
            Ok(format!(
                "channel {name} · kind {}\ntoken {} · allow {} · admin {}\nallow: {}\nallow_admin_from: {}",
                kind_of(name, t),
                if token.trim().is_empty() { "missing" } else { "set" },
                allow_len(t, "allow"),
                allow_len(t, "allow_admin_from"),
                list_of(t, "allow"),
                list_of(t, "allow_admin_from"),
            ))
        }
        Op::GatewayStatus => {
            let listen = match seagent_app::AppConfig::parse(&c.k.cfg.app) {
                Ok(a) if a.enabled => a.listen,
                Ok(_) => "disabled ([app] enabled = false)".into(),
                Err(e) => format!("INVALID [app]: {e}"),
            };
            Ok(format!(
                "daemon: {}\nsocket: {}\napp listen: {}\nservice issues: {}",
                if daemon_up(c) { "running" } else { "not reachable from this process" },
                c.k.paths.socket().display(),
                listen,
                crate::ops::service::audit(&c.workspace).len(),
            ))
        }
        Op::Agents => {
            let mut s = c.k.store.list();
            s.sort_by_key(|x| std::cmp::Reverse(x.updated_ms));
            if s.is_empty() {
                return Ok("no sessions yet".into());
            }
            let mut lines = vec![format!("{} session(s):", s.len())];
            for x in s.iter().take(20) {
                let id: String = x.id.chars().take(8).collect();
                lines.push(format!("- {id} · {} · {}{}", x.title.as_deref().unwrap_or("(untitled)"), x.model, if c.k.is_running(&x.id) { " · running" } else { "" }));
            }
            if s.len() > 20 {
                lines.push(format!("… {} more", s.len() - 20));
            }
            Ok(lines.join("\n"))
        }
        Op::Plugins => match c.ext {
            Some(e) if !e.plugins.is_empty() => {
                let mut lines = vec![format!("{} plugin(s):", e.plugins.len())];
                for p in &e.plugins {
                    lines.push(format!("- {}{}", p.name, if p.commands.is_empty() { String::new() } else { format!(" · {} command(s)", p.commands.len()) }));
                }
                Ok(lines.join("\n"))
            }
            _ => Ok("no plugins loaded".into()),
        },
        Op::ConfigGet { path } => crate::ops::confcli::get(&c.k.paths, &c.workspace, path).map(|v| crate::slash::redact(&format!("{path} = {v}"))),
        Op::SetDefaultModel { model } => crate::ops::confcli::set(&c.k.paths, "model.default", &format!("{model:?}")).map(|m| format!("{m}\nrestart (/seagent restart) for running channels to pick it up")),
        Op::ConfigSet { path, value } => crate::ops::confcli::set(&c.k.paths, path, value),
        Op::GatewayRestart => restart(60),
    }
}

pub fn rescue(c: &Ctx, a: &str, restart: Spawn) -> Result<String, String> {
    if let Err(e) = rescue_policy(c) {
        return Ok(e);
    }
    match approval_intent(a) {
        Some(true) => {
            let Some(op) = pending_take(c)? else { return Ok("No pending seagent rescue change is waiting for approval.".into()) };
            execute(c, &op, restart).map(|m| if m.is_empty() { "seagent rescue change applied.".into() } else { m })
        }
        Some(false) => Ok(if pending_take(c)?.is_some() { "Dropped the pending seagent rescue change.".into() } else { "No pending seagent rescue change is waiting for approval.".into() }),
        None => {
            let op = parse_op(a);
            if op.persistent() {
                pending_put(c, Some(&op))?;
                return Ok(plan_text(&op));
            }
            // Any fresh command revokes the previous capability for this route.
            pending_put(c, None)?;
            execute(c, &op, restart)
        }
    }
}

pub fn cmd_rescue(c: &Ctx, a: &str) -> Result<Reply, String> {
    text(rescue(c, a, crate::ops::service::restart_detached)?)
}

// ───────────────────────── /restart ─────────────────────────

pub fn restart(c: &Ctx, a: &str, spawn: Spawn) -> Result<String, String> {
    let drain = match a.trim() {
        "" => 60,
        "now" => 0,
        s => s.trim_end_matches('s').parse::<u64>().map_err(|_| "usage: /restart [now|<drain seconds>]".to_string())?.min(3600),
    };
    let _ = c;
    spawn(drain)
}

pub fn cmd_restart(c: &Ctx, a: &str) -> Result<Reply, String> {
    text(restart(c, a, crate::ops::service::restart_detached)?)
}

// ───────────────────────── /pair ─────────────────────────

/// Node methods: in-process inside the daemon (channels / TUI / web), over the socket for `seagent chat`.
fn node_call(c: &Ctx, m: &str, p: Value) -> Result<Value, String> {
    if c.surface == Surface::Cli {
        return seagent_kernel::daemon::call(&c.k.paths.socket(), m, p).map_err(|e| format!("{e} (is the daemon running? `seagent daemon start`)"));
    }
    (seagent_app::node::methods())(m, &p).unwrap_or_else(|| Err((-32601, m.into()))).map_err(|e| e.1)
}

#[cfg(test)]
use seagent_app::lan::SECURE_FIX;

/// The `/node` URL a device should dial and the certificate it must pin. Off loopback this is
/// always `wss://` (LAN mode's own certificate, or `[surfaces] public_url` over https): the
/// address classification and the rule live in `seagent_security::exposure` / `seagent_app::lan`.
pub fn pairing_url(cfg: &seagent_kernel::config::Config, data: &std::path::Path) -> Result<(String, Option<String>), String> {
    let app = seagent_app::lan::effective(&seagent_app::AppConfig::parse(&cfg.app)?, data)?;
    seagent_app::lan::pairing_url(&app, cfg.surfaces.get("public_url").and_then(|v| v.as_str()))
}

pub fn format_pending(v: &Value) -> String {
    let list = v.as_array().cloned().unwrap_or_default();
    if list.is_empty() {
        return "No pending device pairing requests.".into();
    }
    let mut out = vec!["Pending device pairing requests:".to_string()];
    for p in list {
        let mut parts = vec![format!("- {}", p["code"].as_str().unwrap_or(""))];
        if let Some(n) = p["name"].as_str().filter(|s| !s.is_empty()) {
            parts.push(format!("name={n}"));
        }
        if let Some(pl) = p["platform"].as_str().filter(|s| !s.is_empty()) {
            parts.push(format!("platform={pl}"));
        }
        parts.push(format!("id={}", p["id"].as_str().unwrap_or("")));
        out.push(parts.join(" · "));
    }
    out.join("\n")
}

pub fn pair(c: &Ctx, a: &str) -> Result<String, String> {
    let mut w = a.split_whitespace();
    let action = w.next().unwrap_or("").to_lowercase();
    match action.as_str() {
        "status" | "pending" => node_call(c, "node.pair.list", json!({})).map(|v| format_pending(&v)),
        "approve" => {
            let pending = node_call(c, "node.pair.list", json!({}))?;
            let list = pending.as_array().cloned().unwrap_or_default();
            let code = match w.next() {
                Some(code) => code.to_string(),
                None => match list.len() {
                    0 => return Ok("No pending device pairing requests.".into()),
                    1 => list[0]["code"].as_str().unwrap_or("").to_string(),
                    _ => return Ok(format!("Multiple pending requests; use /pair approve <code>.\n{}", format_pending(&pending))),
                },
            };
            if !list.iter().any(|p| p["code"].as_str().is_some_and(|x| x.eq_ignore_ascii_case(&code))) {
                return Ok("Pairing request not found.".into());
            }
            node_call(c, "node.pair.approve", json!({"code": code})).map(|v| format!("Approved device {}.", v["approved"].as_str().unwrap_or("")))
        }
        "reject" | "deny" => {
            let code = w.next().ok_or("usage: /pair reject <code>")?;
            node_call(c, "node.pair.reject", json!({"code": code})).map(|v| if v["rejected"] == true { "Rejected the pairing request.".into() } else { "Pairing request not found.".into() })
        }
        "cleanup" | "clear" | "revoke" => {
            let n = if c.surface == Surface::Cli { return Err("run /pair cleanup from the TUI, web UI or a channel (the daemon owns the setup codes)".into()) } else { seagent_app::node::clear_bootstrap() };
            Ok(if n > 0 { format!("Invalidated {n} unused setup code{}.", if n == 1 { "" } else { "s" }) } else { "No unused setup codes were active.".into() })
        }
        "" | "qr" | "new" | "code" => {
            let app = seagent_app::AppConfig::parse(&c.k.cfg.app)?;
            if !app.enabled || !app.nodes {
                return Ok("Device pairing needs the app server with nodes: set `[app] enabled = true` and `nodes = true`, then /restart.".into());
            }
            let (url, fp) = pairing_url(&c.k.cfg, &c.k.paths.data)?;
            let mut p = json!({"url": url, "ttlMs": 10 * 60_000});
            if let Some(f) = fp {
                p["tlsFingerprint"] = json!(f);
            }
            let r = node_call(c, "node.setup.create", p)?;
            let code = r["code"].as_str().unwrap_or("");
            let mut out = String::from("Pairing setup code generated.\n1) Open the seagent app (or run `seagent node --setup-code CODE`) on the device\n2) Paste the setup code below and connect\n3) Back here, run /pair approve\n\n");
            if action == "qr" {
                match seagent_app::qr::Qr::encode(code.as_bytes()) {
                    Some(q) => out.push_str(&format!("{}\n", q.render(1))),
                    None => out.push_str("(the code is too long for a QR code; paste it instead)\n"),
                }
            }
            out.push_str(&format!("{code}\n\nvalid 10 minutes, single use · {}", r["url"].as_str().unwrap_or(&url)));
            Ok(out)
        }
        other => Err(format!("unknown /pair action `{other}` (qr, pending, approve [code], reject <code>, cleanup)")),
    }
}

pub fn cmd_pair(c: &Ctx, a: &str) -> Result<Reply, String> {
    text(pair(c, a)?)
}

// ───────────────────────── /controlui ─────────────────────────

pub fn controlui(c: &Ctx) -> Result<(String, Option<String>), String> {
    let Some(s) = c.sender.clone().filter(|_| c.surface == Surface::Channel) else {
        return Ok(("/controlui opens the Control UI as a Telegram Mini App; run it in a DM with your Telegram bot (here, use the web UI: `seagent app open`).".into(), None));
    };
    let Some(ch) = c.k.cfg.channels.get(&s.channel).filter(|t| t.get("kind").and_then(|k| k.as_str()).unwrap_or(&s.channel) == "telegram") else {
        return Ok(("/controlui is only available in Telegram.".into(), None));
    };
    if s.group {
        return Ok(("open this in a DM with the bot".into(), None));
    }
    let user = s.sender.trim_start_matches("telegram:").to_string();
    if !crate::ops::miniapp::is_owner(ch, &user) {
        return Ok((format!("Restricted to the bot owner. Ask your seagent administrator to add your numeric Telegram user ID{} to this channel's allow or allow_admin_from, then retry /controlui. Wildcards and usernames do not grant Control UI access.", if user.chars().all(|c| c.is_ascii_digit()) && !user.is_empty() { format!(" ({user})") } else { String::new() }), None));
    }
    let ticket = crate::ops::miniapp::issue_ticket(&s.channel, &user);
    match crate::ops::miniapp::page_url(&c.k.cfg, &s.channel, &ticket) {
        Ok(u) => Ok(("Open seagent Control UI.".into(), Some(u))),
        Err(e) => Ok((e, None)),
    }
}

pub fn cmd_controlui(c: &Ctx, _: &str) -> Result<Reply, String> {
    let (msg, url) = controlui(c)?;
    let Some(url) = url else { return text(msg) };
    // Telegram only permits web_app buttons in private chats; the button carries the
    // `webapp:` scheme the Telegram adapter renders as `{"web_app": {"url"}}`.
    if let (Some(e), Some(s)) = (c.ext, c.sender.as_ref()) {
        if let Some((ch, _)) = e.channels.get(&s.channel) {
            let mut out = seagent_channel::Outbound::text(&s.chat, &msg);
            out.buttons = vec![vec![seagent_channel::Button { label: "Open Control UI".into(), data: String::new(), url: Some(format!("webapp:{url}")) }]];
            if ch.send(&out).is_ok() {
                return Ok(Reply::default());
            }
        }
    }
    text(format!("{msg}\n{url}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slash::Sender;
    use crate::testkit::kit;

    fn ctx<'a>(t: &'a crate::testkit::Kit, surface: Surface, sender: Option<Sender>) -> Ctx<'a> {
        Ctx { k: &t.k, ext: None, session: Some("s1".into()), workspace: t.ws.clone(), surface, sender, notify: None }
    }
    fn dm(admin: bool) -> Option<Sender> {
        Some(Sender { channel: "tg".into(), chat: "42".into(), sender: "42".into(), group: false, admin, gated: true, user_commands: vec![] })
    }
    fn no_spawn(d: u64) -> Result<String, String> {
        Ok(format!("spawned restart drain={d}"))
    }

    #[cfg(unix)]
    #[test]
    fn diagnostics_bundle_is_private_and_redacted() {
        let t = kit();
        std::fs::write(t.paths.user_config(), "[providers.x]\napi_key = \"sk-live-abcdef\"\n").unwrap();
        let mut g = dm(true);
        g.as_mut().unwrap().group = true;
        let c = ctx(&t, Surface::Channel, g);
        assert_eq!(cmd_diagnostics(&c, "").unwrap().text.unwrap(), DIAGNOSTICS_PRIVATE_ROUTE_UNAVAILABLE);
        let c = ctx(&t, Surface::Channel, dm(true));
        let out = cmd_diagnostics(&c, "slow replies").unwrap().text.unwrap();
        assert!(out.contains("sensitive") && out.contains("bundle:"), "{out}");
        let p = std::fs::read_dir(t.paths.data.join("diagnostics")).unwrap().next().unwrap().unwrap().path();
        let body = std::fs::read_to_string(&p).unwrap();
        assert!(!body.contains("sk-live-abcdef") && body.contains("slow replies"));
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// The bundle carries the recent failed tool calls from the tool-call log (every OS).
    #[test]
    fn diagnostics_bundle_includes_recent_tool_failures() {
        let t = kit();
        let log = crate::ops::toollog::Log::new(t.paths.log_dir(), Default::default());
        let now = seagent_kernel::event::now_ms();
        log.append(&json!({"ts": now - 5000, "session": "s1", "id": "a", "tool": "shell", "args": "command=make", "ms": 3, "ok": false, "err": "make: *** [all] Error 2"}));
        log.append(&json!({"ts": now - 4000, "session": "s1", "id": "b", "tool": "read", "args": "path=x", "ms": 1, "ok": true}));
        log.flush();
        let c = ctx(&t, Surface::Channel, dm(true));
        let out = cmd_diagnostics(&c, "").unwrap().text.unwrap();
        assert!(out.contains("1 failed tool call(s)"), "{out}");
        let p = std::fs::read_dir(t.paths.data.join("diagnostics")).unwrap().next().unwrap().unwrap().path();
        let b: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        let f = b["tool_failures"].as_array().unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!((f[0]["tool"].as_str(), f[0]["err"].as_str()), (Some("shell"), Some("make: *** [all] Error 2")));
    }

    #[test]
    fn rescue_is_two_step_scoped_and_policy_gated() {
        let t = kit();
        let c = ctx(&t, Surface::Channel, dm(false));
        assert!(rescue(&c, "status", no_spawn).unwrap().contains("only accepts commands from an owner"));
        let mut g = dm(true);
        g.as_mut().unwrap().group = true;
        assert!(rescue(&ctx(&t, Surface::Channel, g), "status", no_spawn).unwrap().contains("owner DMs"));
        let c = ctx(&t, Surface::Channel, dm(true));
        assert!(rescue(&c, "status", no_spawn).unwrap().contains("model echo/m"));
        assert!(rescue(&c, "", no_spawn).unwrap().starts_with("Tiny claw tap"));
        assert!(rescue(&c, "doctor fix", no_spawn).unwrap().contains("seagent doctor --fix"));
        assert_eq!(rescue(&c, "yes", no_spawn).unwrap(), "No pending seagent rescue change is waiting for approval.");
        let plan = rescue(&c, "set model openai/gpt-5", no_spawn).unwrap();
        assert!(plan.contains("model.default = openai/gpt-5") && plan.contains("/seagent yes"), "{plan}");
        // Another route cannot approve it.
        let mut other = dm(true);
        other.as_mut().unwrap().sender = "99".into();
        assert!(rescue(&ctx(&t, Surface::Channel, other), "yes", no_spawn).unwrap().starts_with("No pending"));
        let applied = rescue(&c, "yes.", no_spawn).unwrap();
        assert!(applied.contains("model.default"), "{applied}");
        assert!(std::fs::read_to_string(t.paths.user_config()).unwrap().contains("openai/gpt-5"));
        // Restart is persistent too; a fresh command revokes the pending one.
        assert!(rescue(&c, "restart", no_spawn).unwrap().contains("Planned change"));
        rescue(&c, "models", no_spawn).unwrap();
        assert!(rescue(&c, "yes", no_spawn).unwrap().starts_with("No pending"));
        rescue(&c, "restart", no_spawn).unwrap();
        assert_eq!(rescue(&c, "go ahead", no_spawn).unwrap(), "spawned restart drain=60");
        rescue(&c, "config set learn.enabled true", no_spawn).unwrap();
        assert_eq!(rescue(&c, "nope", no_spawn).unwrap(), "Dropped the pending seagent rescue change.");
        // Sandboxing blocks rescue entirely.
        std::fs::write(t.paths.user_config(), "[exec.sandbox]\nmode = \"all\"\n").unwrap();
        assert!(rescue(&c, "status", no_spawn).unwrap().contains("sandboxing is active"));
        assert_eq!(approval_intent("Sounds good!"), Some(true));
        assert_eq!(approval_intent("cancel that"), Some(false));
        assert_eq!(approval_intent("status"), None);
    }

    #[test]
    fn rescue_read_verbs_report_state_without_writing() {
        let t = crate::testkit::kit_with(|c| {
            c.channels.insert("tg".into(), "kind = \"telegram\"\nallow = [\"42\"]\nallow_admin_from = [\"42\"]\ntoken = \"123:ABC\"\n".parse().unwrap());
            c.channels.insert("slack".into(), "kind = \"slack\"\n".parse().unwrap());
        });
        let c = ctx(&t, Surface::Channel, dm(true));
        let before = std::fs::read_to_string(t.paths.user_config()).unwrap_or_default();
        let o = rescue(&c, "overview", no_spawn).unwrap();
        assert!(o.contains("channel(s): slack, tg") && o.contains("config valid") && o.contains("doctor"), "{o}");
        let d = rescue(&c, "doctor", no_spawn).unwrap();
        assert!(d.starts_with("seagent doctor:"), "{d}");
        assert!(d.contains("no findings") || d.contains("finding(s) across"), "{d}");
        let v = rescue(&c, "config validate", no_spawn).unwrap();
        assert!(v.starts_with("config valid") || v.starts_with("config INVALID"), "{v}");
        let chs = rescue(&c, "channels", no_spawn).unwrap();
        assert!(chs.contains("- tg (telegram)") && chs.contains("- slack (slack)") && chs.contains("allow 1"), "{chs}");
        let ch = rescue(&c, "channel tg", no_spawn).unwrap();
        assert!(ch.contains("kind telegram") && ch.contains("token set") && ch.contains("allow: 42"), "{ch}");
        assert!(rescue(&c, "channel nope", no_spawn).unwrap_err().contains("unknown channel `nope`"));
        let g = rescue(&c, "gateway status", no_spawn).unwrap();
        assert!(g.contains("daemon:") && g.contains("app listen:") && g.contains("service issues:"), "{g}");
        assert_eq!(rescue(&c, "agents", no_spawn).unwrap(), "no sessions yet");
        assert_eq!(rescue(&c, "plugins", no_spawn).unwrap(), "no plugins loaded");
        assert!(rescue(&c, "gateway start", no_spawn).unwrap().contains("cannot start or stop the daemon"));
        assert!(rescue(&c, "frobnicate", no_spawn).unwrap().contains("overview, doctor"));
        // Every read verb is model-free and write-free, and none leaves an approval behind.
        assert_eq!(std::fs::read_to_string(t.paths.user_config()).unwrap_or_default(), before);
        assert!(rescue(&c, "yes", no_spawn).unwrap().starts_with("No pending"));
        assert!(parse_op("doctor") == Op::Doctor && parse_op("gateway") == Op::GatewayStatus && parse_op("channel tg") == Op::Channel { name: "tg".into() });
        assert!(Op::GatewayRestart.persistent() && !Op::Doctor.persistent() && !Op::Overview.persistent());
    }

    #[test]
    fn restart_parses_drain() {
        let t = kit();
        let c = ctx(&t, Surface::Tui, None);
        assert_eq!(restart(&c, "", no_spawn).unwrap(), "spawned restart drain=60");
        assert_eq!(restart(&c, "now", no_spawn).unwrap(), "spawned restart drain=0");
        assert_eq!(restart(&c, "15s", no_spawn).unwrap(), "spawned restart drain=15");
        assert!(restart(&c, "soon", no_spawn).is_err());
    }

    #[test]
    fn pair_urls_codes_and_approval() {
        let home = seagent_core::tmp::TempDir::new("seagent-pair-url");
        let mut cfg = seagent_kernel::config::Config::default();
        cfg.surfaces.insert("public_url".into(), toml::Value::String("https://seagent.example.com/".into()));
        assert_eq!(pairing_url(&cfg, home.path()).unwrap().0, "wss://seagent.example.com/node");
        // Cleartext pairing off this machine is gone, LAN addresses included.
        cfg.surfaces.insert("public_url".into(), toml::Value::String("http://192.168.1.5:8640".into()));
        assert_eq!(pairing_url(&cfg, home.path()).unwrap_err(), SECURE_FIX);
        let lo = seagent_kernel::config::Config::default();
        assert_eq!(pairing_url(&lo, home.path()).unwrap().0, "ws://127.0.0.1:8640/node");
        let mut lan = seagent_kernel::config::Config::default();
        lan.app.insert("listen".into(), toml::Value::String("192.168.1.5:8640".into()));
        lan.app.insert("exposure".into(), toml::Value::Table("lan = true".parse::<toml::Table>().unwrap()));
        let (u, fp) = pairing_url(&lan, home.path()).unwrap();
        assert_eq!(u, "wss://192.168.1.5:8640/node");
        assert_eq!(fp.unwrap().len(), 64);
        assert_eq!(format_pending(&json!([])), "No pending device pairing requests.");
        assert_eq!(format_pending(&json!([{"code": "AB12", "id": "n1", "name": "phone", "platform": "android"}])), "Pending device pairing requests:\n- AB12 · name=phone · platform=android · id=n1");

        let t = crate::testkit::kit_with(|c| {
            c.app.insert("enabled".into(), toml::Value::Boolean(true));
            c.app.insert("nodes".into(), toml::Value::Boolean(true));
        });
        let c = ctx(&t, Surface::Tui, None);
        let out = pair(&c, "").unwrap();
        assert!(out.contains("Pairing setup code generated") && out.contains("ws://127.0.0.1:8640/node"), "{out}");
        let code = out.lines().find(|l| l.len() > 40 && !l.contains(' ')).unwrap();
        let sc = seagent_app::node::SetupCode::decode(code, seagent_kernel::event::now_ms()).unwrap();
        assert_eq!(sc.url, "ws://127.0.0.1:8640/node");
        assert!(pair(&c, "cleanup").unwrap().starts_with("Invalidated"));
        assert_eq!(pair(&c, "approve").unwrap(), "No pending device pairing requests.");
        assert_eq!(pair(&c, "approve ZZZZ").unwrap(), "Pairing request not found.");
        assert!(pair(&c, "frobnicate").is_err());
    }

    #[test]
    fn controlui_owner_dm_only() {
        let t = crate::testkit::kit_with(|c| {
            c.surfaces.insert("public_url".into(), toml::Value::String("https://seagent.example.ts.net".into()));
            c.channels.insert("tg".into(), "kind = \"telegram\"\nallow = [\"42\"]\n".parse().unwrap());
        });
        let (m, u) = controlui(&ctx(&t, Surface::Web, None)).unwrap();
        assert!(m.contains("Telegram") && u.is_none());
        let mut g = dm(true);
        g.as_mut().unwrap().group = true;
        assert_eq!(controlui(&ctx(&t, Surface::Channel, g)).unwrap().0, "open this in a DM with the bot");
        let mut stranger = dm(false);
        stranger.as_mut().unwrap().sender = "7".into();
        assert!(controlui(&ctx(&t, Surface::Channel, stranger)).unwrap().0.contains("Restricted to the bot owner"));
        let (m, u) = controlui(&ctx(&t, Surface::Channel, dm(false))).unwrap();
        let u = u.unwrap();
        assert_eq!(m, "Open seagent Control UI.");
        assert!(u.starts_with("https://seagent.example.ts.net/tg-miniapp/?channel=tg#launchTicket="), "{u}");
        let ticket = u.split("launchTicket=").nth(1).unwrap();
        assert!(crate::ops::miniapp::consume_ticket(&seagent_net::urldecode(ticket), "tg", "42"));
    }
}
