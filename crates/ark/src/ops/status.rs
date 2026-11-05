//! `ark status` (Hermes `hermes status`, OpenClaw `status`): one place that answers "what
//! is this install configured to do, and is it doing it right now".
//!
//! Print order follows upstream's `_SECTIONS`: banner, Environment, API keys, Terminal
//! backend, Messaging platforms, Gateway service, Scheduled jobs, Sessions, Deep checks,
//! footer. The default is the one-screen summary (model, provider, connected providers,
//! gateway, platforms, jobs, sessions, workspace, service). `--full`/`--all` prints every
//! section, `--deep` implies full and adds local checks, `--json` prints one machine-readable
//! object with a key per section (the same data whatever the other flags are).
//!
//! `--deep` never touches the network — probing a model endpoint is `ark providers check`.
//! It validates that the config parses, that the default model names a known provider with
//! usable credentials, that every `[channels.*]` table parses, that the workspace is
//! writable, that `secrets.toml` is not group/world readable and that `[exec]` parses.
//!
//! Exit codes: `0` for the summary and `--full` whatever they find; `--deep` exits `1` when
//! one of the checks above is a blocking problem and `0` otherwise. `ark status health`
//! exits `1` when arkd is not answering; `ark status sessions` always exits `0`.
//!
//! Secret values never reach the output: providers are reported by *where* a credential
//! comes from (`Providers::key_source`: "vault", "environment", "config", …), never by its
//! value, and every rendered line is passed through `Vault::redact` as a last line of
//! defence.

use crate::args::Args;
use crate::ops::service::Issue;
use crate::R;
use ark_kernel::automation::{self, Job};
use ark_kernel::config::{Config, Paths};
use ark_kernel::vault::Vault;
use ark_tools::exec::ExecConfig;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const COMMANDS: &[&str] = &["status"];
pub const VALUE_FLAGS: &[&str] = &[];
/// `--all`, `--deep` and `--json` are global switches; `--full` is ours.
pub const BOOL_FLAGS: &[&str] = &["full"];

/// Width of the `  Label:      value` column (upstream `_kv`).
const LABEL_WIDTH: usize = 14;
/// How long a status probe waits for arkd before calling it unresponsive.
const RPC_TIMEOUT: Duration = Duration::from_millis(1500);

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd != "status" {
        return None;
    }
    Some(run(&Paths::from_env(), a))
}

/// Command body, parameterised on the paths so tests can point it at a temp layout.
pub fn run(paths: &Paths, a: &Args) -> R {
    let ws = crate::workspace(a)?;
    run_in(paths, ws, a)
}

pub fn run_in(paths: &Paths, ws: PathBuf, a: &Args) -> R {
    (|| -> R {
        match a.pos(0) {
            None => {}
            // Small sub-forms: a session overview, and "is arkd answering right now".
            Some("sessions") => {
                let st = snapshot(paths, ws, Ok(Config::default()), false);
                if a.flag("json") {
                    println!("{}", st.vault.redact(&json!({"sessions": sessions_json(&st.sessions)}).to_string()));
                } else {
                    let mut o = String::new();
                    sessions_section(&mut o, &st);
                    print!("{}", st.vault.redact(&o));
                }
                return Ok(0);
            }
            Some("health") => return health(paths, a),
            Some(other) => return crate::usage(format!("unknown `status {other}` (sessions, health)")),
        }
        let deep = a.flag("deep");
        let cfg = crate::load_config(a, &ws, paths).map_err(|e| e.to_string());
        let st = snapshot(paths, ws, cfg, deep);
        if a.flag("json") {
            println!("{}", report_json(&st));
        } else {
            let mode = if a.flag("full") || a.flag("all") || deep { Mode::Full } else { Mode::Summary };
            print!("{}", report(&st, mode));
        }
        Ok(exit_code(&st, deep))
    })()
}

/// `ark status health`: OpenClaw `health` — one question, one exit code.
fn health(paths: &Paths, a: &Args) -> R {
    let d = daemon_state(paths);
    let vault = load_vault(paths);
    if a.flag("json") {
        let v = json!({
            "ok": d.running,
            "socket": d.socket.display().to_string(),
            "socketExists": d.socket_exists,
            "pid": d.pid,
            "version": d.version.clone(),
            "uptimeSecs": d.uptime_secs,
            "runningSessions": d.running_sessions,
            "error": d.ping_error.clone(),
        });
        println!("{}", vault.redact(&v.to_string()));
    } else if d.running {
        let mut bits = vec![format!("socket {}", d.socket.display())];
        if let Some(pid) = d.pid {
            bits.push(format!("pid {pid}"));
        }
        if let Some(v) = &d.version {
            bits.push(format!("version {v}"));
        }
        if let Some(up) = d.uptime_secs {
            bits.push(format!("up {}", duration(up)));
        }
        bits.push(format!("{} running session(s)", d.running_sessions));
        println!("✓ arkd: running ({})", bits.join(", "));
    } else {
        println!("✗ arkd: not running ({})", d.ping_error.clone().unwrap_or_else(|| format!("no daemon at {}", d.socket.display())));
        println!("  start it with `ark daemon start`");
    }
    Ok(if d.running { 0 } else { 1 })
}

// ───────────────────────── collected state ─────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRow {
    pub id: String,
    /// Where the credential comes from — never the credential itself.
    pub source: String,
    pub ok: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRow {
    pub name: String,
    pub kind: String,
    /// `dm_policy = "disabled"` switches a channel off without deleting its table.
    pub enabled: bool,
    /// `Some` only when arkd answered and listed its channels.
    pub running: Option<bool>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Daemon {
    pub socket: PathBuf,
    pub socket_exists: bool,
    /// Socket on disk but nothing answering and no live pid.
    pub stale: bool,
    pub running: bool,
    pub pid: Option<i32>,
    pub alive: bool,
    pub version: Option<String>,
    pub uptime_secs: Option<i64>,
    pub running_sessions: usize,
    pub ping_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cron {
    pub total: usize,
    pub enabled: usize,
    pub next_run: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sessions {
    pub count: usize,
    pub running: Option<usize>,
    pub newest: Option<String>,
    pub newest_ms: Option<u64>,
}

/// One row of the `--deep` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    /// A blocking problem makes `--deep` exit non-zero.
    pub blocking: bool,
    pub detail: String,
}

pub struct Status {
    pub workspace: PathBuf,
    pub paths: Paths,
    pub profile: String,
    pub version: &'static str,
    pub cfg: Option<Config>,
    pub config_error: Option<String>,
    pub model: String,
    pub provider: Option<ProviderRow>,
    /// Providers worth reporting: the default model's, `[providers.*]` overrides, and any
    /// provider that actually has a credential.
    pub providers: Vec<ProviderRow>,
    pub provider_error: Option<String>,
    pub channels: Vec<ChannelRow>,
    pub exec: Result<ExecConfig, String>,
    pub daemon: Daemon,
    pub service_unit: String,
    pub service: Vec<Issue>,
    pub restarts: usize,
    pub cron: Cron,
    pub sessions: Sessions,
    pub deep: bool,
    pub checks: Vec<Check>,
    vault: Arc<Vault>,
}

fn load_vault(paths: &Paths) -> Arc<Vault> {
    // A secrets file with wrong permissions is reported by the deep checks; the vault is
    // then left empty so nothing else fails.
    Vault::load(&paths.secrets()).map(Arc::new).unwrap_or_else(|_| Arc::new(Vault::empty()))
}

/// Collect everything `ark status` shows. `cfg` carries the load error so the report can
/// still be rendered for a broken config (and `--deep` can turn it into an exit code).
pub fn snapshot(paths: &Paths, workspace: PathBuf, cfg: Result<Config, String>, deep: bool) -> Status {
    let vault = load_vault(paths);
    let (cfg, config_error) = match cfg {
        Ok(c) => (Some(c), None),
        Err(e) => (None, Some(e)),
    };
    let model = cfg.as_ref().map(|c| c.model.default.trim().to_string()).unwrap_or_default();
    let exec = crate::exec_cli::exec_config(paths);
    let daemon = daemon_state(paths);
    let running_channels = if daemon.running { live_channel_names(&daemon.socket) } else { None };
    let channels = channel_rows(cfg.as_ref(), running_channels.as_ref());
    let (provider, providers, provider_error) = provider_rows(cfg.as_ref(), &vault, &model);
    let mut sessions = session_stats(paths);
    sessions.running = daemon.running.then_some(daemon.running_sessions);
    let mut st = Status {
        workspace,
        paths: paths.clone(),
        profile: crate::ops::profile::current(),
        version: env!("CARGO_PKG_VERSION"),
        model,
        provider,
        providers,
        provider_error,
        channels,
        exec,
        daemon,
        service_unit: crate::ops::service::unit_name(),
        service: Vec::new(),
        restarts: 0,
        cron: cron_state(paths),
        sessions,
        deep,
        checks: Vec::new(),
        cfg,
        config_error,
        vault,
    };
    st.service = crate::ops::service::audit(&st.workspace);
    st.restarts = crate::ops::service::recent_starts(paths, ark_kernel::util::unix_now()).len();
    st.checks = deep_checks(&st);
    st
}

// ───────────────────────── daemon ─────────────────────────

fn pid_alive(pid: i32) -> bool {
    pid > 0 && unsafe { libc::kill(pid, 0) } == 0
}

/// Minimal JSON-RPC call with a short timeout: `daemon::call` waits 30s, far too long for a
/// status line.
fn rpc(socket: &Path, method: &str, params: Value) -> Result<Value, String> {
    let mut s = ark_kernel::daemon::connect(socket)?;
    s.set_read_timeout(Some(RPC_TIMEOUT)).ok();
    s.set_write_timeout(Some(RPC_TIMEOUT)).ok();
    let mut line = serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})).map_err(|e| e.to_string())?;
    line.push(b'\n');
    s.write_all(&line).map_err(|e| e.to_string())?;
    let mut out = String::new();
    BufReader::new(s).read_line(&mut out).map_err(|e| format!("arkd did not answer: {e}"))?;
    let v: Value = serde_json::from_str(&out).map_err(|_| "arkd sent an unreadable reply".to_string())?;
    match v.get("error") {
        Some(err) => Err(err.get("message").and_then(|m| m.as_str()).unwrap_or("arkd returned an error").to_string()),
        None => Ok(v.get("result").cloned().unwrap_or(Value::Null)),
    }
}

/// `<data>/restarts.log` is written by arkd at every start (`ops::service`); the last entry
/// names the version that is (or was last) running.
fn logged_version(paths: &Paths) -> Option<String> {
    let text = std::fs::read_to_string(paths.data.join("restarts.log")).ok()?;
    text.lines().rev().find_map(|l| l.split("version=").nth(1).map(|v| v.trim().to_string())).filter(|v| !v.is_empty())
}

fn daemon_state(paths: &Paths) -> Daemon {
    let socket = paths.socket();
    let socket_exists = socket.exists();
    let pid_path = paths.runtime.join("arkd.pid");
    let file_pid = std::fs::read_to_string(&pid_path).ok().and_then(|s| s.trim().parse::<i32>().ok());
    let alive = file_pid.is_some_and(pid_alive);
    let uptime_secs = std::fs::metadata(&pid_path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| ark_kernel::util::unix_now() - d.as_secs() as i64)
        .filter(|s| *s >= 0);
    let ping = if socket_exists { rpc(&socket, "ping", json!({})) } else { Err(format!("no socket at {}", socket.display())) };
    let (live, ping_error) = match ping {
        Ok(v) => (Some(v), None),
        Err(e) => (None, Some(e)),
    };
    // A live RPC wins; otherwise a socket next to a live pid still counts as running (the
    // daemon may be busy), and a socket with nothing behind it is stale.
    let running = live.is_some() || (socket_exists && alive);
    let pid = live.as_ref().and_then(|v| v.get("pid").and_then(|p| p.as_i64())).map(|p| p as i32).or(file_pid);
    let version = live.as_ref().and_then(|v| v.get("version").and_then(|s| s.as_str()).map(String::from)).or_else(|| logged_version(paths));
    let running_sessions = live.as_ref().and_then(|v| v.get("running").and_then(|r| r.as_array()).map(Vec::len)).unwrap_or(0);
    Daemon { socket, socket_exists, stale: socket_exists && !running, running, pid, alive, version, uptime_secs, running_sessions, ping_error }
}

/// Channel names arkd reports as live (`channels.list`); `None` when it could not be asked.
fn live_channel_names(socket: &Path) -> Option<Vec<String>> {
    let v = rpc(socket, "channels.list", json!({})).ok()?;
    Some(v.as_array()?.iter().filter_map(|c| c.get("name").and_then(|n| n.as_str()).map(String::from)).collect())
}

// ───────────────────────── channels, providers, cron, sessions ─────────────────────────

fn channel_rows(cfg: Option<&Config>, running: Option<&Vec<String>>) -> Vec<ChannelRow> {
    let Some(cfg) = cfg else { return Vec::new() };
    cfg.channels
        .iter()
        .map(|(name, table)| {
            let json = serde_json::to_value(table).unwrap_or(Value::Null);
            match ark_channel::config::parse_config(name, &json) {
                Ok(c) => ChannelRow {
                    name: name.clone(),
                    kind: c.kind.clone(),
                    enabled: c.policy.dm_policy != ark_channel::access::DmPolicy::Disabled,
                    running: running.map(|r| r.contains(name)),
                    error: None,
                },
                Err(e) => ChannelRow { name: name.clone(), kind: String::new(), enabled: false, running: running.map(|r| r.contains(name)), error: Some(e) },
            }
        })
        .collect()
}

fn provider_row(reg: &crate::providers::Providers, id: &str) -> ProviderRow {
    match reg.key_source(id) {
        Ok(src) => ProviderRow { id: id.to_string(), source: src.to_string(), ok: true },
        Err(e) => ProviderRow { id: id.to_string(), source: e, ok: false },
    }
}

/// Credentials ark can actually see. `key_source` also answers "none needed" (local servers)
/// and provider-level claims ("AWS credentials", "Google Cloud credentials", "Entra ID");
/// those are not a connected provider, so they never count as one in the summary.
fn has_credentials(p: &ProviderRow) -> bool {
    p.ok && matches!(p.source.as_str(), "vault" | "environment" | "config" | "credential store" | "key_cmd")
}

fn provider_rows(cfg: Option<&Config>, vault: &Arc<Vault>, model: &str) -> (Option<ProviderRow>, Vec<ProviderRow>, Option<String>) {
    let Some(cfg) = cfg else { return (None, Vec::new(), Some("config does not parse".into())) };
    let reg = match crate::providers::Providers::new(&cfg.providers, vault.clone()) {
        Ok(r) => r,
        Err(e) => return (None, Vec::new(), Some(e)),
    };
    let pid = ark_kernel::context::split_model(model).0.to_string();
    let provider = (!pid.is_empty()).then(|| provider_row(&reg, &pid));
    let rows = reg
        .configs()
        .keys()
        .map(|id| provider_row(&reg, id))
        .filter(|r| Some(r.id.as_str()) == Some(pid.as_str()) || cfg.providers.contains_key(&r.id) || has_credentials(r))
        .collect();
    (provider, rows, None)
}

fn cron_state(paths: &Paths) -> Cron {
    match automation::read_list::<Job>(&automation::jobs_path(&paths.data)) {
        Err(e) => Cron { error: Some(e), ..Cron::default() },
        Ok(jobs) => Cron {
            total: jobs.len(),
            enabled: jobs.iter().filter(|j| j.enabled).count(),
            next_run: jobs.iter().filter(|j| j.enabled).map(|j| j.next_run).min(),
            error: None,
        },
    }
}

/// Session count and newest activity straight from `<data>/sessions/*/events.jsonl` — no
/// event parsing, so `ark status` stays instant on a large home.
fn session_stats(paths: &Paths) -> Sessions {
    let mut out = Sessions::default();
    let Ok(rd) = std::fs::read_dir(paths.sessions()) else { return out };
    for e in rd.flatten() {
        let Ok(m) = std::fs::metadata(e.path().join("events.jsonl")) else { continue };
        out.count += 1;
        let ms = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0);
        if out.newest_ms.is_none_or(|x| ms > x) {
            out.newest_ms = Some(ms);
            out.newest = Some(e.file_name().to_string_lossy().to_string());
        }
    }
    out
}

// ───────────────────────── deep checks (local only) ─────────────────────────

fn deep_checks(st: &Status) -> Vec<Check> {
    let mut out = Vec::new();
    let cfg_path = st.paths.user_config();
    match (&st.cfg, &st.config_error) {
        (Some(_), _) => out.push(Check { name: "config", ok: true, blocking: true, detail: format!("parses ({})", cfg_path.display()) }),
        (None, err) => out.push(Check { name: "config", ok: false, blocking: true, detail: err.clone().unwrap_or_else(|| "does not parse".into()) }),
    }
    match (&st.cfg, &st.provider) {
        (None, _) => out.push(Check { name: "model", ok: false, blocking: false, detail: "not checked: the config does not parse".into() }),
        (Some(_), None) if st.model.is_empty() => out.push(Check { name: "model", ok: false, blocking: true, detail: "model.default is not set (ark setup)".into() }),
        (Some(_), Some(p)) if p.ok => out.push(Check { name: "model", ok: true, blocking: true, detail: format!("{} → provider {} ({})", st.model, p.id, key_phrase(p)) }),
        (Some(_), Some(p)) => out.push(Check { name: "model", ok: false, blocking: true, detail: format!("{} → {}: {}", st.model, p.id, p.source) }),
        (Some(_), None) => out.push(Check { name: "model", ok: false, blocking: true, detail: format!("{} has no provider", st.model) }),
    }
    let bad: Vec<String> = st.channels.iter().filter_map(|c| c.error.clone()).collect();
    out.push(Check {
        name: "channels",
        ok: bad.is_empty(),
        blocking: true,
        detail: if bad.is_empty() { format!("{} configured, all parse", st.channels.len()) } else { bad.join("; ") },
    });
    let writable = unsafe { libc::access(std::ffi::CString::new(st.workspace.as_os_str().as_encoded_bytes()).unwrap_or_default().as_ptr(), libc::W_OK) } == 0;
    out.push(Check { name: "workspace", ok: writable, blocking: true, detail: if writable { format!("writable ({})", st.workspace.display()) } else { format!("not writable ({})", st.workspace.display()) } });
    let secrets = st.paths.secrets();
    let mode = secret_mode(&secrets);
    out.push(Check {
        name: "secrets",
        ok: mode.is_none_or(|m| m & 0o077 == 0),
        blocking: true,
        detail: match mode {
            None => "no secrets.toml yet (ark secrets set NAME)".into(),
            Some(m) if m & 0o077 == 0 => format!("{} ({m:04o})", secrets.display()),
            Some(m) => format!("{} is {m:04o}; `ark secrets` keeps it 0600", secrets.display()),
        },
    });
    out.push(match (&st.exec, &st.config_error) {
        // `[exec]` lives in the same file: a broken config is already reported above.
        (Err(_), Some(_)) => Check { name: "exec", ok: false, blocking: false, detail: "not checked: the config does not parse".into() },
        (Ok(c), _) => Check { name: "exec", ok: true, blocking: true, detail: format!("[exec] parses (backend {})", c.backend) },
        (Err(e), _) => Check { name: "exec", ok: false, blocking: true, detail: format!("[exec] does not parse: {e}") },
    });
    // Informational: ark works without arkd, it just does less.
    let d = &st.daemon;
    out.push(Check {
        name: "arkd",
        ok: d.running,
        blocking: false,
        detail: match (d.running, d.stale, d.socket_exists) {
            (true, _, _) => format!("answering on {}", d.socket.display()),
            (false, true, _) => format!("stale socket at {} (ark daemon start)", d.socket.display()),
            (false, false, true) => format!("socket {} exists but nothing answers", d.socket.display()),
            _ => "not running (schedules, channels and send/attach are idle)".into(),
        },
    });
    out
}

/// Documented exit code: only `--deep` can fail, and only on a blocking finding.
pub fn exit_code(st: &Status, deep: bool) -> i32 {
    i32::from(deep && st.checks.iter().any(|c| !c.ok && c.blocking))
}

// ───────────────────────── rendering ─────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Summary,
    Full,
}

fn mark(ok: bool) -> &'static str {
    if ok { "✓" } else { "✗" }
}

/// Errors from toml/serde arrive multi-line; status rows are one line each.
fn one_line(s: &str) -> String {
    s.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(" ")
}

fn kv(o: &mut String, label: &str, value: impl std::fmt::Display) {
    o.push_str(&format!("  {label:<LABEL_WIDTH$}{}\n", one_line(&value.to_string())));
}

fn kv_flag(o: &mut String, label: &str, ok: bool, on: &str, off: &str) {
    kv(o, label, format!("{} {}", mark(ok), if ok { on } else { off }));
}

/// `  name        ✓ text` — upstream `_row`.
fn row(o: &mut String, name: &str, ok: bool, text: &str) {
    o.push_str(&format!("  {name:<12}  {} {}\n", mark(ok), one_line(text)));
}

fn section(o: &mut String, title: &str) {
    o.push_str(&format!("\n◆ {title}\n"));
}

fn banner(o: &mut String) {
    let bar = "─".repeat(58);
    o.push_str(&format!("┌{bar}┐\n│{:^58}│\n└{bar}┘\n", "ark — agent status"));
}

fn duration(secs: i64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h {}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d", s / 86_400),
    }
}

fn ago(secs: i64) -> String {
    if secs < 60 { "just now".into() } else { format!("{} ago", duration(secs)) }
}

fn secret_mode(path: &Path) -> Option<u32> {
    std::fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o777)
}

fn offset(st: &Status) -> i32 {
    st.cfg.as_ref().map(|c| c.schedule.utc_offset_minutes).unwrap_or(0)
}

fn gateway_line(d: &Daemon) -> String {
    if d.running {
        let mut bits = Vec::new();
        if let Some(pid) = d.pid {
            bits.push(format!("pid {pid}"));
        }
        if let Some(up) = d.uptime_secs {
            bits.push(format!("up {}", duration(up)));
        }
        if bits.is_empty() { "✓ running".into() } else { format!("✓ running ({})", bits.join(", ")) }
    } else if d.stale {
        format!("✗ stopped (stale socket {})", d.socket.display())
    } else {
        "✗ stopped (ark daemon start)".into()
    }
}

fn platforms_line(channels: &[ChannelRow]) -> String {
    if channels.is_empty() {
        return "none configured".into();
    }
    channels.iter().map(|c| format!("{} ({})", c.name, if c.error.is_some() { "invalid" } else if c.enabled { c.kind.as_str() } else { "disabled" })).collect::<Vec<_>>().join(", ")
}

fn cron_line(c: &Cron) -> String {
    if let Some(e) = &c.error {
        return format!("✗ {e}");
    }
    format!("{} active, {} total", c.enabled, c.total)
}

fn sessions_line(s: &Sessions) -> String {
    let mut line = format!("{}", s.count);
    if let Some(r) = s.running {
        line.push_str(&format!(" · {r} running"));
    }
    match s.newest_ms {
        Some(ms) => line.push_str(&format!(" · last active {}", ago(ark_kernel::util::unix_now() - (ms / 1000) as i64))),
        None => line.push_str(" · none yet"),
    }
    line
}

fn key_phrase(p: &ProviderRow) -> String {
    match p.source.as_str() {
        "none needed" => "no key needed".to_string(),
        s if has_credentials(p) => format!("key from {s}"),
        s => s.to_string(),
    }
}

fn service_line(unit: &str, issues: &[Issue]) -> String {
    if issues.is_empty() {
        format!("✓ {unit} matches this version")
    } else if issues.iter().all(|i| i.code == "unit-missing") {
        format!("· {unit} is not installed (ark service install)")
    } else {
        format!("✗ {} issue(s) — ark service audit", issues.len())
    }
}

/// Every human/JSON report is redacted here: one place, so no section can leak a value.
pub fn report(st: &Status, mode: Mode) -> String {
    let raw = match mode {
        Mode::Summary => summary(st),
        Mode::Full => full(st),
    };
    st.vault.redact(&raw)
}

pub fn report_json(st: &Status) -> String {
    st.vault.redact(&json_report(st).to_string())
}

fn summary(st: &Status) -> String {
    let mut o = String::new();
    banner(&mut o);
    o.push('\n');
    kv(&mut o, "Model:", if st.model.is_empty() { "(not set — ark setup)".to_string() } else { st.model.clone() });
    let provider = match (&st.provider, &st.provider_error) {
        (Some(p), _) if p.ok => format!("{} {} ({})", mark(true), p.id, key_phrase(p)),
        (Some(p), _) => format!("{} {} ({})", mark(false), p.id, p.source),
        (None, Some(e)) => format!("{} {}", mark(false), e),
        (None, None) => format!("{} no default model (ark setup)", mark(false)),
    };
    kv(&mut o, "Provider:", provider);
    let connected: Vec<&str> = st.providers.iter().filter(|p| has_credentials(p)).map(|p| p.id.as_str()).collect();
    kv(&mut o, "Providers:", if connected.is_empty() { "none connected".to_string() } else { connected.join(", ") });
    kv(&mut o, "Gateway:", gateway_line(&st.daemon));
    kv(&mut o, "Platforms:", platforms_line(&st.channels));
    kv(&mut o, "Jobs:", cron_line(&st.cron));
    kv(&mut o, "Sessions:", sessions_line(&st.sessions));
    kv(&mut o, "Workspace:", st.workspace.display());
    kv(&mut o, "Service:", service_line(&st.service_unit, &st.service));
    if let Some(e) = &st.config_error {
        kv(&mut o, "Config:", format!("{} {}", mark(false), e));
    }
    o.push_str("\n  Run 'ark status --full' for every section\n\n");
    o
}

fn full(st: &Status) -> String {
    let mut o = String::new();
    banner(&mut o);
    environment_section(&mut o, st);
    api_keys_section(&mut o, st);
    terminal_section(&mut o, st);
    platforms_section(&mut o, st);
    gateway_section(&mut o, st);
    cron_section(&mut o, st);
    sessions_section(&mut o, st);
    if st.deep {
        deep_section(&mut o, st);
    }
    footer(&mut o);
    o
}

fn environment_section(o: &mut String, st: &Status) {
    section(o, "Environment");
    kv(o, "Version:", st.version);
    kv(o, "Profile:", &st.profile);
    kv(o, "Workspace:", st.workspace.display());
    let cfg = st.paths.user_config();
    kv_flag(o, "Config:", cfg.exists(), &cfg.display().to_string(), &format!("not found ({})", cfg.display()));
    let secrets = st.paths.secrets();
    // A4: the secrets may live in an encrypted `secrets.enc`; show whichever file holds them
    // and say which backend unlocked it.
    let store_file = if std::path::Path::new(&secrets.with_extension("enc")).exists() { secrets.with_extension("enc") } else { secrets.clone() };
    let backend = ark_kernel::secretstore::peek_backend(&secrets);
    match secret_mode(&store_file) {
        Some(m) if m & 0o077 == 0 => kv(o, "Secrets:", format!("{} {}{}", mark(true), store_file.display(), backend.map(|b| format!(" ({})", b.as_str())).unwrap_or_default())),
        Some(m) => kv(o, "Secrets:", format!("{} {} ({m:04o} — chmod 600)", mark(false), store_file.display())),
        None => kv(o, "Secrets:", format!("· none yet ({})", secrets.display())),
    }
    let env = st.paths.config_dir.join(".env");
    kv_flag(o, ".env file:", env.exists(), "exists", "not found");
    kv(o, "Data dir:", st.paths.data.display());
    kv(o, "Runtime dir:", st.paths.runtime.display());
    kv(o, "Model:", if st.model.is_empty() { "(not set)".to_string() } else { st.model.clone() });
    match (&st.provider, &st.provider_error) {
        (Some(p), _) if p.ok => kv(o, "Provider:", format!("{} ({})", p.id, key_phrase(p))),
        (Some(p), _) => kv(o, "Provider:", format!("{} {} ({})", mark(false), p.id, p.source)),
        (None, Some(e)) => kv(o, "Provider:", format!("{} {e}", mark(false))),
        (None, None) => kv(o, "Provider:", "(no default model)"),
    }
}

fn api_keys_section(o: &mut String, st: &Status) {
    section(o, "API keys");
    if let Some(e) = &st.provider_error {
        kv(o, "Providers:", format!("{} {e}", mark(false)));
        return;
    }
    if st.providers.is_empty() {
        kv(o, "Keys:", "none configured (ark setup, or ark secrets set ANTHROPIC_API_KEY)");
        return;
    }
    for p in &st.providers {
        // Sources only: a value is never part of `source`.
        row(o, &p.id, p.ok, &p.source);
    }}

fn terminal_section(o: &mut String, st: &Status) {
    section(o, "Terminal backend");
    let backend = match &st.exec {
        Ok(c) => c.backend.clone(),
        Err(_) => "unknown".into(),
    };
    kv(o, "Backend:", &backend);
    let (ok, note) = sandbox_note(&st.exec);
    kv(o, "Sandbox:", format!("{} {note}", mark(ok)));
    if let Err(e) = &st.exec {
        kv(o, "Config:", format!("{} [exec] does not parse: {e}", mark(false)));
    }
}

/// Is the configured exec backend's confinement actually available on this host?
fn sandbox_note(exec: &Result<ExecConfig, String>) -> (bool, String) {
    let Ok(c) = exec else { return (false, "[exec] does not parse".into()) };
    match c.backend.as_str() {
        "local" => (true, "none — commands run as your user (exec.backend = \"local\")".into()),
        "bwrap" => match ark_tools::exec::local::which("bwrap") {
            Some(p) => (true, format!("bwrap at {}", p.display())),
            None => (false, "bwrap is not installed".into()),
        },
        "landlock" => {
            let lsm = std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_default();
            let on = lsm.split(',').any(|m| m.trim() == "landlock");
            (on, if on { "landlock is active in this kernel".into() } else { "landlock is not in the kernel's active LSM list".into() })
        }
        "docker" | "podman" => match ark_tools::exec::local::which(&c.backend) {
            Some(p) => (true, format!("{} at {}", c.backend, p.display())),
            None => (false, format!("{} is not installed", c.backend)),
        },
        other => (true, format!("{other} backend configured")),
    }
}

fn platforms_section(o: &mut String, st: &Status) {
    section(o, "Messaging platforms");
    if st.channels.is_empty() {
        kv(o, "Channels:", "none configured ([channels.<name>] kind = \"telegram\"… )");
        return;
    }
    for c in &st.channels {
        if let Some(e) = &c.error {
            row(o, &c.name, false, &format!("invalid — {e}"));
            continue;
        }
        let state = if c.enabled { "enabled" } else { "disabled" };
        let live = match c.running {
            Some(true) => "running",
            Some(false) => "not running",
            None => "unknown (arkd stopped)",
        };
        row(o, &c.name, c.enabled && c.running != Some(false), &format!("{} · {state} · {live}", c.kind));
    }
}

fn gateway_section(o: &mut String, st: &Status) {
    section(o, "Gateway service");
    let d = &st.daemon;
    kv_flag(o, "Status:", d.running, gateway_line(d).trim_start_matches("✓ "), gateway_line(d).trim_start_matches("✗ "));
    kv(o, "Socket:", format!("{} {}", mark(d.socket_exists), d.socket.display()));
    if let Some(pid) = d.pid {
        kv(o, "PID:", format!("{pid}{}", if d.alive { "" } else { " (not running)" }));
    }
    kv(o, "Version:", d.version.clone().unwrap_or_else(|| "unknown".into()));
    kv(o, "Last start:", match d.uptime_secs {
        Some(s) => format!("{} ago (pid file)", duration(s)),
        None => "unknown".into(),
    });
    let storm = crate::ops::service::STORM_THRESHOLD;
    kv(o, "Restarts:", format!("{} in the last {} minutes{}", st.restarts, crate::ops::service::STORM_WINDOW_SECS / 60, if st.restarts >= storm { " — restart storm!" } else { "" }));
    if let Some(e) = &d.ping_error {
        kv(o, "Probe:", format!("{} {e}", mark(false)));
    }
    if st.service.is_empty() {
        kv(o, "Unit:", format!("{} {}", mark(true), st.service_unit));
    } else {
        for i in &st.service {
            kv(o, "Unit:", format!("{} [{}] {}", mark(false), i.code, i.message));
        }
    }
}

fn cron_section(o: &mut String, st: &Status) {
    section(o, "Scheduled jobs");
    kv(o, "Jobs:", cron_line(&st.cron));
    match st.cron.next_run {
        Some(next) => {
            let now = ark_kernel::util::unix_now();
            kv(o, "Next run:", format!("in {} ({})", duration((next - now).max(0)), ark_kernel::util::fmt_time(next, offset(st))));
        }
        None => kv(o, "Next run:", "-"),
    }
}

fn sessions_section(o: &mut String, st: &Status) {
    section(o, "Sessions");
    kv(o, "Stored:", st.sessions.count);
    match st.sessions.running {
        Some(n) => kv(o, "Running:", format!("{n} (reported by arkd)")),
        None => kv(o, "Running:", "unknown (arkd stopped)"),
    }
    match (&st.sessions.newest, st.sessions.newest_ms) {
        (Some(id), Some(ms)) => {
            let ago = ago(ark_kernel::util::unix_now() - (ms / 1000) as i64);
            kv(o, "Newest:", format!("{id} ({ago})"));
        }
        _ => kv(o, "Newest:", "none"),
    }
}

fn deep_section(o: &mut String, st: &Status) {
    section(o, "Deep checks");
    for c in &st.checks {
        // Advisory rows (arkd, checks skipped because the config is broken) get `·`, so a ✓
        // always means "checked and fine".
        let m = if c.ok { mark(true) } else if c.blocking { mark(false) } else { "·" };
        kv(o, &format!("{}:", c.name), format!("{m} {}", c.detail));
    }
    let blocking = st.checks.iter().filter(|c| !c.ok && c.blocking).count();
    kv(o, "Result:", if blocking == 0 { "✓ no blocking problems".to_string() } else { format!("{} {blocking} blocking problem(s)", mark(false)) });
}

fn footer(o: &mut String) {
    o.push_str(&format!("\n{}\n", "─".repeat(60)));
    o.push_str("  Run 'ark doctor' for detailed diagnostics\n");
    o.push_str("  Run 'ark setup' to configure\n\n");
}

// ───────────────────────── JSON ─────────────────────────

fn provider_json(p: &ProviderRow) -> Value {
    json!({"id": p.id, "source": p.source, "ok": p.ok})
}

fn sessions_json(s: &Sessions) -> Value {
    json!({"count": s.count, "running": s.running, "newest": s.newest.clone(), "newestMs": s.newest_ms})
}

fn check_json(c: &Check) -> Value {
    json!({"name": c.name, "ok": c.ok, "blocking": c.blocking, "detail": c.detail})
}

fn json_report(st: &Status) -> Value {
    let d = &st.daemon;
    let (sandbox_ok, sandbox) = sandbox_note(&st.exec);
    let cfg = st.paths.user_config();
    let env = st.paths.config_dir.join(".env");
    let secrets = st.paths.secrets();
    // A4: report the file that actually holds the secrets today.
    let secrets = if secrets.with_extension("enc").exists() { secrets.with_extension("enc") } else { secrets };
    let secrets_backend = ark_kernel::secretstore::peek_backend(&st.paths.secrets()).map(|b| b.as_str().to_string());
    let mut v = json!({
        "version": st.version,
        "profile": st.profile.clone(),
        "workspace": st.workspace.display().to_string(),
        "paths": {
            "data": st.paths.data.display().to_string(),
            "configDir": st.paths.config_dir.display().to_string(),
            "runtime": st.paths.runtime.display().to_string(),
            "configFile": cfg.display().to_string(),
            "configFileExists": cfg.exists(),
            "secretsFile": secrets.display().to_string(),
            "secretsMode": secret_mode(&secrets).map(|m| format!("{m:04o}")),
            "secretsBackend": secrets_backend,
            "envFile": env.display().to_string(),
            "envFileExists": env.exists(),
        },
        "model": st.model.clone(),
        "provider": st.provider.as_ref().map(provider_json),
        "providers": st.providers.iter().map(provider_json).collect::<Vec<_>>(),
        "providerError": st.provider_error.clone(),
        "configError": st.config_error.clone(),
        "exec": {"backend": st.exec.as_ref().map(|c| c.backend.clone()).unwrap_or_else(|_| "unknown".into()), "sandbox": sandbox_ok, "note": sandbox},
        "channels": st.channels.iter().map(|c| json!({"name": c.name, "kind": c.kind, "enabled": c.enabled, "running": c.running, "error": c.error})).collect::<Vec<_>>(),
        "gateway": {
            "running": d.running,
            "socket": d.socket.display().to_string(),
            "socketExists": d.socket_exists,
            "stale": d.stale,
            "pid": d.pid,
            "alive": d.alive,
            "version": d.version.clone(),
            "uptimeSecs": d.uptime_secs,
            "runningSessions": d.running_sessions,
            "error": d.ping_error.clone(),
        },
        "service": {"unit": st.service_unit.clone(), "issues": st.service.iter().map(|i| json!({"code": i.code, "message": i.message})).collect::<Vec<_>>()},
        "restarts": st.restarts,
        "cron": {"total": st.cron.total, "enabled": st.cron.enabled, "nextRun": st.cron.next_run, "error": st.cron.error.clone()},
        "sessions": sessions_json(&st.sessions),
    });
    if st.deep {
        v["deep"] = json!({
            "checks": st.checks.iter().map(check_json).collect::<Vec<_>>(),
            "blocking": st.checks.iter().any(|c| !c.ok && c.blocking),
        });
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, Ordering};

    const VAULT_VALUE: &str = "vault-status-value-123";
    const CONFIG_VALUE: &str = "sk-literal-status-value";

    /// Temp layout (data/, config/, run/, ws/) — no process env is touched.
    fn temp_home(tag: &str) -> (Paths, PathBuf) {
        let root = ark_core::tmp::scratch_path(format!("ark-status-{tag}-{}", ark_kernel::util::random_hex(6)));
        let paths = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() };
        let ws = root.join("ws");
        for d in [&paths.data, &paths.config_dir, &paths.runtime, &ws] {
            std::fs::create_dir_all(d).unwrap();
        }
        (paths, ws)
    }

    fn write_secret(paths: &Paths, name: &str, value: &str) {
        std::fs::write(paths.secrets(), format!("{name} = \"{value}\"\n")).unwrap();
        std::fs::set_permissions(paths.secrets(), std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn keyless_config(paths: &Paths) {
        // `auth = "none"` keeps the model check independent of whatever keys the CI host has.
        std::fs::write(
            paths.user_config(),
            "[model]\ndefault = \"local/llama\"\n\n[providers.local]\nformat = \"openai_chat\"\nbase_url = \"http://127.0.0.1:9/v1\"\nauth = \"none\"\n",
        )
        .unwrap();
    }

    fn load(paths: &Paths) -> Result<Config, String> {
        Config::load(Some(&paths.user_config()), None, &[]).map_err(|e| e.to_string())
    }

    /// Answers every JSON-RPC request with a `ping` result until stopped.
    fn ping_responder(listener: UnixListener, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            listener.set_nonblocking(true).unwrap();
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let mut line = String::new();
                        let _ = BufReader::new(s.try_clone().unwrap()).read_line(&mut line);
                        let reply = json!({"jsonrpc": "2.0", "id": 1, "result": {"protocol": 1, "version": "9.9.9", "pid": std::process::id(), "running": ["s1"]}});
                        let _ = s.write_all(format!("{reply}\n").as_bytes());
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        })
    }

    #[test]
    fn summary_full_and_json_render_a_temp_home_without_leaking_secrets() {
        let (paths, ws) = temp_home("render");
        std::fs::write(
            paths.user_config(),
            format!(
                "[model]\ndefault = \"echo/m\"\n\n[channels.tg]\nkind = \"telegram\"\ntoken = \"{{{{secret:STATUS_KEY}}}}\"\ndm_policy = \"open\"\n\n[providers.echo]\nformat = \"openai_chat\"\nbase_url = \"http://127.0.0.1:9/v1\"\napi_key = \"{CONFIG_VALUE}\"\n"
            ),
        )
        .unwrap();
        write_secret(&paths, "STATUS_KEY", VAULT_VALUE);

        let st = snapshot(&paths, ws.clone(), load(&paths), true);
        let summary = report(&st, Mode::Summary);
        let full = report(&st, Mode::Full);
        let json = report_json(&st);

        // model, workspace and channel rows are all there
        assert!(summary.contains("echo/m"), "{summary}");
        assert!(summary.contains(&ws.display().to_string()), "{summary}");
        assert!(summary.contains("tg (telegram)"), "{summary}");
        assert!(summary.contains("key from config"), "the provider row reports where the key comes from: {summary}");
        assert!(full.contains("◆ Environment") && full.contains("◆ API keys") && full.contains("◆ Messaging platforms"), "{full}");
        assert!(full.contains("◆ Gateway service") && full.contains("◆ Scheduled jobs") && full.contains("◆ Sessions"), "{full}");
        let v: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["model"], "echo/m");
        assert_eq!(v["workspace"], ws.display().to_string());
        assert_eq!(v["channels"][0]["name"], "tg");
        assert_eq!(v["channels"][0]["enabled"], true);
        assert_eq!(v["gateway"]["running"], false);
        assert!(v["deep"]["checks"].as_array().is_some_and(|a| !a.is_empty()));

        // neither the vault value nor the literal key in the config may be printed
        for out in [&summary, &full, &json] {
            assert!(!out.contains(VAULT_VALUE), "vault secret leaked: {out}");
            assert!(!out.contains(CONFIG_VALUE), "config key leaked: {out}");
        }
    }

    #[test]
    fn daemon_state_follows_socket_and_pid() {
        let (paths, ws) = temp_home("daemon");
        keyless_config(&paths);
        let st = snapshot(&paths, ws.clone(), load(&paths), false);
        assert!(!st.daemon.running, "no socket yet: {:?}", st.daemon);
        assert!(report(&st, Mode::Summary).contains("stopped"));

        // A real unix socket plus a pid file naming this (live) process → running.
        let listener = UnixListener::bind(paths.socket()).unwrap();
        std::fs::write(paths.runtime.join("arkd.pid"), std::process::id().to_string()).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let responder = ping_responder(listener, stop.clone());
        let st = snapshot(&paths, ws.clone(), load(&paths), true);
        assert!(st.daemon.running, "{:?}", st.daemon);
        assert!(st.daemon.socket_exists && !st.daemon.stale);
        assert_eq!(st.daemon.version.as_deref(), Some("9.9.9"), "the live daemon's version wins");
        assert_eq!(st.daemon.running_sessions, 1);
        assert!(st.daemon.uptime_secs.is_some_and(|s| s >= 0), "uptime comes from the pid file mtime");
        let summary = report(&st, Mode::Summary);
        assert!(summary.contains("✓ running"), "{summary}");
        assert!(summary.contains(&format!("pid {}", std::process::id())), "{summary}");

        // Remove both again → stopped.
        stop.store(true, Ordering::SeqCst);
        responder.join().unwrap();
        std::fs::remove_file(paths.socket()).unwrap();
        std::fs::remove_file(paths.runtime.join("arkd.pid")).unwrap();
        let st = snapshot(&paths, ws, load(&paths), false);
        assert!(!st.daemon.running && !st.daemon.socket_exists);
        assert!(report(&st, Mode::Summary).contains("stopped"));
    }

    #[test]
    fn deep_exit_codes_follow_blocking_problems() {
        let (paths, ws) = temp_home("deep");
        keyless_config(&paths);
        let st = snapshot(&paths, ws.clone(), load(&paths), true);
        assert!(st.checks.iter().all(|c| c.name != "config" || c.ok), "{:?}", st.checks);
        assert_eq!(exit_code(&st, true), 0);
        assert!(report(&st, Mode::Full).contains("◆ Deep checks"));

        // Invalid config text: the deep check blocks and the documented exit code is 1.
        std::fs::write(paths.user_config(), "[model\ndefault = \"local/llama\"\n").unwrap();
        assert!(load(&paths).is_err());
        let st = snapshot(&paths, ws, load(&paths), true);
        let cfg_check = st.checks.iter().find(|c| c.name == "config").unwrap();
        assert!(!cfg_check.ok && cfg_check.blocking, "{cfg_check:?}");
        assert!(st.config_error.is_some());
        assert_eq!(exit_code(&st, true), 1, "deep reports blocking problems through its exit code");
        assert_eq!(exit_code(&st, false), 0, "the plain report never fails");
        let full = report(&st, Mode::Full);
        assert!(full.contains("✗ config"), "{full}");
        assert!(full.contains("blocking problem"), "{full}");
    }

    #[test]
    fn dispatch_owns_only_status() {
        assert!(COMMANDS.contains(&"status"));
        assert!(crate::ops::owns("status"), "status is listed in ops::MODULES");
        let a = Args::parse(&["bogus".to_string()]).unwrap();
        assert!(dispatch("doctor", &a, &[]).is_none());
        assert!(dispatch("service", &a, &[]).is_none());
        // Routed to us, and an unknown sub-form is a usage error rather than silent output.
        assert!(matches!(dispatch("status", &a, &[]), Some(Err(crate::Fail::Usage(_)))));
    }
}
