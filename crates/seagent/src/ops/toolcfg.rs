//! `seagent tools` per-platform enable/disable, `--summary` and `post-setup`
//! (Hermes §9: `hermes_cli/subcommands/tools.py`, `tools_config_mcp.py`
//! `tools_disable_enable_command`, `tools_config_post_setup.py`
//! `valid_post_setup_keys` / `run_post_setup_command`).
//!
//! seagent already has a *global* `seagent tools [list|enable|disable]` in
//! `slash.rs::tools_command` (it writes `tools.disabled`). This module adds the
//! two dimensions that command lacks — per-platform policy and the non-interactive
//! post-install hooks — and claims **only** these shapes:
//!
//! ```text
//! seagent tools list    [--platform P] [--json]
//! seagent tools enable  NAME… [--platform P]
//! seagent tools disable NAME… [--platform P]
//! seagent tools --summary
//! seagent tools post-setup KEY [--dry-run]
//! ```
//!
//! Everything else returns `None` so `slash.rs` keeps serving the global form
//! unchanged. The claim rule (also asserted by the tests) is deliberately sharp:
//! `list`/`enable`/`disable` are only claimed when `--platform` is given, so a
//! bare `seagent tools list` is still the kernel-backed global listing.
//!
//! ## Platforms and what a ✓ means
//!
//! Platforms are `cli` (the global `tools.disabled` list, exactly what the slash
//! command edits), every configured channel name (`cfg.channels` keys) and the
//! well-known platform kinds `telegram`, `discord`, `slack`, `whatsapp`, `web`,
//! `tui`. A tool is shown ✓ when it is neither in `tools.disabled` nor refused by
//! any policy layer that applies to that platform:
//!
//! * `cli` → `tools.profile` / `allow` / `also_allow` / `deny`;
//! * a channel → the same global layer plus `[tools.by_channel.<platform>]`.
//!
//! Those are the layers `seagent_security::toolpolicy::allowed` applies at call time
//! (`crates/seagent-kernel/tests/security.rs`), so what the listing shows is what the
//! agent gets — the setting is wired, not cosmetic.
//!
//! `enable`/`disable` on a non-`cli` platform edits
//! `[tools.by_channel.<platform>] deny = [...]` (disable → add, enable → remove
//! from `deny`). Every change is written through `ops::confcli::set`, so it is
//! validated, backed up and line-preserving like any other config edit, and it
//! takes effect in new sessions (restart the daemon for running ones).
//!
//! ## Tool universe
//!
//! `NAME` is a tool name, a `@toolset` group (`@web`, `@runtime`, … — the
//! `seagent_security::toolpolicy::groups()` sets plus the bare-name aliases in
//! [`TOOLSETS`]) or an MCP `server:tool` (anything containing `:` is written
//! verbatim, as are `group:` names and globs). The listing shows the built-in
//! toolset (`seagent_tools::builtin_tools()`) plus every plain name that already
//! appears in the config, so a hand-edited `tools.disabled = ["gone_tool"]` stays
//! visible. MCP `server:tool` entries are **not** listed: their inventory lives in
//! the extension registry (`Kernel::specs()`), which needs a live kernel plus the
//! MCP servers themselves, and a config linter must stay offline.
//!
//! ## Wiring
//!
//! `ops/mod.rs` needs the module row
//! `(toolcfg::COMMANDS, toolcfg::VALUE_FLAGS, toolcfg::BOOL_FLAGS, toolcfg::dispatch)`
//! (it is what teaches `Args` about `--platform`/`--summary`/`--dry-run`). Until
//! that row exists `dispatch` is only reachable from the tests.
//!
//! ## post-setup
//!
//! Hermes runs the install/bootstrap step behind a tool backend from a
//! *non-interactive* command (the dashboard spawns it). seagent ports the behaviour,
//! not the Python: [`HOOKS`] is a hard-coded registry (`key`, `what`, `argv`), an
//! unknown key is refused before anything runs (upstream's allowlist guard) and
//! exits 2, `--dry-run` prints the argv without running it, and a real run
//! executes the argv with a bounded timeout, inherited stdio and exit 1 on a
//! non-zero status with the command echoed.

use crate::args::Args;
use crate::{usage, Fail, R};
use seagent_kernel::config::{Config, Paths};
use serde_json::json;
use std::time::{Duration, Instant};

pub const COMMANDS: &[&str] = &["tools"];
pub const VALUE_FLAGS: &[&str] = &["platform", "model", "channel", "sender"];
pub const BOOL_FLAGS: &[&str] = &["summary", "dry-run"];

/// Platform kinds that are valid even when no channel of that name is configured
/// (Hermes `PLATFORMS`; a configured channel of the same name wins, it is the
/// same string).
pub const WELL_KNOWN: &[&str] = &["telegram", "discord", "slack", "whatsapp", "web", "tui"];

/// Bare-name toolsets (Hermes `CONFIGURABLE_TOOLSETS` keys) mapped onto seagent's
/// tool names. `@name` also accepts the `seagent_security::toolpolicy::groups()`
/// sets (`@fs`, `@runtime`, `@web`, `@memory`, …), which are richer; these are the
/// upstream spellings users type.
pub const TOOLSETS: &[(&str, &[&str])] = &[
    // Hermes' `web` toolset is "web_search, web_extract"; seagent's search tool is
    // `web_search` and URL extraction is `web_fetch`/`web_extract`, which stay
    // available unless named explicitly (that is what the parity spec pins).
    ("web", &["web_search"]),
    ("files", &["read", "write", "edit", "patch", "glob", "grep"]),
    ("file", &["read", "write", "edit", "patch", "glob", "grep"]),
    ("runtime", &["shell", "run", "job", "process"]),
    ("terminal", &["shell", "run", "job", "process"]),
    ("memory", &["memory", "session_search"]),
    (
        "plan",
        &["todo", "skill", "ask_user", "tool_describe", "tool_call"],
    ),
    (
        "media",
        &["image", "tts", "pdf", "image_generate", "vision"],
    ),
];

/// Default bound for one hook run (upstream hooks are `npm`/`pip`/binary installs).
pub const HOOK_TIMEOUT: Duration = Duration::from_secs(600);

// ───────────── config ─────────────

fn load(paths: &Paths) -> Config {
    Config::load(Some(&paths.user_config()), None, &[]).unwrap_or_default()
}

/// Valid platforms, sorted: `cli`, every configured channel, the well-known kinds.
pub fn platforms(cfg: &Config) -> Vec<String> {
    let mut v: Vec<String> = std::iter::once("cli".to_string())
        .chain(cfg.channels.keys().cloned())
        .collect();
    for k in WELL_KNOWN {
        if !v.iter().any(|p| p == k) {
            v.push((*k).to_string());
        }
    }
    v.sort();
    v.dedup();
    v
}

/// Error text for an unknown platform (upstream: `Unknown platform '<p>'. Valid: …`).
pub fn unknown_platform(cfg: &Config, platform: &str) -> String {
    format!(
        "Unknown platform '{platform}'. Valid: {}",
        platforms(cfg).join(", ")
    )
}

fn check_platform(cfg: &Config, platform: &str) -> Result<(), String> {
    if platforms(cfg).iter().any(|p| p == platform) {
        Ok(())
    } else {
        Err(unknown_platform(cfg, platform))
    }
}

/// Name of one policy entry that is a tool name (not a group/glob/MCP ref).
fn plain(entry: &str) -> Option<String> {
    let e = entry.trim();
    (!e.is_empty() && !e.starts_with("group:") && !e.contains([':', '*', '?', '[']))
        .then(|| e.to_string())
}

/// Every tool name the listing can know about: the built-in toolset plus plain
/// names mentioned anywhere in the tool policy (so config edits round-trip).
pub fn names(cfg: &Config) -> Vec<String> {
    let mut v: Vec<String> = seagent_tools::builtin_tools()
        .iter()
        .map(|t| t.spec().name)
        .collect();
    let t = &cfg.tools;
    let mut mentioned: Vec<&String> = t
        .disabled
        .iter()
        .chain(t.deny.iter())
        .chain(t.allow.iter())
        .chain(t.also_allow.iter())
        .collect();
    for l in t
        .by_channel
        .values()
        .chain(t.by_provider.values())
        .chain(t.by_sender.values())
    {
        mentioned.extend(
            l.deny
                .iter()
                .chain(l.allow.iter())
                .chain(l.also_allow.iter()),
        );
    }
    v.extend(mentioned.into_iter().filter_map(|e| plain(e)));
    v.sort();
    v.dedup();
    v
}

/// Is `name` enabled for `platform`? `tools.disabled` plus every applicable
/// `toolpolicy` layer (the same predicate a call goes through).
pub fn enabled(cfg: &Config, platform: &str, name: &str) -> bool {
    if cfg.tools.disabled.iter().any(|d| d == name) {
        return false;
    }
    let origin = if platform == "cli" {
        seagent_security::toolpolicy::Origin::default()
    } else {
        seagent_security::toolpolicy::Origin {
            channel: Some(platform.to_string()),
            ..Default::default()
        }
    };
    cfg.tools.permits(&origin, name)
}

fn counts(cfg: &Config, platform: &str) -> (usize, usize) {
    let n = names(cfg);
    let on = n.iter().filter(|t| enabled(cfg, platform, t)).count();
    (on, n.len() - on)
}

fn rule(platform: &str) -> String {
    if platform == "cli" {
        "tools.disabled + tools.deny".to_string()
    } else {
        format!("tools.disabled + [tools.by_channel.{platform}]")
    }
}

fn one_line(s: &str, n: usize) -> String {
    let first = s.lines().next().unwrap_or("").trim();
    if first.chars().count() <= n {
        first.to_string()
    } else {
        format!("{}…", first.chars().take(n).collect::<String>())
    }
}

/// `seagent tools explain <tool>`: replay the same layers a call goes through and
/// name the first policy that blocks it, plus the config key that would change it.
pub fn explain_tool(cfg: &Config, tool: &str, origin: &seagent_security::toolpolicy::Origin) -> String {
    let tool = tool.trim();
    let mut out = vec![format!("tool `{tool}` · model={} · channel={} · sender={}", if origin.model.is_empty() { "-" } else { origin.model.as_str() }, origin.channel.as_deref().unwrap_or("-"), origin.sender.as_deref().unwrap_or("-"))];
    if cfg.tools.disabled.iter().any(|d| d == tool) {
        out.push("✗ blocked by tools.disabled".into());
        out.push(format!("  fix: seagent tools enable {tool} --platform cli"));
        return out.join("\n");
    }
    let blocks = seagent_security::toolpolicy::explain(&cfg.tools.layer(), &cfg.tools.by_provider, &cfg.tools.by_channel, &cfg.tools.by_sender, origin, tool);
    if blocks.is_empty() {
        out.push("✓ available: no tool policy layer blocks it".into());
        if !names(cfg).iter().any(|n| n == tool) {
            out.push(format!("  note: `{tool}` is not a built-in tool this build knows; an MCP `server__tool` is only visible with a live kernel"));
        }
    } else {
        out.push(format!("✗ blocked by {}", blocks.iter().map(|b| b.layer.as_str()).collect::<Vec<_>>().join(", ")));
        for b in blocks {
            out.push(format!("  {} (`{}`)", b.config, b.layer));
            out.push(format!("  fix: {}", b.fix));
        }
    }
    out.join("\n")
}

/// `seagent tools list --platform P`: ✓/✗ per tool, with the description the model sees.
pub fn listing(cfg: &Config, platform: &str, as_json: bool) -> String {
    let desc: std::collections::BTreeMap<String, String> = seagent_tools::builtin_tools()
        .iter()
        .map(|t| (t.spec().name, one_line(&t.spec().description, 60)))
        .collect();
    let rows: Vec<(String, bool)> = names(cfg)
        .into_iter()
        .map(|n| {
            let on = enabled(cfg, platform, &n);
            (n, on)
        })
        .collect();
    let (on, off) = counts(cfg, platform);
    if as_json {
        let tools: Vec<serde_json::Value> = rows
            .iter()
            .map(|(n, on)| json!({"name": n, "enabled": on}))
            .collect();
        return json!({"platform": platform, "rule": rule(platform), "enabled": on, "disabled": off, "tools": tools}).to_string();
    }
    let mut out = vec![format!(
        "{platform}: {on} enabled · {off} disabled ({})",
        rule(platform)
    )];
    out.extend(rows.iter().map(|(n, on)| {
        let mark = if *on { "✓" } else { "✗" };
        let d = desc.get(n).cloned().unwrap_or_default();
        if d.is_empty() {
            format!("{mark} {n}")
        } else {
            format!("{mark} {n:<20} {d}")
        }
    }));
    out.join("\n")
}

/// `seagent tools --summary`: one line per platform with enabled/disabled counts.
pub fn summary(cfg: &Config) -> String {
    platforms(cfg)
        .iter()
        .map(|p| {
            let (on, off) = counts(cfg, p);
            format!("{p:<12} {on:>3} enabled · {off} disabled")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `@toolset` / bare-toolset / `server:tool` expansion into concrete config entries.
pub fn expand(cfg: &Config, word: &str) -> Result<Vec<String>, String> {
    let w = word.trim();
    if w.is_empty() {
        return Err("empty tool name".into());
    }
    // A group expands to the members this build actually ships, so the config
    // never grows deny entries for tools that do not exist.
    let known = names(cfg);
    let set = |m: &'static [&str]| -> Vec<String> {
        m.iter()
            .filter(|s| known.iter().any(|k| k == *s))
            .map(|s| (*s).to_string())
            .collect()
    };
    if let Some(g) = w.strip_prefix('@') {
        let members = TOOLSETS
            .iter()
            .find(|(k, _)| *k == g)
            .map(|(_, m)| set(m))
            .or_else(|| {
                seagent_security::toolpolicy::groups()
                    .get(format!("group:{g}").as_str())
                    .map(|m| set(m))
            })
            .ok_or_else(|| format!("unknown toolset @{g} (see `seagent tools list --platform cli`)"))?;
        if members.is_empty() {
            return Err(format!("toolset @{g} has no tool this build ships"));
        }
        return Ok(members);
    }
    if w.starts_with("group:") || w.contains([':', '*', '?', '[']) {
        // MCP `server:tool`, a policy group or a glob: written verbatim.
        return Ok(vec![w.to_string()]);
    }
    if known.iter().any(|n| n == w) {
        return Ok(vec![w.to_string()]);
    }
    if let Some((_, m)) = TOOLSETS.iter().find(|(k, _)| *k == w) {
        return Ok(set(m));
    }
    Err(format!("unknown tool `{w}` (use a tool name, `@toolset` or `server:tool`) — see `seagent tools list --platform cli`"))
}

fn toml_array(v: &[String]) -> String {
    toml::Value::Array(v.iter().map(|s| toml::Value::String(s.clone())).collect()).to_string()
}

/// Config keys are dotted paths of `[A-Za-z0-9_-]` segments (`confcli::split_key`).
fn writable(platform: &str) -> Result<(), String> {
    if platform
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(())
    } else {
        Err(format!(
            "platform `{platform}` cannot be written to config (use letters, digits, `_` or `-`)"
        ))
    }
}

/// `seagent tools enable|disable NAME… --platform P`. `platform == "cli"` edits the
/// global `tools.disabled` (the slash command's list); any other platform edits
/// `[tools.by_channel.<platform>] deny`.
pub fn toggle(
    paths: &Paths,
    platform: &str,
    words: &[String],
    disable: bool,
) -> Result<String, String> {
    let cfg = load(paths);
    check_platform(&cfg, platform)?;
    let mut targets: Vec<String> = vec![];
    for w in words {
        for t in expand(&cfg, w)? {
            if !targets.contains(&t) {
                targets.push(t);
            }
        }
    }
    if targets.is_empty() {
        return Err(format!(
            "usage: seagent tools {} NAME… [--platform P]",
            if disable { "disable" } else { "enable" }
        ));
    }
    let verb = if disable { "disabled" } else { "enabled" };
    let caveat = "takes effect in new sessions (restart the daemon for running ones)";
    if platform == "cli" {
        let mut d = cfg.tools.disabled.clone();
        for t in &targets {
            if disable {
                if !d.contains(t) {
                    d.push(t.clone());
                }
            } else {
                d.retain(|x| x != t);
            }
        }
        d.sort();
        d.dedup();
        crate::ops::confcli::set(paths, "tools.disabled", &toml_array(&d))?;
        return Ok(format!("{verb} {} · {caveat}", targets.join(", ")));
    }
    writable(platform)?;
    let mut deny = cfg
        .tools
        .by_channel
        .get(platform)
        .map(|l| l.deny.clone())
        .unwrap_or_default();
    for t in &targets {
        if disable {
            if !deny.contains(t) {
                deny.push(t.clone());
            }
        } else {
            deny.retain(|x| x != t);
        }
    }
    deny.sort();
    deny.dedup();
    crate::ops::confcli::set(
        paths,
        &format!("tools.by_channel.{platform}.deny"),
        &toml_array(&deny),
    )?;
    Ok(format!(
        "{verb} {} on {platform} · [tools.by_channel.{platform}] deny is enforced per channel at call time · {caveat}",
        targets.join(", ")
    ))
}

// ───────────── post-setup hooks ─────────────

/// One non-interactive install/bootstrap hook (Hermes `_POST_SETUP_HOOKS`).
pub struct Hook {
    /// Stable key the dashboard/CLI passes (`hermes tools post-setup <key>`).
    pub key: &'static str,
    /// What the hook installs, printed before it runs.
    pub what: &'static str,
    /// The command, run without a shell so signals reach the real process.
    pub argv: &'static [&'static str],
}

// Keys that need something seagent cannot install itself print the instruction instead
// of silently doing nothing.
const CAMOFOX: &[&str] = &[
    "sh",
    "-c",
    "echo 'Camofox is an externally managed Firefox server; seagent only speaks its REST API.'; \
     echo 'Run it yourself, e.g.: docker run -p 9377:9377 -e CAMOFOX_PORT=9377 jo-inc/camofox-browser'; \
     echo 'then set browser.camofox.url (or CAMOFOX_URL) to http://127.0.0.1:9377'",
];

/// post_setup key → install/bootstrap command, in the upstream key order.
pub const HOOKS: &[Hook] = &[
    Hook {
        key: "agent_browser",
        what: "Chrome for Testing (the local browser backend)",
        argv: &["seagent", "browser", "install"],
    },
    Hook {
        key: "camofox",
        what: "Camofox server (external; this prints how to run it)",
        argv: CAMOFOX,
    },
    Hook {
        key: "cua_driver",
        what: "cua-driver desktop backend (`seagent computer-use`)",
        argv: &["seagent", "computer-use", "install"],
    },
    Hook {
        key: "kittentts",
        what: "kittentts (local CPU text-to-speech)",
        argv: &["python3", "-m", "pip", "install", "kittentts"],
    },
    Hook {
        key: "piper",
        what: "piper-tts (local text-to-speech)",
        argv: &["python3", "-m", "pip", "install", "piper-tts"],
    },
    Hook {
        key: "ddgs",
        what: "ddgs (keyless DuckDuckGo web search)",
        argv: &["python3", "-m", "pip", "install", "ddgs"],
    },
    Hook {
        key: "xai_grok",
        what: "xAI credentials (`seagent login xai`)",
        argv: &["seagent", "login", "xai"],
    },
    Hook {
        key: "openai_codex",
        what: "ChatGPT/Codex OAuth credentials (`seagent login openai-codex`)",
        argv: &["seagent", "login", "openai-codex"],
    },
];

pub fn hook(key: &str) -> Option<&'static Hook> {
    HOOKS.iter().find(|h| h.key == key)
}

/// Upstream's allowlist guard: an unknown key is refused, nothing is executed.
pub fn unknown_key_error(key: &str) -> String {
    format!(
        "Unknown post-setup key: '{key}'. Valid keys: {}",
        HOOKS.iter().map(|h| h.key).collect::<Vec<_>>().join(", ")
    )
}

/// Quote one argv word for the echoed command line.
fn sh_quote(a: &str) -> String {
    if !a.is_empty()
        && a.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@,+".contains(c))
    {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', r"'\''"))
    }
}

pub fn command_line(argv: &[&str]) -> String {
    argv.iter()
        .map(|a| sh_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

fn dur(d: Duration) -> String {
    if d.subsec_millis() == 0 {
        format!("{}s", d.as_secs())
    } else if d.as_secs() == 0 {
        format!("{}ms", d.subsec_millis())
    } else {
        format!("{}.{:03}s", d.as_secs(), d.subsec_millis())
    }
}

fn status_text(st: std::process::ExitStatus) -> String {
    match st.code() {
        Some(c) => format!("exit {c}"),
        #[cfg(unix)]
        None => {
            use std::os::unix::process::ExitStatusExt;
            format!("killed by signal {}", st.signal().unwrap_or(0))
        }
        // Windows always has an exit code; kept for exhaustiveness.
        #[cfg(not(unix))]
        None => "killed".into(),
    }
}

/// Run one argv with a bounded timeout, inherited stdio; the command is echoed in
/// the result so a failure names what failed. The CLI always goes through [`run_command`] (it can
/// be a dry run), so this shorthand only exists for the tests.
#[cfg(test)]
pub fn run_hook_argv(argv: &[&str], timeout: Duration) -> Result<String, String> {
    run_command(argv, false, timeout)
}

/// `run_hook_argv` plus the `--dry-run` branch (prints, runs nothing).
pub fn run_command(argv: &[&str], dry_run: bool, timeout: Duration) -> Result<String, String> {
    let cmd = command_line(argv);
    let (prog, args) = argv
        .split_first()
        .ok_or_else(|| "empty hook command".to_string())?;
    if dry_run {
        return Ok(format!("would run: {cmd}"));
    }
    let mut child = seagent_core::platform::layout::program_command(prog)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| format!("{cmd}: {e}"))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) if st.success() => return Ok(format!("{cmd} → exit 0")),
            Ok(Some(st)) => return Err(format!("{cmd} → {}", status_text(st))),
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{cmd}: {e}"));
            }
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "{cmd} → timed out after {} (child killed)",
                dur(timeout)
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `seagent tools post-setup KEY [--dry-run]`: exit 0 ok, 1 hook failed, 2 unknown key.
pub fn post_setup(key: &str, dry_run: bool, timeout: Duration) -> Result<String, String> {
    let h = hook(key).ok_or_else(|| unknown_key_error(key))?;
    let out = run_command(h.argv, dry_run, timeout)?;
    Ok(format!("{}: {}\n  {out}", h.key, h.what))
}

// ───────────── dispatch ─────────────

#[derive(Debug, Default)]
struct Cmd {
    sub: Option<String>,
    names: Vec<String>,
    platform: Option<String>,
    model: Option<String>,
    channel: Option<String>,
    sender: Option<String>,
    json: bool,
    summary: bool,
    dry_run: bool,
}

/// Flags are read from the raw argv (not `Args`) so the module works before it is
/// registered in `ops::MODULES`; `--platform` / `--summary` / `--dry-run` are also
/// declared in [`VALUE_FLAGS`] / [`BOOL_FLAGS`] for that registration.
fn parse(raw: &[String]) -> Result<Cmd, String> {
    let mut c = Cmd::default();
    let mut i = 0;
    while i < raw.len() {
        let r = raw[i].as_str();
        i += 1;
        match r {
            "--json" => c.json = true,
            "--summary" => c.summary = true,
            "--dry-run" => c.dry_run = true,
            "--platform" => {
                c.platform = Some(
                    raw.get(i)
                        .cloned()
                        .ok_or_else(|| "--platform needs a value".to_string())?,
                );
                i += 1;
            }
            f if f.starts_with("--platform=") => {
                c.platform = Some(f["--platform=".len()..].to_string())
            }
            "--model" | "--channel" | "--sender" => {
                let v = raw.get(i).cloned().ok_or_else(|| format!("{r} needs a value"))?;
                i += 1;
                match r {
                    "--model" => c.model = Some(v),
                    "--channel" => c.channel = Some(v),
                    _ => c.sender = Some(v),
                }
            }
            f if f.starts_with("--model=") => c.model = Some(f["--model=".len()..].to_string()),
            f if f.starts_with("--channel=") => c.channel = Some(f["--channel=".len()..].to_string()),
            f if f.starts_with("--sender=") => c.sender = Some(f["--sender=".len()..].to_string()),
            f if f.starts_with('-') => return Err(format!("unknown option {f} for `seagent tools`")),
            w => match &c.sub {
                None => c.sub = Some(w.to_string()),
                Some(_) => c.names.push(w.to_string()),
            },
        }
    }
    Ok(c)
}

/// `Some` only for the shapes this module owns; `None` = `slash.rs` (global form).
pub fn dispatch(cmd: &str, _a: &Args, raw: &[String]) -> Option<R> {
    if cmd != "tools" {
        return None;
    }
    let c = match parse(raw) {
        Ok(c) => c,
        // `post-setup` is ours whatever else is on the line; anything else stays
        // with the global command, which ignores unknown flags.
        Err(e) if raw.iter().any(|w| w == "post-setup") => return Some(usage(e)),
        Err(_) => return None,
    };
    if c.summary && c.sub.is_none() {
        return Some(run_summary());
    }
    match c.sub.as_deref() {
        Some("post-setup") => Some(run_post_setup(&c)),
        Some("explain") => Some(run_explain(&c)),
        Some("list") if c.platform.is_some() => Some(run_list(&c)),
        Some(v @ ("enable" | "disable")) if c.platform.is_some() => {
            Some(run_toggle(&c, v == "disable"))
        }
        _ => None,
    }
}

fn run_explain(c: &Cmd) -> R {
    let name = c.names.first().ok_or_else(|| Fail::Usage("usage: seagent tools explain <tool> [--model M] [--channel C] [--sender S]".into()))?;
    let cfg = load(&Paths::from_env());
    let model = c.model.clone().unwrap_or_else(|| cfg.model.default.clone());
    let origin = seagent_security::toolpolicy::Origin { model, channel: c.channel.clone().or_else(|| c.platform.clone().filter(|p| p != "cli")), sender: c.sender.clone() };
    println!("{}", explain_tool(&cfg, name, &origin));
    Ok(0)
}

fn run_summary() -> R {
    let cfg = load(&Paths::from_env());
    println!("{}", summary(&cfg));
    Ok(0)
}

fn run_list(c: &Cmd) -> R {
    let cfg = load(&Paths::from_env());
    let platform = c.platform.as_deref().unwrap_or("cli");
    check_platform(&cfg, platform).map_err(Fail::Usage)?;
    println!("{}", listing(&cfg, platform, c.json));
    Ok(0)
}

fn run_toggle(c: &Cmd, disable: bool) -> R {
    let platform = c.platform.as_deref().unwrap_or("cli");
    // Both mistakes are usage errors (exit 2), not command failures (exit 1).
    if c.names.is_empty() {
        return usage(format!(
            "usage: seagent tools {} NAME… [--platform P]",
            if disable { "disable" } else { "enable" }
        ));
    }
    let paths = Paths::from_env();
    check_platform(&load(&paths), platform).map_err(Fail::Usage)?;
    println!("{}", toggle(&paths, platform, &c.names, disable)?);
    Ok(0)
}

fn run_post_setup(c: &Cmd) -> R {
    let key = c
        .names
        .first()
        .ok_or_else(|| Fail::Usage("usage: seagent tools post-setup KEY [--dry-run]".into()))?;
    if hook(key).is_none() {
        return usage(unknown_key_error(key));
    }
    println!("{}", post_setup(key, c.dry_run, HOOK_TIMEOUT)?);
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Paths {
        let root =
            seagent_core::tmp::scratch_path(format!("seagent-tools-{}", seagent_kernel::util::random_hex(6)));
        let paths = Paths {
            data: root.join("data"),
            config_dir: root.join("config"),
            runtime: root.join("run"), ..Default::default()
        };
        for d in [&paths.data, &paths.config_dir, &paths.runtime] {
            std::fs::create_dir_all(d).unwrap();
        }
        paths
    }

    fn text(p: &Paths) -> String {
        std::fs::read_to_string(p.user_config()).unwrap()
    }

    #[test]
    fn list_and_toggle_per_platform() {
        let p = paths();
        let args = |v: &[&str]| -> Vec<String> { v.iter().map(|s| (*s).to_string()).collect() };
        // `disable web --platform telegram` → the per-channel deny list.
        let msg = toggle(&p, "telegram", &args(&["web"]), true).unwrap();
        assert!(msg.contains("disabled web_search on telegram"), "{msg}");
        let t = text(&p);
        assert!(t.contains("[tools.by_channel.telegram]"), "{t}");
        assert!(t.contains(r#"deny = ["web_search"]"#), "{t}");

        let cfg = load(&p);
        assert_eq!(
            cfg.tools.by_channel["telegram"].deny,
            vec!["web_search".to_string()]
        );
        assert!(!enabled(&cfg, "telegram", "web_search"));
        assert!(enabled(&cfg, "cli", "web_search"), "cli is untouched");

        assert!(listing(&cfg, "telegram", false).contains("✗ web_search"));
        assert!(listing(&cfg, "cli", false).contains("✓ web_search"));
        // the listing is JSON-parseable on demand
        let j: serde_json::Value = serde_json::from_str(&listing(&cfg, "telegram", true)).unwrap();
        assert_eq!(j["platform"], "telegram");
        assert!(j["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["name"] == "web_search" && x["enabled"] == false));

        // `enable` removes it again (empty list, the table stays).
        toggle(&p, "telegram", &args(&["web"]), false).unwrap();
        let cfg = load(&p);
        assert!(
            cfg.tools.by_channel["telegram"].deny.is_empty(),
            "{:?}",
            cfg.tools.by_channel
        );
        assert!(enabled(&cfg, "telegram", "web_search"));
        assert!(text(&p).contains(r#"deny = []"#));

        // `--platform cli` is the global list the slash command edits.
        toggle(&p, "cli", &args(&["shell"]), true).unwrap();
        assert!(text(&p).contains(r#"disabled = ["shell"]"#), "{}", text(&p));
        let cfg = load(&p);
        assert_eq!(cfg.tools.disabled, vec!["shell".to_string()]);
        assert!(!enabled(&cfg, "cli", "shell"));
        assert!(
            !enabled(&cfg, "telegram", "shell"),
            "tools.disabled applies everywhere"
        );
        toggle(&p, "cli", &args(&["shell"]), false).unwrap();
        assert!(load(&p).tools.disabled.is_empty());

        // unknown platform lists the valid ones, unknown tool is refused, nothing written.
        let before = text(&p);
        let e = toggle(&p, "myspace", &args(&["shell"]), true).unwrap_err();
        assert!(e.contains("Unknown platform 'myspace'"), "{e}");
        for p2 in [
            "cli", "telegram", "discord", "slack", "whatsapp", "web", "tui",
        ] {
            assert!(e.contains(p2), "{p2} missing from {e}");
        }
        let e = toggle(&p, "telegram", &args(&["no_such_tool"]), true).unwrap_err();
        assert!(e.contains("unknown tool `no_such_tool`"), "{e}");
        assert_eq!(text(&p), before, "a rejected name must not be written");

        // `@toolset` and `server:tool` expand, and a configured channel is a platform.
        crate::ops::confcli::set(&p, "channels.ops.dm_policy", "\"open\"").unwrap();
        let cfg = load(&p);
        assert!(platforms(&cfg).contains(&"ops".to_string()));
        assert!(expand(&cfg, "@runtime")
            .unwrap()
            .contains(&"shell".to_string()));
        assert_eq!(
            expand(&cfg, "github:create_issue").unwrap(),
            vec!["github:create_issue".to_string()]
        );
        assert!(toggle(&p, "ops", &args(&["@runtime"]), true).is_ok());
        assert!(text(&p).contains("[tools.by_channel.ops]"));
        assert!(load(&p).tools.by_channel["ops"]
            .deny
            .contains(&"shell".to_string()));
    }

    #[test]
    fn summary_counts_per_platform() {
        let p = paths();
        let args = |v: &[&str]| -> Vec<String> { v.iter().map(|s| (*s).to_string()).collect() };
        let cfg = load(&p);
        let n = names(&cfg).len();
        let base = summary(&cfg);
        assert!(base.lines().count() >= 7, "{base}");
        assert!(
            base.lines().any(
                |l| l.starts_with("cli") && l.contains(&format!("{n:>3} enabled · 0 disabled"))
            ),
            "{base}"
        );

        toggle(&p, "telegram", &args(&["web"]), true).unwrap();
        let s = summary(&load(&p));
        assert!(
            s.lines()
                .any(|l| l.starts_with("telegram") && l.contains("1 disabled")),
            "{s}"
        );
        assert!(
            s.lines()
                .any(|l| l.starts_with("cli") && l.contains("0 disabled")),
            "{s}"
        );
        assert!(
            s.lines()
                .any(|l| l.starts_with("discord") && l.contains("0 disabled")),
            "{s}"
        );
    }

    #[test]
    fn post_setup_allowlist_and_dry_run() {
        let dir =
            seagent_core::tmp::scratch_path(format!("seagent-hooks-{}", seagent_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("marker");
        // A shell line: Windows runs it through Git Bash (`sh`, `C:/…` spelling).
        let touch = format!("touch {}", seagent_core::platform::shell::path_str(&marker));
        let sh = if cfg!(windows) { "sh" } else { "/bin/sh" };
        let argv = [sh, "-c", touch.as_str()];

        // an unknown key never executes anything and names the valid ones (exit 2 path)
        let e = post_setup("nope", false, Duration::from_secs(5)).unwrap_err();
        assert!(e.contains("Unknown post-setup key: 'nope'"), "{e}");
        for k in [
            "agent_browser",
            "camofox",
            "cua_driver",
            "kittentts",
            "piper",
            "ddgs",
            "xai_grok",
            "openai_codex",
        ] {
            assert!(e.contains(k), "{k} missing from {e}");
            assert!(hook(k).is_some(), "{k} not in the registry");
        }

        // `--dry-run` prints the command and runs nothing…
        let out = run_command(&argv, true, Duration::from_secs(5)).unwrap();
        assert!(out.starts_with(&format!("would run: {sh} -c")), "{out}");
        assert!(!marker.exists(), "dry run executed the hook");
        // …while a real run of the same argv does create it (proves the assertion above).
        assert!(run_command(&argv, false, Duration::from_secs(5)).is_ok());
        assert!(marker.exists());

        // the registry's own commands are echoed for a real key
        let out = post_setup("agent_browser", true, Duration::from_secs(5)).unwrap();
        assert!(out.contains("seagent browser install"), "{out}");
        assert!(post_setup("openai_codex", true, Duration::from_secs(5))
            .unwrap()
            .contains("seagent login openai-codex"));

        // exit statuses: 0 ok, non-zero a failure with the command echoed
        // `/bin/true` / `/bin/false`; Windows: `cmd /c exit 0|1` (no `/bin` there).
        let (ok, bad): (&[&str], &[&str]) = if cfg!(windows) { (&["cmd", "/c", "exit 0"], &["cmd", "/c", "exit 1"]) } else { (&["/bin/true"], &["/bin/false"]) };
        assert!(run_hook_argv(ok, Duration::from_secs(5))
            .unwrap()
            .contains("exit 0"));
        let e = run_hook_argv(bad, Duration::from_secs(5)).unwrap_err();
        assert!(e.contains(bad[0]), "{e}");
        assert!(e.contains("exit 1"), "{e}");

        // bounded timeout: the child is killed and the message says so
        let t0 = Instant::now();
        // `/bin/sleep 2`; Windows: PowerShell's Start-Sleep.
        let slow: &[&str] = if cfg!(windows) { &["powershell", "-NoProfile", "-Command", "Start-Sleep 2"] } else { &["/bin/sleep", "2"] };
        let e = run_hook_argv(slow, Duration::from_millis(200)).unwrap_err();
        assert!(e.contains("timed out after 200ms"), "{e}");
        assert!(e.contains("child killed"), "{e}");
        assert!(e.contains(slow[0]), "{e}");
        assert!(
            t0.elapsed() < Duration::from_millis(1500),
            "timeout did not bound the run: {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn explain_replays_layers_and_names_the_fix() {
        let mut cfg = Config::default();
        cfg.model.default = "openai/gpt-4o".into();
        let origin = seagent_security::toolpolicy::Origin { model: "ollama/llama3".into(), channel: Some("telegram".into()), sender: Some("7".into()) };
        // `shell` is available by default.
        let s = explain_tool(&cfg, "shell", &origin);
        assert!(s.contains("✓ available"), "{s}");
        cfg.tools.by_provider.insert("ollama".into(), seagent_security::toolpolicy::Layer { deny: vec!["shell".into()], ..Default::default() });
        cfg.tools.by_channel.insert("telegram".into(), seagent_security::toolpolicy::Layer { deny: vec!["group:runtime".into()], ..Default::default() });
        cfg.tools.by_sender.insert("telegram:7".into(), seagent_security::toolpolicy::Layer { deny: vec!["write".into()], ..Default::default() });
        let s = explain_tool(&cfg, "shell", &origin);
        assert!(s.contains("blocked by tools.by_provider.ollama, tools.by_channel.telegram"), "{s}");
        assert!(s.contains("[tools.by_provider.ollama]") && s.contains("also_allow"), "{s}");
        // A disabled tool is a separate, earlier layer with its own fix.
        cfg.tools.disabled = vec!["write".into()];
        let s = explain_tool(&cfg, "write", &origin);
        assert!(s.contains("tools.disabled") && s.contains("seagent tools enable write"), "{s}");
        // The parse path accepts the model/channel/sender selectors.
        let raw: Vec<String> = ["explain", "shell", "--model", "ollama/llama3", "--channel=telegram", "--sender", "7"].iter().map(|s| s.to_string()).collect();
        let c = parse(&raw).unwrap();
        assert_eq!((c.sub.as_deref(), c.names[0].as_str()), (Some("explain"), "shell"));
        assert_eq!((c.model.as_deref(), c.channel.as_deref(), c.sender.as_deref()), (Some("ollama/llama3"), Some("telegram"), Some("7")));
    }

    #[test]
    fn dispatch_scope() {
        // `dispatch` really runs the command (`disable … --platform=telegram` writes config
        // through `Paths::from_env()`): point SEAGENT_HOME at a throwaway home for the duration,
        // or the test rewrites the config of whoever launched it.
        let _env = crate::testkit::env_lock();
        let home = seagent_core::tmp::scratch("seagent-toolcfg-dispatch");
        let prev = std::env::var_os("SEAGENT_HOME");
        std::env::set_var("SEAGENT_HOME", &home);
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => std::env::set_var("SEAGENT_HOME", v),
                    None => std::env::remove_var("SEAGENT_HOME"),
                }
            }
        }
        let _restore = Restore(prev);
        let a = Args::default();
        let raw = |v: &[&str]| -> Vec<String> { v.iter().map(|s| (*s).to_string()).collect() };
        // The global form stays with `slash.rs`: no subcommand, or no --platform.
        assert!(dispatch("tools", &a, &[]).is_none());
        assert!(dispatch("tools", &a, &raw(&["list"])).is_none());
        assert!(dispatch("tools", &a, &raw(&["enable", "web"])).is_none());
        assert!(dispatch("tools", &a, &raw(&["disable", "@web"])).is_none());
        assert!(dispatch("toolsets", &a, &raw(&["list", "--platform", "cli"])).is_none());
        assert!(dispatch("config", &a, &raw(&["set", "a", "b"])).is_none());
        assert!(dispatch("docker", &a, &[]).is_none());
        // Our shapes are claimed.
        assert!(dispatch(
            "tools",
            &a,
            &raw(&["post-setup", "agent_browser", "--dry-run"])
        )
        .is_some());
        assert!(dispatch("tools", &a, &raw(&["list", "--platform", "telegram"])).is_some());
        assert!(dispatch("tools", &a, &raw(&["explain", "shell"])).is_some());
        assert!(dispatch(
            "tools",
            &a,
            &raw(&["disable", "web", "--platform=telegram"])
        )
        .is_some());
        // post-setup with an unknown key is a usage error (exit 2), not a fallthrough.
        match dispatch("tools", &a, &raw(&["post-setup", "nope"])) {
            Some(Err(Fail::Usage(m))) => assert!(m.contains("Unknown post-setup key"), "{m}"),
            other => panic!("expected a usage failure, got {other:?}"),
        }
    }
}
