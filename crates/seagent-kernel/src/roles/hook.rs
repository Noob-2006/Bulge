//! The role's run-time checks, as a native hook (installed by `ctxhost::attach`).
//!
//! - `pre_tool`: the role's default permissions (presets.toml `[preset.policy]`): command
//!   globs it never runs, SQL writes under `db_read_only`, active scans outside
//!   `[role] scan_targets` under `scan_allowlist`, passwords typed for someone under
//!   `no_password_entry`; and, for a regulated role, a tool call whose input performs one of
//!   the role's reserved acts (writing a signed certificate, sending a prescription…).
//!   A hit refuses that one call with the reason; the model routes around it.
//! - `before_agent_finalize`: a regulated role's final reply that performs a reserved act is
//!   sent back for a rewrite (prepared material + hand-over to the professional, with the
//!   area's escalation wording) — up to the kernel's revision limit.
//!
//! A session's role is the `[role:<id>]` marker of its `role` system segment, so a role set by
//! the config, a named agent or `/role` is enforced the same way, and sessions without a role
//! pay one cached lookup per tool call.

use super::{boundary, Catalog, Policy, Role};
use crate::hooks::{Hook, HookDecision, HookEvent};
use crate::kernel::Runtime;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

/// Bumped whenever a session's role segment is rewritten (`/role`), so cached lookups refresh.
static GENERATION: AtomicU64 = AtomicU64::new(0);

pub fn invalidate() {
    GENERATION.fetch_add(1, Ordering::SeqCst);
}

/// What the checks need about a session's role.
#[derive(Debug, Clone)]
pub struct Checks {
    pub role_id: String,
    pub acts: Vec<String>,
    pub policy: Policy,
}

impl Checks {
    pub fn of(role: &Role) -> Checks {
        Checks { role_id: role.id.clone(), acts: role.acts(), policy: role.policy() }
    }
}

/// session → (generation it was read at, its checks).
type Cache = HashMap<String, (u64, Option<Arc<Checks>>)>;

pub struct RoleHook {
    kernel: Weak<Runtime>,
    cache: Mutex<Cache>,
}

impl RoleHook {
    pub fn new(kernel: Weak<Runtime>) -> RoleHook {
        RoleHook { kernel, cache: Mutex::new(HashMap::new()) }
    }

    fn checks(&self, session: &str) -> Option<Arc<Checks>> {
        let gen = GENERATION.load(Ordering::SeqCst);
        if let Some((g, c)) = self.cache.lock().unwrap().get(session) {
            if *g == gen {
                return c.clone();
            }
        }
        let k = self.kernel.upgrade()?;
        let cfg = k.cfg_now();
        let found = k.store.read(session).ok().and_then(|ev| {
            let v = crate::projection::project(&ev);
            let seg = v.system.iter().find(|s| s.id == super::SEGMENT_ID)?;
            let id = super::segment_role_id(&seg.text)?;
            super::resolve(&cfg, &Catalog::for_config(&cfg), &id).ok().map(|r| Arc::new(Checks::of(&r)))
        });
        let mut g = self.cache.lock().unwrap();
        if g.len() > 4096 {
            g.clear();
        }
        g.insert(session.to_string(), (gen, found.clone()));
        found
    }

    fn scan_targets(&self) -> Vec<String> {
        self.kernel.upgrade().map(|k| k.cfg_now().role.scan_targets).unwrap_or_default()
    }
}

impl Hook for RoleHook {
    fn name(&self) -> String {
        "role".into()
    }
    fn wants(&self, event: HookEvent, _tool: Option<&str>) -> bool {
        matches!(event, HookEvent::PreTool | HookEvent::BeforeAgentFinalize)
    }
    fn run(&self, event: HookEvent, p: &Value) -> Result<HookDecision, String> {
        let session = p.get("session_id").and_then(Value::as_str).unwrap_or("");
        let Some(c) = self.checks(session) else { return Ok(HookDecision::Allow) };
        let reason = match event {
            HookEvent::PreTool => {
                let tool = p.get("tool_name").and_then(Value::as_str).unwrap_or("");
                let input = p.get("tool_input").cloned().unwrap_or(Value::Null);
                check_tool(&c, tool, &input, &self.scan_targets())
            }
            HookEvent::BeforeAgentFinalize => {
                let text = p.get("last_assistant_message").and_then(Value::as_str).unwrap_or("");
                boundary::detect(text, &c.acts).map(|h| h.instruction())
            }
            _ => None,
        };
        Ok(reason.map(|r| HookDecision::Block(format!("[role {}] {r}", c.role_id))).unwrap_or(HookDecision::Allow))
    }
}

/// Shell-like tools whose `command` is a command line.
fn command_of(tool: &str, input: &Value) -> Option<String> {
    let shellish = matches!(tool, "shell" | "bash" | "exec" | "run" | "process" | "job" | "terminal" | "code_execution");
    let cmd = ["command", "cmd", "script"].iter().find_map(|k| input.get(*k).and_then(Value::as_str));
    if shellish || cmd.is_some() {
        cmd.map(String::from)
    } else {
        None
    }
}

fn sql_write() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)\b(?:insert\s+into|update\s+[\w.]+\s+set|delete\s+from|drop\s+(?:table|database|schema|index|view)|alter\s+table|truncate\b|create\s+(?:table|database|schema|index|view)|grant\s|revoke\s|merge\s+into|replace\s+into|copy\s+\w+\s+from)").unwrap())
}

fn db_client() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)(?:^|[\s;&|(])(?:psql|mysql|mariadb|sqlite3|duckdb|clickhouse-client|clickhouse|sqlcmd|bq|snowsql|trino|presto|cockroach\s+sql|mongosh)\b").unwrap())
}

fn password_entry() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)(?:\bchpasswd\b|\bpasswd\s+--stdin\b|\|\s*passwd\b|\busermod\s+.*\s-p\s|\buseradd\s+.*\s-p\s|--password[=\s]+\S+|\bConvertTo-SecureString\b|\bnet\s+user\s+\S+\s+\S+)").unwrap())
}

const SCANNERS: &[&str] = &["nmap", "masscan", "nikto", "nuclei", "zap-cli", "zaproxy", "wpscan", "gobuster", "ffuf", "dirb", "feroxbuster", "gvm-cli", "openvas", "rustscan", "zmap", "sslyze", "testssl.sh", "testssl"];

/// `(scanner, targets)` when `cmd` runs an active scanner.
pub fn scan_targets_of(cmd: &str) -> Option<(String, Vec<String>)> {
    for part in cmd.split([';', '|', '&', '\n']) {
        let words: Vec<&str> = part.split_whitespace().collect();
        let Some(i) = words.iter().position(|w| SCANNERS.contains(&w.rsplit('/').next().unwrap_or(w))) else { continue };
        let mut targets = Vec::new();
        let mut skip_next = false;
        for w in &words[i + 1..] {
            if skip_next {
                skip_next = false;
                continue;
            }
            if w.starts_with('-') {
                // Flags with a separate value (`-p 80`, `-o out.txt`, `-u URL` keeps the URL).
                if matches!(*w, "-u" | "--url" | "-h" | "--host" | "-target" | "--target" | "-t") {
                    continue;
                }
                skip_next = matches!(*w, "-p" | "-o" | "-oN" | "-oX" | "-oG" | "-oA" | "-iL" | "--top-ports" | "-w" | "--wordlist" | "--rate" | "-T" | "-s" | "--script" | "-e" | "-c" | "-x");
                continue;
            }
            let host = w.trim_start_matches("http://").trim_start_matches("https://").split(['/', ':']).next().unwrap_or("");
            if !host.is_empty() && (host.contains('.') || host.parse::<std::net::IpAddr>().is_ok() || host == "localhost") {
                targets.push(if w.contains('/') && !w.contains("://") { w.to_string() } else { host.to_string() });
            }
        }
        return Some((words[i].rsplit('/').next().unwrap_or(words[i]).to_string(), targets));
    }
    None
}

/// Is `target` (host, IP or `a.b.c.d/nn`) inside one of `allow` (host, `.domain`, `10.0.0.`
/// prefix or IPv4 CIDR)?
pub fn target_allowed(target: &str, allow: &[String]) -> bool {
    let t = target.trim().to_lowercase();
    let v4 = |s: &str| s.parse::<std::net::Ipv4Addr>().ok().map(u32::from);
    let cidr = |s: &str| -> Option<(u32, u32)> {
        let (ip, n) = s.split_once('/')?;
        let n: u32 = n.parse().ok().filter(|n| *n <= 32)?;
        let mask = if n == 0 { 0 } else { u32::MAX << (32 - n) };
        Some((v4(ip)? & mask, mask))
    };
    allow.iter().map(|a| a.trim().to_lowercase()).filter(|a| !a.is_empty()).any(|a| {
        if a == t {
            return true;
        }
        if let Some((net, mask)) = cidr(&a) {
            // A target range must sit wholly inside the allowed one.
            if let Some((tnet, tmask)) = cidr(&t) {
                return tmask >= mask && tnet & mask == net;
            }
            return v4(&t).is_some_and(|ip| ip & mask == net);
        }
        if let Some(bare) = a.strip_prefix('.') {
            return t.ends_with(&a) || t == bare;
        }
        a.ends_with('.') && t.starts_with(&a)
    })
}

/// Why a tool call is refused under this role, if it is.
pub fn check_tool(c: &Checks, tool: &str, input: &Value, scan_allow: &[String]) -> Option<String> {
    let pol = &c.policy;
    let cmd = command_of(tool, input);
    if let Some(cmd) = &cmd {
        let lc = cmd.to_lowercase();
        let parts: Vec<&str> = lc.split([';', '\n']).flat_map(|p| p.split("&&")).flat_map(|p| p.split("||")).map(str::trim).filter(|p| !p.is_empty()).collect();
        for g in &pol.deny {
            let g = g.to_lowercase();
            if seagent_security::glob::fnmatch(&g, lc.trim()) || parts.iter().any(|p| seagent_security::glob::fnmatch(&g, p)) {
                return Some(format!("this role never runs `{g}` (presets.toml policy). Do it by hand or change the role."));
            }
        }
        if pol.no_password_entry && password_entry().is_match(cmd) {
            return Some("this role never types or pipes a password for someone. Have the user set it themselves (a reset link or a forced change at next login).".into());
        }
        if pol.db_read_only && db_client().is_match(cmd) && sql_write().is_match(cmd) {
            return Some("databases are read-only for this role. Write the statement for a person with write access to review and run.".into());
        }
        if pol.scan_allowlist {
            if let Some((scanner, targets)) = scan_targets_of(cmd) {
                if targets.is_empty() {
                    return Some(format!("`{scanner}` is an active scanner and its target is not clear; name the target explicitly (it must be in `[role] scan_targets`)."));
                }
                if let Some(t) = targets.iter().find(|t| !target_allowed(t, scan_allow)) {
                    return Some(format!("active scan target `{t}` is not in `[role] scan_targets`; only allowlisted targets may be scanned. Ask the owner to add it."));
                }
            }
        }
    } else if pol.db_read_only && (tool.contains("sql") || tool.contains("query") || tool.contains("database")) {
        let text = boundary::tool_text(input);
        if sql_write().is_match(&text) {
            return Some("databases are read-only for this role. Write the statement for a person with write access to review and run.".into());
        }
    }
    if !c.acts.is_empty() {
        let text = boundary::tool_text(input);
        if let Some(h) = boundary::detect(&text, &c.acts) {
            return Some(h.instruction());
        }
    }
    None
}
