//! Structured doctor health checks (OpenClaw `src/flows/doctor-*`): `seagent doctor --lint` runs
//! the checks without changing anything and exits non-zero at `--severity-min` (default
//! warning); `seagent doctor --fix [--dry-run]` runs each check's repair, then re-runs its detect to
//! validate what is left (`doctor-repair-flow.ts`). `seagent doctor checks` lists them. Plain
//! `seagent doctor` keeps the quick environment report in `main.rs`.
//!
//! Checks: config migrations (repair: migrate with backup), runtime tool schemas (every tool the
//! model would see — built-ins, MCP, plugins — must have a JSON-object input schema of
//! `type: "object"`, no `$dynamicRef`/`$dynamicAnchor`, depth ≤ 128, a provider-safe unique
//! name), channel config (parse, known kind, plugin present, secret references set, privacy
//! notice for public channels), native helpers (sandbox runtimes for the configured exec
//! backend: bwrap, Landlock, user namespaces, container CLI), workspace (exists, writable,
//! untrusted project config, stale `trusted_projects` — repair removes them), removed state
//! (stale daemon socket/pid, state files of channels no longer configured — repair removes
//! them) and secret file permissions (repair: chmod 600).

use crate::args::Args;
use crate::R;
use seagent_core::ToolSpec;
use seagent_kernel::config::{Config, Paths};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const COMMANDS: &[&str] = &[];
pub const VALUE_FLAGS: &[&str] = &["only", "skip", "severity-min"];
// `--bundle`, `--out`, `--lines`, `--keep-identity` belong to ops/debugdump.rs (`seagent doctor --bundle`).
pub const BOOL_FLAGS: &[&str] = &["lint", "dry-run"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
    pub fn parse(s: &str) -> Option<Severity> {
        Some(match s {
            "info" => Severity::Info,
            "warning" | "warn" => Severity::Warning,
            "error" => Severity::Error,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub check: &'static str,
    pub severity: Severity,
    pub message: String,
    pub path: Option<String>,
    pub requirement: Option<String>,
    pub fix_hint: Option<String>,
}

fn finding(check: &'static str, severity: Severity, message: impl Into<String>) -> Finding {
    Finding { check, severity, message: message.into(), path: None, requirement: None, fix_hint: None }
}

impl Finding {
    fn path(mut self, p: impl Into<String>) -> Self {
        self.path = Some(p.into());
        self
    }
    fn req(mut self, r: impl Into<String>) -> Self {
        self.requirement = Some(r.into());
        self
    }
    fn hint(mut self, h: impl Into<String>) -> Self {
        self.fix_hint = Some(h.into());
        self
    }
    pub fn to_json(&self) -> Value {
        json!({"checkId": self.check, "severity": self.severity.as_str(), "message": self.message, "path": self.path, "requirement": self.requirement, "fixHint": self.fix_hint})
    }
}

/// What every check sees.
pub struct Ctx {
    pub paths: Paths,
    pub cfg: Config,
    pub ws: PathBuf,
    /// Tools the model would see (None = could not build the agent; the tool check reports it).
    pub specs: Result<Vec<ToolSpec>, String>,
    pub secret_names: Vec<String>,
    pub daemon_running: bool,
}

#[derive(Default)]
pub struct Repair {
    pub changes: Vec<String>,
    pub warnings: Vec<String>,
    /// "repaired" (default) or "skipped".
    pub skipped: Option<String>,
    /// Updated config carried to the following checks (and the validation re-detect).
    pub config: Option<Config>,
}

/// A repair entry point: `(ctx, findings, apply)`.
pub type RepairFn = fn(&Ctx, &[Finding], bool) -> Result<Repair, String>;

#[derive(Clone, Copy)]
pub struct Check {
    pub id: &'static str,
    pub description: &'static str,
    pub detect: fn(&Ctx) -> Result<Vec<Finding>, String>,
    pub repair: Option<RepairFn>,
}

pub fn checks() -> Vec<Check> {
    vec![
        Check { id: "core/doctor/config-migrations", description: "The user config has no pending migrations (retired models, config_version).", detect: detect_migrations, repair: Some(repair_migrations) },
        Check { id: "core/doctor/runtime-tool-schemas", description: "Every runtime tool exposes a provider-compatible input schema.", detect: detect_tool_schemas, repair: None },
        Check { id: "core/doctor/channel-config", description: "Configured channels parse, resolve their secrets and declare required notices.", detect: detect_channels, repair: None },
        Check { id: "core/doctor/native-status", description: "Native sandbox and process helpers are available for this runtime.", detect: detect_native, repair: None },
        Check { id: "core/doctor/workspace", description: "The workspace is usable and trusted_projects points at existing directories.", detect: detect_workspace, repair: Some(repair_workspace) },
        Check { id: "core/doctor/removed-state", description: "No stale daemon runtime files or state of removed channels remain.", detect: detect_removed_state, repair: Some(repair_removed_state) },
        Check { id: "core/doctor/secret-permissions", description: "Secret files are readable by the owner only.", detect: detect_secret_perms, repair: Some(repair_secret_perms) },
        Check { id: "core/doctor/gateway-auth", description: "The app server/gateway has a usable bearer token and is not exposed without one.", detect: detect_gateway_auth, repair: Some(repair_gateway_auth) },
        Check { id: "core/doctor/gateway-services", description: "The installed daemon service matches this build and seagentd is not crash-looping.", detect: detect_gateway_services, repair: Some(repair_gateway_services) },
        Check { id: "core/doctor/exec-credential", description: "The exec backend's credentials (sudo secret, ssh key, credential files) resolve.", detect: detect_exec_credential, repair: None },
        Check { id: "core/doctor/model-references", description: "Every configured model reference names a known provider/model with usable credentials.", detect: detect_model_reference, repair: None },
    ]
}

// ───────────────────────── config migrations ─────────────────────────

fn detect_migrations(c: &Ctx) -> Result<Vec<Finding>, String> {
    let p = c.paths.user_config();
    let Ok(text) = std::fs::read_to_string(&p) else { return Ok(vec![]) };
    let (_, notes) = crate::ops::confcli::migrate_text(&text)?;
    Ok(notes.into_iter().map(|n| finding("core/doctor/config-migrations", Severity::Warning, format!("config migration pending: {n}")).path(p.display().to_string()).hint("Run `seagent doctor --fix` (or `seagent config migrate`) to apply it; a backup is kept.")).collect())
}

fn repair_migrations(c: &Ctx, _: &[Finding], dry: bool) -> Result<Repair, String> {
    let text = std::fs::read_to_string(c.paths.user_config()).map_err(|e| e.to_string())?;
    let (new, notes) = crate::ops::confcli::migrate_text(&text)?;
    if !dry {
        crate::ops::confcli::write_validated(&c.paths, &new, true)?;
    }
    Ok(Repair { changes: notes.into_iter().map(|n| format!("{}migrated {n}", if dry { "would have " } else { "" })).collect(), ..Default::default() })
}

// ───────────────────────── tool schemas ─────────────────────────

pub const MAX_TOOL_SCHEMA_DEPTH: usize = 128;
const LITERAL_KEYS: &[&str] = &["const", "enum", "default", "examples", "example"];
const MAP_KEYS: &[&str] = &["properties", "patternProperties", "$defs", "definitions", "dependentSchemas"];

fn walk(v: &Value, path: &str, depth: usize, keywords: bool, out: &mut Vec<String>, too_deep: &mut bool) {
    if depth > MAX_TOOL_SCHEMA_DEPTH {
        *too_deep = true;
        return;
    }
    match v {
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                walk(x, &format!("{path}[{i}]"), depth + 1, keywords, out, too_deep);
            }
        }
        Value::Object(o) => {
            if keywords {
                for k in ["$dynamicRef", "$dynamicAnchor"] {
                    if o.contains_key(k) {
                        out.push(format!("{path}.{k}"));
                    }
                }
            }
            for (k, x) in o {
                if !x.is_object() && !x.is_array() {
                    continue;
                }
                let child_kw = keywords && !LITERAL_KEYS.contains(&k.as_str());
                if child_kw && MAP_KEYS.contains(&k.as_str()) {
                    if let Some(m) = x.as_object() {
                        for (n, s) in m {
                            walk(s, &format!("{path}.{k}.{n}"), depth + 1, true, out, too_deep);
                        }
                        continue;
                    }
                }
                walk(x, &format!("{path}.{k}"), depth + 1, child_kw, out, too_deep);
            }
        }
        _ => {}
    }
}

/// Violations for one tool's input schema (empty = compatible).
pub fn schema_violations(name: &str, schema: &Value) -> Vec<String> {
    let path = format!("{name}.parameters");
    let mut v = vec![];
    match schema.as_object() {
        None => v.push(format!("{path} must be a JSON object schema")),
        Some(o) => {
            if o.get("type").is_some_and(|t| t != "object") {
                v.push(format!("{path}.type must be \"object\""));
            }
        }
    }
    let mut deep = false;
    walk(schema, &path, 0, true, &mut v, &mut deep);
    if deep {
        v.push(format!("{path} nests deeper than {MAX_TOOL_SCHEMA_DEPTH} levels (truncated for providers)"));
    }
    if let Some(req) = schema.get("required").and_then(|r| r.as_array()) {
        let props = schema.get("properties").and_then(|p| p.as_object());
        for r in req.iter().filter_map(|r| r.as_str()) {
            if !props.is_some_and(|p| p.contains_key(r)) {
                v.push(format!("{path}.required names `{r}`, which is not in properties"));
            }
        }
    }
    v
}

fn detect_tool_schemas(c: &Ctx) -> Result<Vec<Finding>, String> {
    const ID: &str = "core/doctor/runtime-tool-schemas";
    let specs = match &c.specs {
        Ok(s) => s,
        Err(e) => return Ok(vec![finding(ID, Severity::Error, "Runtime tool schema validation could not load the runtime tool set.").req(e.clone()).hint("Fix the configuration error above (or disable the offending MCP server / plugin), then rerun doctor.")]),
    };
    let name_ok = regex::Regex::new(r"^[A-Za-z0-9_-]{1,64}$").unwrap();
    let mut out = vec![];
    let mut seen = std::collections::BTreeMap::new();
    for s in specs {
        let owner = if let Some(rest) = s.name.strip_prefix("mcp__") { format!(" (MCP server {})", rest.split("__").next().unwrap_or("")) } else { String::new() };
        let mut v = schema_violations(&s.name, &s.input_schema);
        if !name_ok.is_match(&s.name) {
            v.push(format!("tool name `{}` must match ^[A-Za-z0-9_-]{{1,64}}$ for every provider", s.name));
        }
        *seen.entry(s.name.clone()).or_insert(0) += 1;
        if !v.is_empty() {
            v.truncate(12);
            let hint = if owner.is_empty() { "Fix the tool's schema (or disable the tool via tools.disabled), then rerun doctor.".to_string() } else { "Fix or disable the offending MCP server, then rerun doctor before relying on assistant tool startup.".to_string() };
            out.push(finding(ID, Severity::Error, format!("tool {}{owner} has an unsupported input schema for runtime projection.", s.name)).path(s.name.clone()).req(v.join(", ")).hint(hint));
        }
    }
    for (n, k) in seen.into_iter().filter(|x| x.1 > 1) {
        out.push(finding(ID, Severity::Error, format!("{k} tools are named `{n}`; providers reject duplicate tool names.")).path(n).hint("Rename or disable one of them (MCP servers can be prefixed)."));
    }
    Ok(out)
}

// ───────────────────────── channels ─────────────────────────

fn secret_refs(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => {
            let re = regex::Regex::new(r"\{\{secret:([A-Za-z0-9_.-]+)\}\}").unwrap();
            out.extend(re.captures_iter(s).map(|c| c[1].to_string()));
        }
        Value::Array(a) => a.iter().for_each(|x| secret_refs(x, out)),
        Value::Object(o) => o.values().for_each(|x| secret_refs(x, out)),
        _ => {}
    }
}

fn detect_channels(c: &Ctx) -> Result<Vec<Finding>, String> {
    const ID: &str = "core/doctor/channel-config";
    let mut out = vec![];
    for (n, t) in &c.cfg.channels {
        let path = format!("channels.{n}");
        let json = serde_json::to_value(t).unwrap_or(Value::Null);
        let cc = match seagent_channel::config::parse_config(n, &json) {
            Ok(cc) => cc,
            Err(e) => {
                out.push(finding(ID, Severity::Error, e).path(path).hint("Fix the channel table (see docs for its kind), then rerun doctor."));
                continue;
            }
        };
        if cc.is_plugin() {
            let p = cc.plugin.clone().unwrap_or_default();
            if !c.cfg.plugins.contains_key(&p) {
                out.push(finding(ID, Severity::Error, format!("[{path}]: no plugin `{p}` is configured")).path(path.clone()).hint(format!("Add [plugins.{p}] or remove the channel.")));
            }
        }
        let mut refs = vec![];
        secret_refs(&json, &mut refs);
        for r in refs {
            if !c.secret_names.contains(&r) && std::env::var(&r).map(|v| v.is_empty()).unwrap_or(true) {
                out.push(finding(ID, Severity::Error, format!("[{path}] references secret `{r}`, which is not set")).path(path.clone()).req("Configured channels should resolve every {{secret:…}} reference.").hint(format!("Run `seagent secrets set {r}`.")));
            }
        }
        use seagent_channel::access::{DmPolicy, GroupPolicy};
        let p = &cc.policy;
        if (matches!(p.dm_policy, DmPolicy::Open | DmPolicy::Pairing) || p.group_policy == GroupPolicy::Open) && cc.privacy_notice.is_none() {
            out.push(finding(ID, Severity::Warning, format!("[{path}] accepts people you have not listed but has no `privacy_notice` (個資法第 8 條告知義務)")).path(path.clone()).hint("Add privacy_notice = \"…\" to the channel."));
        }
    }
    Ok(out)
}

// ───────────────────────── native helpers ─────────────────────────

fn on_path(bin: &str) -> Option<PathBuf> {
    if bin.contains('/') {
        return Some(PathBuf::from(bin)).filter(|p| p.exists());
    }
    #[cfg(not(unix))]
    if let Some(p) = seagent_core::platform::layout::which(bin) {
        return Some(p); // PATHEXT lookup (`bwrap` → never; `docker` → docker.exe)
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).map(|d| d.join(bin)).find(|p| std::fs::metadata(p).is_ok_and(|m| crate::ops::hostos::is_executable(p, &m)))
}

/// `[exec]` from the user config file (`backend`, `bwrap.binary`).
fn exec_table(paths: &Paths) -> toml::Table {
    std::fs::read_to_string(paths.user_config()).ok().and_then(|t| t.parse::<toml::Table>().ok()).and_then(|t| t.get("exec").and_then(|e| e.as_table()).cloned()).unwrap_or_default()
}

#[cfg_attr(windows, allow(unreachable_code, unused_variables))]
fn detect_native(c: &Ctx) -> Result<Vec<Finding>, String> {
    const ID: &str = "core/doctor/native-status";
    let exec = exec_table(&c.paths);
    let backend = exec.get("backend").and_then(|v| v.as_str()).unwrap_or("local").to_string();
    // Windows: bwrap / Landlock / user namespaces / cgroups do not exist; the native sandbox
    // is an AppContainer (restricted token + low integrity when profiles cannot be created).
    #[cfg(windows)]
    {
        let _ = &backend;
        let mut out = vec![];
        let ac = seagent_tools::exec::appcontainer::available();
        let sev = if ac { Severity::Info } else if backend == "appcontainer" { Severity::Error } else { Severity::Warning };
        out.push(finding(ID, sev, if ac { "appcontainer: available (Windows AppContainer + Job Object)".to_string() } else { "appcontainer: AppContainer profiles cannot be created here; the sandbox degrades to a restricted token at low integrity".to_string() }).hint("exec.backend = \"appcontainer\" (or `auto`) runs tools in an AppContainer; for a microVM build the guest image (`seagent sandbox vm image build`) and enable Hyper-V or QEMU with WHPX."));
        for b in ["docker", "podman"] {
            if backend == b {
                let found = on_path(b);
                out.push(finding(ID, if found.is_some() { Severity::Info } else { Severity::Error }, format!("{b}: {}", found.map(|p| format!("available at {}", p.display())).unwrap_or_else(|| "not installed".into()))).hint(format!("Install {b} (Docker Desktop / Podman machine) or choose another exec.backend.")));
            }
        }
        let git = on_path("git");
        out.push(finding(ID, if git.is_some() { Severity::Info } else if c.cfg.checkpoint.enabled { Severity::Error } else { Severity::Warning }, format!("git (checkpoints): {}", if git.is_some() { "available" } else { "not installed" })).hint("Install Git for Windows, or set checkpoint.enabled = false."));
        return Ok(out);
    }
    // ent-023/026: one kernel probe shared with the sandbox policy (`seagent sandbox explain`).
    let hk = seagent_vm::hostcaps::HostKernel::detect();
    let landlock = hk.landlock_abi > 0;
    let userns = hk.userns;
    let bwrap = on_path(exec.get("bwrap").and_then(|b| b.get("binary")).and_then(|v| v.as_str()).unwrap_or("bwrap"));
    let needed = |b: &str| backend == b;
    let mut out = vec![];
    let sev = |ok: bool, required: bool| if ok { Severity::Info } else if required { Severity::Error } else { Severity::Warning };
    out.push(finding(ID, sev(bwrap.is_some() && userns, needed("bwrap")), match (&bwrap, userns) {
        (Some(p), true) => format!("bwrap: available at {}", p.display()),
        (Some(_), false) => "bwrap: installed but unprivileged user namespaces are disabled".into(),
        (None, _) => "bwrap: not installed".into(),
    }).hint("Install bubblewrap (and enable user namespaces) to use exec.backend = \"bwrap\"."));
    out.push(finding(ID, sev(landlock, needed("landlock")), if landlock { format!("landlock: ABI {} in kernel {}", hk.landlock_abi, hk.release) } else if hk.version < (5, 13) { format!("landlock: unavailable (kernel {} < 5.13)", hk.release) } else { "landlock: not in the kernel's active LSM list".to_string() }).hint("Boot a kernel ≥ 5.13 with lsm=…,landlock to use exec.backend = \"landlock\"; on older kernels seagent falls back to bwrap, a container engine or the host (`seagent sandbox explain`)."));
    if !userns {
        out.push(finding(ID, Severity::Warning, format!("user namespaces: disabled ({})", hk.userns_blocker.clone().unwrap_or_default())).hint("bwrap and rootless podman cannot run; seagent uses Landlock, docker or only its static gates (`seagent sandbox explain` shows which). Enable with sysctl user.max_user_namespaces=15000."));
    }
    out.push(finding(ID, Severity::Info, format!("cgroups: {} (process cleanup and resource caps use it when a delegated subtree is writable)", hk.cgroup.label())));
    for b in ["docker", "podman"] {
        if needed(b) {
            let found = on_path(b);
            out.push(finding(ID, sev(found.is_some(), true), format!("{b}: {}", found.map(|p| format!("available at {}", p.display())).unwrap_or_else(|| "not installed".into()))).hint(format!("Install {b} or choose another exec.backend.")));
        }
    }
    let git = on_path("git");
    out.push(finding(ID, sev(git.is_some(), c.cfg.checkpoint.enabled), format!("git (checkpoints): {}", if git.is_some() { "available" } else { "not installed" })).hint("Install git, or set checkpoint.enabled = false."));
    Ok(out)
}

// ───────────────────────── workspace ─────────────────────────

fn detect_workspace(c: &Ctx) -> Result<Vec<Finding>, String> {
    const ID: &str = "core/doctor/workspace";
    let mut out = vec![];
    match std::fs::metadata(&c.ws) {
        Err(e) => out.push(finding(ID, Severity::Error, format!("workspace {} is not accessible: {e}", c.ws.display())).path(c.ws.display().to_string())),
        Ok(m) if m.permissions().readonly() || !crate::ops::hostos::writable(&c.ws) => {
            out.push(finding(ID, Severity::Warning, format!("workspace {} is not writable; file tools and checkpoints will fail", c.ws.display())).path(c.ws.display().to_string()))
        }
        _ => {}
    }
    let proj = c.ws.join(".seagent/config.toml");
    let trusted = c.cfg.trusted_projects.iter().any(|t| Path::new(t).canonicalize().ok().as_deref() == c.ws.canonicalize().ok().as_deref());
    if proj.exists() && !trusted {
        out.push(finding(ID, Severity::Info, format!("{} exists but this workspace is not in trusted_projects; gated keys in it are ignored", proj.display())).path(proj.display().to_string()).hint("Add the workspace to trusted_projects if you trust it."));
    }
    for t in &c.cfg.trusted_projects {
        if !Path::new(t).is_dir() {
            out.push(finding(ID, Severity::Warning, format!("trusted_projects entry {t} no longer exists")).path(format!("trusted_projects:{t}")).hint("Run `seagent doctor --fix` to drop it."));
        }
    }
    Ok(out)
}

fn repair_workspace(c: &Ctx, f: &[Finding], dry: bool) -> Result<Repair, String> {
    let stale: Vec<String> = f.iter().filter_map(|x| x.path.as_deref()?.strip_prefix("trusted_projects:").map(String::from)).collect();
    if stale.is_empty() {
        return Ok(Repair { skipped: Some("only manual workspace findings".into()), ..Default::default() });
    }
    let text = std::fs::read_to_string(c.paths.user_config()).map_err(|e| e.to_string())?;
    let t: toml::Table = text.parse().map_err(|e| format!("config does not parse: {e}"))?;
    let keep: Vec<toml::Value> = t.get("trusted_projects").and_then(|v| v.as_array()).cloned().unwrap_or_default().into_iter().filter(|v| !v.as_str().is_some_and(|s| stale.iter().any(|x| x == s))).collect();
    let mut cfg = c.cfg.clone();
    cfg.trusted_projects.retain(|t| !stale.contains(t));
    if !dry {
        let new = crate::ops::confcli::edited_text(&text, "trusted_projects", Some(toml::Value::Array(keep)))?;
        crate::ops::confcli::write_validated(&c.paths, &new, true)?;
    }
    Ok(Repair { changes: stale.iter().map(|s| format!("{} {s} from trusted_projects", if dry { "would remove" } else { "removed" })).collect(), config: Some(cfg), ..Default::default() })
}

// ───────────────────────── removed / stale state ─────────────────────────

fn pid_alive(pid: i32) -> bool {
    crate::ops::hostos::pid_alive(pid as i64)
}

fn stale_state(c: &Ctx) -> Vec<(PathBuf, String)> {
    let mut v = vec![];
    if !c.daemon_running {
        let sock = c.paths.socket();
        if sock.exists() {
            v.push((sock, "stale daemon socket (seagentd is not running)".to_string()));
        }
        let pid = c.paths.runtime.join("seagentd.pid");
        if let Ok(p) = std::fs::read_to_string(&pid) {
            if !p.trim().parse::<i32>().is_ok_and(pid_alive) {
                v.push((pid, format!("stale daemon pid file (process {} is gone)", p.trim())));
            }
        }
    }
    let dir = c.paths.data.join("channels");
    for e in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let chan = name.split('.').next().unwrap_or("").to_string();
        if !chan.is_empty() && !c.cfg.channels.contains_key(&chan) {
            v.push((e.path(), format!("state of removed channel `{chan}`")));
        }
    }
    v
}

fn detect_removed_state(c: &Ctx) -> Result<Vec<Finding>, String> {
    Ok(stale_state(c).into_iter().map(|(p, why)| finding("core/doctor/removed-state", Severity::Warning, format!("{why}: {}", p.display())).path(p.display().to_string()).hint("Run `seagent doctor --fix` to remove it.")).collect())
}

fn repair_removed_state(c: &Ctx, _: &[Finding], dry: bool) -> Result<Repair, String> {
    let mut r = Repair::default();
    for (p, why) in stale_state(c) {
        // Only ever inside seagent's own runtime/data directories.
        if !(p.starts_with(&c.paths.runtime) || p.starts_with(&c.paths.data)) {
            r.warnings.push(format!("refusing to remove {} outside seagent's directories", p.display()));
            continue;
        }
        if !dry {
            let res = if p.is_dir() { std::fs::remove_dir_all(&p) } else { std::fs::remove_file(&p) };
            if let Err(e) = res {
                r.warnings.push(format!("{}: {e}", p.display()));
                continue;
            }
        }
        r.changes.push(format!("{} {} ({why})", if dry { "would remove" } else { "removed" }, p.display()));
    }
    Ok(r)
}

// ───────────────────────── secret permissions ─────────────────────────

fn secret_files(c: &Ctx) -> Vec<PathBuf> {
    [c.paths.secrets(), c.paths.config_dir.join(".env")].into_iter().filter(|p| p.exists()).collect()
}

fn detect_secret_perms(c: &Ctx) -> Result<Vec<Finding>, String> {
    Ok(secret_files(c).into_iter().filter_map(|p| {
        let mode = crate::ops::hostos::mode_of(&p).ok()? & 0o777;
        (mode & 0o077 != 0).then(|| finding("core/doctor/secret-permissions", Severity::Error, format!("{} is readable by others (mode {mode:o})", p.display())).path(p.display().to_string()).hint("Run `seagent doctor --fix` (chmod 600).")
        )
    }).collect())
}

fn repair_secret_perms(c: &Ctx, _: &[Finding], dry: bool) -> Result<Repair, String> {
    let mut r = Repair::default();
    for p in secret_files(c) {
        let mode = crate::ops::hostos::mode_of(&p).map_err(|e| e.to_string())? & 0o777;
        if mode & 0o077 != 0 {
            if !dry {
                crate::ops::hostos::set_mode(&p, 0o600).map_err(|e| e.to_string())?;
            }
            r.changes.push(format!("{} {} {mode:o} → 600", if dry { "would chmod" } else { "chmod" }, p.display()));
        }
    }
    Ok(r)
}

// ───────────────────────── gateway auth (OpenClaw doctor-gateway-auth) ─────────────────────────

/// Values that are never a usable bearer token: blank, the literal strings Node's
/// stringification produces, a redaction sentinel, or an unresolved `{{secret:NAME}}` reference
/// (the server refuses to start on one of those, so doctor must find it first).
fn unusable_token(tok: &str, secret_names: &[String]) -> Option<&'static str> {
    let t = tok.trim();
    if t.is_empty() {
        return Some("blank");
    }
    if matches!(t, "null" | "undefined" | "changeme" | "***" | "[redacted]") {
        return Some("a placeholder, not a secret");
    }
    if let Some(name) = t.strip_prefix("{{secret:").and_then(|r| r.strip_suffix("}}")).map(str::trim) {
        // A reference resolves only when the named secret exists; the server refuses to start
        // on an unresolved one, so this must be reported before the restart loop starts.
        if !secret_names.iter().any(|n| n == name) {
            return Some("an unresolved secret reference");
        }
    } else if t.contains("{{secret:") {
        return Some("an unresolved secret reference");
    }
    None
}

/// The `[app]` server is seagent's gateway: its bearer token is the only credential the Control UI,
/// the OpenAI-compatible API, A2A and device nodes accept. Upstream reports a missing/unresolvable
/// gateway token as an error and an auth-off gateway as a warning; seagent's app server is off by
/// default, so a disabled server with no token is fine.
fn detect_gateway_auth(c: &Ctx) -> Result<Vec<Finding>, String> {
    let app = seagent_app::AppConfig::parse(&c.cfg.app)?;
    let mut v = vec![];
    let tok = app.token.clone().unwrap_or_default();
    let bad = unusable_token(&tok, &c.secret_names);
    let remote = !(app.listen.starts_with("127.") || app.listen.starts_with("localhost") || app.listen.starts_with("[::1]") || app.listen.starts_with("::1"));
    match (app.enabled, bad) {
        (true, Some(why)) => v.push(
            finding("core/doctor/gateway-auth", Severity::Error, format!("the app server is enabled but its token is {why}"))
                .path("app.token")
                .req("a bearer token in app.token (or the APP_TOKEN secret)")
                .hint("Run `seagent doctor --fix` to generate one (stored as the APP_TOKEN secret), then restart the daemon."),
        ),
        (_, None) if remote => v.push(
            finding("core/doctor/gateway-auth", Severity::Warning, format!("[app] listens on {} (all/non-loopback interfaces) with a bearer token; anyone who leaks it gets the agent's tools", app.listen))
                .path("app.listen")
                .hint("Bind 127.0.0.1 and put a TLS reverse proxy in front for remote access, or keep the token in the vault."),
        ),
        _ => {}
    }
    // The dashboard login is an *additional* credential, never a replacement for the token.
    if app.enabled && app.auth.enabled {
        use seagent_app::dashboard_auth::{Basic, Oidc};
        let reason = match app.auth.provider.as_str() {
            "basic" | "" => Basic::new(&app.auth).err(),
            "self_hosted" | "oidc" => Oidc::new(&app.auth).err(),
            other => Some(format!("[app.auth] provider `{other}` is not built in (basic, self_hosted) and no plugin provides it")),
        };
        if let Some(r) = reason {
            v.push(finding("core/doctor/gateway-auth", Severity::Error, format!("[app.auth] is enabled but cannot build its login: {r}")).path("app.auth").hint("Fix the [app.auth] section, or set enabled = false to rely on the app token alone."));
        }
    }
    Ok(v)
}

/// `--fix` generates a token: upstream's `--generate-gateway-token`. It is stored in the vault
/// (0600) and the config keeps only `{{secret:APP_TOKEN}}`, so the value never lands in
/// config.toml or in a log.
fn repair_gateway_auth(c: &Ctx, _: &[Finding], dry: bool) -> Result<Repair, String> {
    let app = seagent_app::AppConfig::parse(&c.cfg.app)?;
    let mut r = Repair::default();
    if !app.enabled {
        return Ok(r);
    }
    let tok = app.token.clone().unwrap_or_default();
    let Some(why) = unusable_token(&tok, &c.secret_names) else { return Ok(r) };
    // An existing `{{secret:NAME}}` keeps its name; otherwise APP_TOKEN is the conventional one.
    let name = tok.trim().strip_prefix("{{secret:").and_then(|s| s.strip_suffix("}}")).map(str::trim).filter(|n| !n.is_empty()).unwrap_or("APP_TOKEN").to_string();
    let new = seagent_kernel::util::random_hex(32);
    if !dry {
        let vault = seagent_kernel::vault::Vault::load(&c.paths.secrets())?;
        vault.set(&name, &new)?;
        if name != "APP_TOKEN" || tok.trim().is_empty() {
            crate::ops::confcli::set(&c.paths, "app.token", &format!("\"{{{{secret:{name}}}}}\""))?;
        }
    }
    r.changes.push(format!("{} a gateway token ({why}) and stored it as the {name} secret{}", if dry { "would generate" } else { "generated" }, if dry { "" } else { "; restart the daemon and re-pair devices with the new token" }));
    Ok(r)
}

// ───────────────────────── gateway services (OpenClaw doctor-gateway-services) ─────────────────────────

/// Upstream reports extra/legacy gateway services and a restart-storming gateway. seagent has one
/// unit per profile (`ops/service.rs`): doctor audits the installed unit against what this build
/// writes, and reuses the restart-storm log the daemon keeps.
fn unit_field(text: &str, key: &str) -> String {
    text.lines().find_map(|l| l.trim().strip_prefix(key)?.strip_prefix('=').map(|v| v.trim().to_string())).unwrap_or_default()
}

fn detect_gateway_services(c: &Ctx) -> Result<Vec<Finding>, String> {
    let mut v = vec![];
    // Only the unit of *this* workspace/profile is ours to judge: another profile's unit under
    // the same name runs a different `-w`, and rewriting it would break that install.
    let path = crate::ops::service::user_unit_dir().join(crate::ops::service::unit_name());
    if let Ok(installed) = std::fs::read_to_string(&path) {
        let wd = unit_field(&installed, "WorkingDirectory");
        if wd.is_empty() || Path::new(&wd) == c.ws {
            let exe = std::env::current_exe().unwrap_or_default();
            for i in crate::ops::service::audit_text(&installed, &crate::ops::service::unit(&exe, &c.ws, None), &exe) {
                let mut f = finding("core/doctor/gateway-services", Severity::Warning, i.message.clone()).path(path.display().to_string());
                if let Some(fix) = i.fix {
                    f = f.req(fix);
                }
                v.push(f.hint("Run `seagent doctor --fix` to rewrite the unit, then `systemctl --user daemon-reload`."));
            }
        }
    }
    // launchd agent / Task Scheduler task / Windows Service (ops::service_os); not installed is fine.
    #[cfg(any(target_os = "macos", windows))]
    for i in crate::ops::service::audit(&c.ws).into_iter().filter(|i| i.code != "unit-missing") {
        let f = finding("core/doctor/gateway-services", Severity::Warning, i.message.clone());
        v.push(match i.fix {
            Some(fix) => f.req(fix).hint("Run `seagent doctor --fix` (or `seagent service install`) to rewrite it."),
            None => f,
        });
    }
    let starts = crate::ops::service::recent_starts(&c.paths, seagent_kernel::util::unix_now()).len();
    if starts >= crate::ops::service::STORM_THRESHOLD {
        v.push(
            finding("core/doctor/gateway-services", Severity::Error, format!("seagentd started {starts} times in the last {} minutes: it is crash-looping", crate::ops::service::STORM_WINDOW_SECS / 60))
                .path(c.paths.data.join("restarts.log").display().to_string())
                .hint("Read `seagent service logs` / `seagent logs` for the crash, fix the cause, then restart."),
        );
    }
    Ok(v)
}

fn repair_gateway_services(c: &Ctx, f: &[Finding], dry: bool) -> Result<Repair, String> {
    let mut r = Repair::default();
    // Only a drifted/missing ExecStart unit is rewritten; a crash loop needs a human.
    let rewrite = f.iter().any(|x| x.check == "core/doctor/gateway-services" && (x.requirement.as_deref() == Some("reinstall") || x.message.contains("differs from what this version writes")));
    if !rewrite {
        return Ok(r);
    }
    let path = crate::ops::service::user_unit_dir().join(crate::ops::service::unit_name());
    if dry {
        r.changes.push(format!("would rewrite {} for this build's binary and hardening flags", path.display()));
        return Ok(r);
    }
    r.warnings.push(crate::ops::service::install_user(&c.ws, false)?);
    #[cfg(any(target_os = "macos", windows, target_os = "android", target_os = "ios"))]
    r.changes.push("rewrote the autostart entry — run `seagent service restart` to apply".into());
    #[cfg(not(any(target_os = "macos", windows, target_os = "android", target_os = "ios")))]
    r.changes.push(format!("rewrote {} — run `systemctl --user daemon-reload && systemctl --user restart {}` to apply", path.display(), crate::ops::service::unit_name()));
    Ok(r)
}

// ───────────────────────── exec credentials (OpenClaw doctor-gateway-exec-credential) ─────────────────────────

/// The exec backend may need a credential to run tools: a sudo password (vault secret), an ssh
/// private key, or host files copied into a container/remote backend. Upstream reports an
/// unresolvable exec credential instead of letting every tool call fail later.
fn detect_exec_credential(c: &Ctx) -> Result<Vec<Finding>, String> {
    let exec = seagent_tools::exec::ExecConfig::parse(&serde_json::to_value(&c.cfg.exec).map_err(|e| e.to_string())?)?;
    let mut v = vec![];
    let secret = exec.sudo_password_secret.trim();
    if !secret.is_empty() && !c.secret_names.iter().any(|n| n == secret) {
        // `SUDO_PASSWORD` is the documented default (no secret = a plain sudo prompt), so its
        // absence is a note; a name the operator chose is a warning (sudo will silently prompt).
        let sev = if secret == "SUDO_PASSWORD" { Severity::Info } else { Severity::Warning };
        v.push(
            finding("core/doctor/exec-credential", sev, format!("exec.sudo_password_secret names the secret `{secret}`, which is not in the vault; the sudo tool falls back to a plain prompt"))
                .path("exec.sudo_password_secret")
                .req(format!("a `{secret}` entry in secrets.toml"))
                .hint(format!("Run `seagent secrets set {secret}` (or drop exec.sudo_password_secret).")),
        );
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let expand = |p: &str| if let Some(rest) = p.strip_prefix("~/") { PathBuf::from(&home).join(rest) } else { PathBuf::from(p) };
    for f in &exec.credential_files {
        let p = expand(f);
        if !p.exists() {
            v.push(
                finding("core/doctor/exec-credential", Severity::Warning, format!("exec.credential_files lists {}, which does not exist", p.display()))
                    .path("exec.credential_files")
                    .hint("Fix the path or remove it; the exec backend copies it on every call."),
            );
        }
    }
    let key = exec.ssh.identity_file.trim();
    if !key.is_empty() {
        let p = expand(key);
        if !p.exists() {
            v.push(finding("core/doctor/exec-credential", Severity::Warning, format!("exec.ssh.identity_file {} does not exist", p.display())).path("exec.ssh.identity_file").hint("Point exec.ssh.identity_file at the private key, or leave it empty to use ssh-agent."));
        } else if let Ok(mode) = crate::ops::hostos::mode_of(&p) {
            if mode & 0o077 != 0 {
                v.push(finding("core/doctor/exec-credential", Severity::Warning, format!("exec.ssh.identity_file {} is readable by others (ssh refuses it)", p.display())).path(p.display().to_string()).hint("chmod 600 the key."));
            }
        }
    }
    Ok(v)
}

// ───────────────────────── model references (OpenClaw doctor-model-reference-check) ─────────────────────────

/// Every model reference in the config must name a provider this install knows, a model that
/// provider can serve (or one with no declared list, where the id cannot be checked offline),
/// and credentials that actually resolve. Upstream reports an unknown provider as a warning and
/// an uncatalogued model as info; doctor never invents a replacement reference.
fn detect_model_reference(c: &Ctx) -> Result<Vec<Finding>, String> {
    let vault = std::sync::Arc::new(seagent_kernel::vault::Vault::load(&c.paths.secrets()).unwrap_or_else(|_| seagent_kernel::vault::Vault::empty()));
    let ps = crate::providers::Providers::new(&c.cfg.providers, vault)?;
    let mut refs: Vec<(&str, String)> = vec![("model.default", c.cfg.model.default.clone())];
    for f in &c.cfg.model.fallback {
        refs.push(("model.fallback", f.clone()));
    }
    refs.push(("model.aux", c.cfg.aux_model().to_string()));
    let mut v = vec![];
    for (key, raw) in refs {
        if raw.trim().is_empty() {
            v.push(finding("core/doctor/model-references", Severity::Warning, format!("{key} is empty: the first turn will fail until a model is chosen")).path(key).hint("Run `seagent setup` or `seagent model set <provider>/<model>`."));
            continue;
        }
        let resolved = c.cfg.resolve_model(raw.trim());
        let Some((pid, model)) = resolved.split_once('/') else {
            v.push(finding("core/doctor/model-references", Severity::Error, format!("{key} = `{raw}` is not a provider/model reference")).path(key).hint("Use `<provider>/<model>`, e.g. `anthropic/claude-sonnet-4-5`."));
            continue;
        };
        let (pid, model) = (pid.trim(), model.trim());
        let Some(canon) = ps.canonical(pid) else {
            v.push(
                finding("core/doctor/model-references", Severity::Warning, format!("{key} = `{raw}` uses unknown provider `{pid}`: no [providers.{pid}] entry and no built-in of that name"))
                    .path(key)
                    .req("a configured provider")
                    .hint("Add the provider under [providers] (or `seagent providers add`), or pick another model."),
            );
            continue;
        };
        let conf = ps.config(&canon).expect("canonical() resolves to a config");
        let known = conf.models.iter().any(|m| m.eq_ignore_ascii_case(model)) || conf.models.is_empty() || seagent_model::modelsdb::registry_entry(Some(&canon), model).is_some();
        if !known {
            v.push(
                finding("core/doctor/model-references", Severity::Info, format!("{key} = `{raw}` uses known provider `{canon}` but `{model}` is not in the local catalog (newly released or self-hosted?)"))
                    .path(key)
                    .req("a provider-supported model id")
                    .hint("Check the id with the provider; rerun with `--severity-min info` to keep it visible."),
            );
        }
        if let Err(e) = ps.key_source(&canon) {
            v.push(
                finding("core/doctor/model-references", Severity::Warning, format!("{key} = `{raw}`: provider `{canon}` has no usable credentials ({e})"))
                    .path(key)
                    .req(format!("a key for {canon}"))
                    .hint(format!("Run `seagent login {canon}` or `seagent models key {canon}`.")),
            );
        }
    }
    Ok(v)
}

// ───────────────────────── lint / repair flows ─────────────────────────

pub struct Lint {
    pub findings: Vec<Finding>,
    pub run: usize,
    pub skipped: usize,
}

pub fn lint(c: &Ctx, all: &[Check], only: &[String], skip: &[String]) -> Lint {
    let (sel, mut findings) = select(all, only, skip);
    for ch in &sel {
        match (ch.detect)(c) {
            Ok(f) => findings.extend(f),
            Err(e) => findings.push(finding(ch.id, Severity::Error, format!("health check threw: {e}"))),
        }
    }
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.check.cmp(b.check)).then(a.path.cmp(&b.path)));
    Lint { findings, run: sel.len(), skipped: all.len() - sel.len() }
}

/// `--only`/`--skip` selection shared by `--lint` and `--fix`, plus selection diagnostics
/// (unknown ids, and an id both selected and skipped).
fn select(all: &[Check], only: &[String], skip: &[String]) -> (Vec<Check>, Vec<Finding>) {
    let mut bad = vec![];
    for id in only {
        if !all.iter().any(|x| x.id == id) {
            bad.push(finding("core/doctor/lint-selection", Severity::Error, format!("Unknown health check id selected by --only: {id}.")).path(id.clone()));
        } else if skip.contains(id) {
            bad.push(finding("core/doctor/lint-selection", Severity::Error, format!("Health check {id} cannot be selected by --only and excluded by --skip.")).path(id.clone()));
        }
    }
    let sel = all.iter().copied().filter(|x| (only.is_empty() || only.iter().any(|o| o == x.id)) && !skip.iter().any(|s| s == x.id)).collect();
    (sel, bad)
}

pub fn exit_code(f: &[Finding], min: Severity) -> i32 {
    i32::from(f.iter().any(|x| x.severity >= min))
}

#[derive(Default)]
pub struct RepairRun {
    pub findings: Vec<Finding>,
    pub remaining: Vec<Finding>,
    pub changes: Vec<String>,
    pub warnings: Vec<String>,
}

/// Detect → repair → re-detect per check (only completed validation replaces findings).
pub fn repair_all(c: &mut Ctx, all: &[Check], dry: bool) -> RepairRun {
    let mut out = RepairRun::default();
    for ch in all {
        let f = match (ch.detect)(c) {
            Ok(f) => f,
            Err(e) => {
                out.warnings.push(format!("{} detect failed: {e}", ch.id));
                continue;
            }
        };
        out.findings.extend(f.iter().cloned());
        let (Some(rep), false) = (ch.repair, f.is_empty()) else {
            out.remaining.extend(f);
            continue;
        };
        let mut remaining = f.clone();
        match rep(c, &f, dry) {
            Err(e) => out.warnings.push(format!("{} repair failed: {e}", ch.id)),
            Ok(r) => {
                out.warnings.extend(r.warnings);
                out.changes.extend(r.changes);
                if let Some(why) = r.skipped {
                    out.warnings.push(format!("{} repair skipped: {why}", ch.id));
                } else if !dry {
                    if let Some(cfg) = r.config {
                        c.cfg = cfg;
                    }
                    match (ch.detect)(c) {
                        Ok(v) => {
                            if !v.is_empty() {
                                out.warnings.push(format!("{} repair left {} finding(s)", ch.id, v.len()));
                            }
                            remaining = v;
                        }
                        Err(e) => out.warnings.push(format!("{} validation failed: {e}", ch.id)),
                    }
                }
            }
        }
        out.remaining.extend(remaining);
    }
    out
}

fn print_findings(f: &[Finding]) {
    for x in f {
        let mark = match x.severity {
            Severity::Error => "✗",
            Severity::Warning => "!",
            Severity::Info => "·",
        };
        println!("{mark} [{}] {}{}", x.check, x.message, x.requirement.as_ref().map(|r| format!("\n    requirement: {r}")).unwrap_or_default());
        if let Some(h) = &x.fix_hint {
            println!("    fix: {h}");
        }
    }
}

fn list(a: &Args, k: &str) -> Vec<String> {
    a.vals(k).iter().flat_map(|v| v.split(',').map(|s| s.trim().to_string())).filter(|s| !s.is_empty()).collect()
}

fn build_ctx(a: &Args) -> Result<Ctx, crate::Fail> {
    let paths = Paths::from_env();
    let ws = crate::workspace(a)?;
    let cfg = crate::load_config(a, &ws, &paths)?;
    let specs = match crate::build_agent(a, crate::approver_for(a, false), false) {
        Ok(c) => Ok(c.k.specs()),
        Err(crate::Fail::Msg(m) | crate::Fail::Usage(m)) => Err(m),
    };
    let secret_names = seagent_kernel::vault::Vault::load(&paths.secrets()).map(|v| v.names()).unwrap_or_default();
    let daemon_running = crate::ops::hostos::daemon_reachable(&paths.socket());
    Ok(Ctx { paths, cfg, ws, specs, secret_names, daemon_running })
}

pub fn dispatch(cmd: &str, a: &Args, _raw: &[String]) -> Option<R> {
    if cmd == "doctor" && a.flag("bundle") {
        return Some(crate::ops::debugdump::doctor_bundle(a));
    }
    if cmd != "doctor" || !(a.flag("fix") || a.flag("lint") || a.pos(0) == Some("checks")) {
        return None;
    }
    Some((|| -> R {
        let all = checks();
        if a.pos(0) == Some("checks") {
            for c in &all {
                println!("{:<36} {}{}", c.id, c.description, if c.repair.is_some() { " [repairable]" } else { "" });
            }
            return Ok(0);
        }
        let mut c = build_ctx(a)?;
        if a.flag("fix") {
            // `--fix` honours the same `--only`/`--skip` selection as `--lint` (upstream's repair
            // runner takes a check subset); an unknown id is an error, never a partial repair.
            let (chosen, mut bad) = select(&all, &list(a, "only"), &list(a, "skip"));
            if !bad.is_empty() {
                bad.sort_by(|x, y| x.path.cmp(&y.path));
                if a.flag("json") {
                    println!("{}", json!({"findings": bad.iter().map(Finding::to_json).collect::<Vec<_>>(), "remainingFindings": [], "changes": [], "warnings": []}));
                } else {
                    print_findings(&bad);
                }
                return Ok(1);
            }
            let r = repair_all(&mut c, &chosen, a.flag("dry-run"));
            if a.flag("json") {
                println!("{}", json!({"findings": r.findings.iter().map(Finding::to_json).collect::<Vec<_>>(), "remainingFindings": r.remaining.iter().map(Finding::to_json).collect::<Vec<_>>(), "changes": r.changes, "warnings": r.warnings}));
            } else {
                for ch in &r.changes {
                    println!("✓ {ch}");
                }
                for w in &r.warnings {
                    println!("! {w}");
                }
                print_findings(&r.remaining.iter().filter(|f| f.severity > Severity::Info).cloned().collect::<Vec<_>>());
                if r.changes.is_empty() && r.remaining.iter().all(|f| f.severity == Severity::Info) {
                    println!("✓ nothing to repair");
                }
            }
            return Ok(exit_code(&r.remaining, Severity::Error));
        }
        let min = Severity::parse(a.val("severity-min").unwrap_or("warning")).ok_or("--severity-min: use info, warning or error")?;
        let l = lint(&c, &all, &list(a, "only"), &list(a, "skip"));
        if a.flag("json") {
            println!("{}", json!({"findings": l.findings.iter().map(Finding::to_json).collect::<Vec<_>>(), "checksRun": l.run, "checksSkipped": l.skipped}));
        } else {
            print_findings(&l.findings);
            println!("{} checks run, {} skipped, {} findings", l.run, l.skipped, l.findings.len());
        }
        Ok(exit_code(&l.findings, min))
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn ctx(f: impl FnOnce(&mut Config)) -> Ctx {
        let root = seagent_core::tmp::scratch_path(format!("seagent-doc-{}", seagent_kernel::util::random_hex(6)));
        let paths = Paths { data: root.join("data"), config_dir: root.join("config"), runtime: root.join("run"), ..Default::default() };
        for d in [&paths.data, &paths.config_dir, &paths.runtime, &root.join("ws")] {
            std::fs::create_dir_all(d).unwrap();
        }
        let mut cfg = Config::default();
        f(&mut cfg);
        let spec = |n: &str, s: Value| ToolSpec { name: n.into(), description: "d".into(), input_schema: s, parallel_safe: false, idempotent: false, pinned: false };
        let specs = vec![
            spec("ok_tool", json!({"type": "object", "properties": {"a": {"type": "string", "enum": [{"$dynamicRef": "#literal"}]}}, "required": ["a"]})),
            spec("bad_type", json!({"type": "string"})),
            spec("dyn", json!({"type": "object", "properties": {"x": {"$dynamicRef": "#meta"}}})),
            spec("req", json!({"type": "object", "properties": {}, "required": ["missing"]})),
            spec("bad name!", json!({"type": "object"})),
            spec("ok_tool", json!({"type": "object"})),
        ];
        Ctx { ws: root.join("ws"), paths, cfg, specs: Ok(specs), secret_names: vec!["HAVE".into()], daemon_running: false }
    }

    #[test]
    fn tool_schema_findings() {
        let c = ctx(|_| {});
        let f = detect_tool_schemas(&c).unwrap();
        let msg = |n: &str| f.iter().find(|x| x.path.as_deref() == Some(n)).map(|x| x.requirement.clone().unwrap_or_default());
        assert!(msg("bad_type").unwrap().contains("bad_type.parameters.type must be \"object\""));
        assert!(msg("dyn").unwrap().contains("dyn.parameters.properties.x.$dynamicRef"));
        assert!(msg("req").unwrap().contains("`missing`"));
        assert!(msg("bad name!").unwrap().contains("must match"));
        assert!(f.iter().any(|x| x.message.contains("2 tools are named `ok_tool`")));
        // literal subtrees (enum) are not inspected for keywords
        assert!(f.iter().all(|x| x.path.as_deref() != Some("ok_tool") || x.requirement.is_none()));
        let mut deep = json!({});
        for _ in 0..140 {
            deep = json!({"items": deep});
        }
        assert!(schema_violations("t", &json!({"type": "object", "properties": {"a": deep}})).iter().any(|v| v.contains("deeper than 128")));
        let c2 = Ctx { specs: Err("mcp boom".into()), ..ctx(|_| {}) };
        assert_eq!(detect_tool_schemas(&c2).unwrap()[0].requirement.as_deref(), Some("mcp boom"));
    }

    #[test]
    fn channel_and_native_findings() {
        let c = ctx(|cfg| {
            cfg.channels.insert("tg".into(), "kind = \"telegram\"\ntoken = \"{{secret:MISSING_TG}}\"\ndm_policy = \"open\"".parse().unwrap());
            cfg.channels.insert("weird".into(), "kind = \"nope\"".parse().unwrap());
            cfg.channels.insert("pl".into(), "kind = \"plugin\"\nplugin = \"slack\"".parse().unwrap());
        });
        let f = detect_channels(&c).unwrap();
        assert!(f.iter().any(|x| x.message.contains("unknown kind `nope`")));
        assert!(f.iter().any(|x| x.message.contains("secret `MISSING_TG`")));
        assert!(f.iter().any(|x| x.message.contains("no plugin `slack`")));
        assert!(f.iter().any(|x| x.message.contains("privacy_notice") && x.severity == Severity::Warning));
        let n = detect_native(&c).unwrap();
        #[cfg(not(windows))]
        assert!(n.iter().any(|x| x.message.starts_with("bwrap:")) && n.iter().any(|x| x.message.starts_with("landlock:")));
        // Windows: the AppContainer probe replaces the bwrap / Landlock findings.
        #[cfg(windows)]
        assert!(n.iter().any(|x| x.message.starts_with("appcontainer:")) && !n.iter().any(|x| x.message.starts_with("bwrap:") || x.message.starts_with("landlock:")), "{n:?}");
        assert!(n.iter().all(|x| x.severity != Severity::Error || x.message.starts_with("git")));
    }

    #[test]
    fn workspace_and_removed_state_findings() {
        // workspace: untrusted project config is informational, a missing directory is an error
        let c = ctx(|_| {});
        std::fs::create_dir_all(c.ws.join(".seagent")).unwrap();
        std::fs::write(c.ws.join(".seagent/config.toml"), "model = \"x\"\n").unwrap();
        let f = detect_workspace(&c).unwrap();
        assert!(f.iter().any(|x| x.message.contains("not in trusted_projects") && x.severity == Severity::Info), "{f:?}");
        let gone = Ctx { ws: c.paths.data.join("nope"), ..ctx(|_| {}) };
        let f = detect_workspace(&gone).unwrap();
        assert!(f.iter().any(|x| x.severity == Severity::Error && x.message.contains("is not accessible")), "{f:?}");
        // a trusted_projects entry that still exists is fine
        let live = Ctx { cfg: Config { trusted_projects: vec![c.ws.display().to_string()], ..Default::default() }, ..c };
        assert!(detect_workspace(&live).unwrap().is_empty());

        // removed state: stale socket + dead pid + state of a channel that is no longer configured
        let c = ctx(|cfg| {
            cfg.channels.insert("tg".into(), "kind = \"telegram\"\ntoken = \"{{secret:HAVE}}\"".parse().unwrap());
        });
        std::fs::write(c.paths.socket(), "").unwrap();
        std::fs::write(c.paths.runtime.join("seagentd.pid"), "999999999").unwrap();
        std::fs::create_dir_all(c.paths.data.join("channels")).unwrap();
        std::fs::write(c.paths.data.join("channels/oldbot.offset"), "1").unwrap();
        std::fs::write(c.paths.data.join("channels/tg.offset"), "1").unwrap();
        let f = detect_removed_state(&c).unwrap();
        assert_eq!(f.len(), 3, "{f:?}");
        assert!(f.iter().all(|x| x.check == "core/doctor/removed-state" && x.severity == Severity::Warning));
        assert!(f.iter().any(|x| x.message.contains("stale daemon socket")));
        assert!(f.iter().any(|x| x.message.contains("stale daemon pid file") && x.message.contains("999999999")));
        assert!(f.iter().any(|x| x.message.contains("removed channel `oldbot`")));
        assert!(f.iter().all(|x| x.fix_hint.as_deref().is_some_and(|h| h.contains("--fix"))));
        // a running daemon keeps its socket/pid (only removed-channel state is reported)
        let up = Ctx { daemon_running: true, ..ctx(|cfg| {
            cfg.channels.insert("tg".into(), "kind = \"telegram\"\ntoken = \"{{secret:HAVE}}\"".parse().unwrap());
        }) };
        std::fs::write(up.paths.socket(), "").unwrap();
        std::fs::write(up.paths.runtime.join("seagentd.pid"), "999999999").unwrap();
        std::fs::create_dir_all(up.paths.data.join("channels")).unwrap();
        std::fs::write(up.paths.data.join("channels/oldbot.offset"), "1").unwrap();
        let f = detect_removed_state(&up).unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].message.contains("oldbot"));
        // dry run removes nothing; the real run removes exactly the reported paths
        let mut c = c;
        let fixable: Vec<Check> = checks().into_iter().filter(|x| x.id == "core/doctor/removed-state").collect();
        let r = repair_all(&mut c, &fixable, true);
        assert_eq!(r.changes.len(), 3);
        assert!(c.paths.socket().exists() && c.paths.data.join("channels/oldbot.offset").exists());
        let r = repair_all(&mut c, &fixable, false);
        assert_eq!(r.changes.len(), 3, "{:?}", r.changes);
        assert!(!c.paths.socket().exists() && !c.paths.runtime.join("seagentd.pid").exists());
        assert!(!c.paths.data.join("channels/oldbot.offset").exists());
        assert!(c.paths.data.join("channels/tg.offset").exists());
        assert!(r.remaining.is_empty() && r.warnings.is_empty(), "{:?} {:?}", r.remaining, r.warnings);
    }

    #[test]
    fn fix_and_lint_share_the_selection() {
        let all = checks();
        let (sel, bad) = select(&all, &["core/doctor/removed-state".into()], &[]);
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].id, "core/doctor/removed-state");
        assert!(bad.is_empty());
        // unknown id: no repair is attempted and the id is reported as an error
        let (sel, bad) = select(&all, &["nope".into()], &[]);
        assert!(sel.is_empty());
        assert_eq!(bad[0].severity, Severity::Error);
        assert!(bad[0].message.contains("Unknown health check id selected by --only: nope"));
        // selected and skipped at once is a conflict, not a silent no-op
        let (sel, bad) = select(&all, &["core/doctor/workspace".into()], &["core/doctor/workspace".into()]);
        assert!(sel.is_empty());
        assert!(bad.iter().any(|x| x.message.contains("cannot be selected by --only and excluded by --skip")));
        // skip alone keeps everything else
        let (sel, bad) = select(&all, &[], &["core/doctor/native-status".into()]);
        assert_eq!(sel.len(), all.len() - 1);
        assert!(bad.is_empty());
        assert!(!sel.iter().any(|x| x.id == "core/doctor/native-status"));
    }

    #[test]
    fn lint_selection_and_exit_codes() {
        let c = ctx(|_| {});
        let all = checks();
        let l = lint(&c, &all, &["core/doctor/runtime-tool-schemas".into(), "nope".into()], &[]);
        assert_eq!((l.run, l.skipped), (1, all.len() - 1));
        assert!(l.findings.iter().any(|f| f.message.contains("Unknown health check id selected by --only: nope")));
        assert_eq!(l.findings[0].severity, Severity::Error);
        assert_eq!(exit_code(&l.findings, Severity::Error), 1);
        let l = lint(&c, &all, &["core/doctor/secret-permissions".into()], &[]);
        assert_eq!(exit_code(&l.findings, Severity::Warning), 0);
    }

    #[cfg(unix)]
    #[test]
    fn repair_flow_fixes_and_validates() {
        let stale_dir = seagent_core::tmp::scratch_path(format!("seagent-doc-gone-{}", seagent_kernel::util::random_hex(6)));
        let mut c = ctx(|cfg| {
            cfg.trusted_projects = vec![stale_dir.display().to_string()];
            cfg.channels.insert("tg".into(), "kind = \"telegram\"\ntoken = \"{{secret:HAVE}}\"".parse().unwrap());
        });
        std::fs::write(c.paths.user_config(), format!("# mine\ntrusted_projects = [{:?}]\n", stale_dir.display().to_string())).unwrap();
        std::fs::write(c.paths.secrets(), "").unwrap();
        std::fs::set_permissions(c.paths.secrets(), std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(c.paths.socket(), "").unwrap();
        std::fs::write(c.paths.runtime.join("seagentd.pid"), "999999999").unwrap();
        std::fs::create_dir_all(c.paths.data.join("channels")).unwrap();
        std::fs::write(c.paths.data.join("channels/oldbot.offset"), "1").unwrap();
        std::fs::write(c.paths.data.join("channels/tg.offset"), "1").unwrap();
        let fixable: Vec<Check> = checks().into_iter().filter(|x| x.repair.is_some()).collect();
        // dry run changes nothing
        let r = repair_all(&mut c, &fixable, true);
        assert!(r.changes.iter().any(|x| x.starts_with("would remove") && x.contains("oldbot")));
        assert!(c.paths.socket().exists());
        let r = repair_all(&mut c, &fixable, false);
        assert!(r.changes.iter().any(|x| x.contains("chmod") && x.contains("644 → 600")), "{:?}", r.changes);
        assert_eq!(std::fs::metadata(c.paths.secrets()).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!c.paths.socket().exists() && !c.paths.runtime.join("seagentd.pid").exists());
        assert!(!c.paths.data.join("channels/oldbot.offset").exists() && c.paths.data.join("channels/tg.offset").exists());
        let cfgtext = std::fs::read_to_string(c.paths.user_config()).unwrap();
        assert!(!cfgtext.contains(&stale_dir.display().to_string()), "{cfgtext}");
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert!(r.remaining.iter().all(|f| f.severity == Severity::Info), "{:?}", r.remaining);
    }

    #[test]
    fn gateway_auth_reports_missing_and_unresolved_tokens() {
        // Disabled app server: nothing to say (seagent ships with it off).
        assert!(detect_gateway_auth(&ctx(|_| {})).unwrap().is_empty());
        // Enabled, blank token: an error with the fix that generates one.
        let c = ctx(|cfg| { cfg.app.insert("enabled".into(), toml::Value::Boolean(true)); });
        let f = detect_gateway_auth(&c).unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!((f[0].severity, f[0].path.as_deref()), (Severity::Error, Some("app.token")));
        assert!(f[0].message.contains("token is blank") && f[0].fix_hint.as_deref().unwrap().contains("seagent doctor --fix"), "{f:?}");
        // A reference to a secret that is not set is the failure mode the daemon refuses to start on.
        let c = ctx(|cfg| {
            cfg.app.insert("enabled".into(), toml::Value::Boolean(true));
            cfg.app.insert("token".into(), toml::Value::String("{{secret:NOPE}}".into()));
        });
        assert!(detect_gateway_auth(&c).unwrap()[0].message.contains("unresolved secret reference"));
        let c = Ctx { cfg: { let mut g = c.cfg.clone(); g.app.insert("token".into(), toml::Value::String("{{secret:HAVE}}".into())); g }, ..c };
        assert!(detect_gateway_auth(&c).unwrap().is_empty(), "a resolvable reference is fine");
        // A literal token on all interfaces is a warning; on loopback it is fine.
        let c = ctx(|cfg| {
            cfg.app.insert("enabled".into(), toml::Value::Boolean(true));
            cfg.app.insert("token".into(), toml::Value::String("literal-token".into()));
            cfg.app.insert("listen".into(), toml::Value::String("0.0.0.0:7777".into()));
        });
        let f = detect_gateway_auth(&c).unwrap();
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].message.contains("0.0.0.0:7777") && f[0].path.as_deref() == Some("app.listen"), "{f:?}");
    }

    #[test]
    fn gateway_auth_repair_generates_a_vaulted_token() {
        let c = ctx(|cfg| {
            cfg.app.insert("enabled".into(), toml::Value::Boolean(true));
            cfg.app.insert("token".into(), toml::Value::String(String::new()));
        });
        std::fs::write(c.paths.user_config(), "[app]\nenabled = true\ntoken = \"\"\n\n[model]\ndefault = \"anthropic/claude-sonnet-4-5\"\n").unwrap();
        let f = detect_gateway_auth(&c).unwrap();
        let dry = repair_gateway_auth(&c, &f, true).unwrap();
        assert!(dry.changes[0].contains("would generate") && !c.paths.secrets().exists(), "{:?}", dry.changes);
        let r = repair_gateway_auth(&c, &f, false).unwrap();
        assert!(r.changes[0].contains("APP_TOKEN"), "{:?}", r.changes);
        let text = std::fs::read_to_string(c.paths.user_config()).unwrap();
        assert!(text.contains("{{secret:APP_TOKEN}}"), "{text}");
        let names = seagent_kernel::vault::Vault::load(&c.paths.secrets()).unwrap().names();
        assert!(names.contains(&"APP_TOKEN".to_string()), "{names:?}");
        // The repaired config passes the check again (re-read from disk).
        let reloaded: Config = toml::from_str(&text).unwrap();
        assert_eq!(reloaded.app.get("token").and_then(|v| v.as_str()), Some("{{secret:APP_TOKEN}}"));
        let c2 = Ctx { cfg: reloaded, secret_names: names, ..ctx(|_| {}) };
        assert!(detect_gateway_auth(&c2).unwrap().is_empty());
        // A reference already in the config keeps its own name.
        let c = ctx(|cfg| {
            cfg.app.insert("enabled".into(), toml::Value::Boolean(true));
            cfg.app.insert("token".into(), toml::Value::String("{{secret:WEB_TOKEN}}".into()));
        });
        std::fs::write(c.paths.user_config(), "[app]\nenabled = true\ntoken = \"{{secret:WEB_TOKEN}}\"\n").unwrap();
        let r = repair_gateway_auth(&c, &[], false).unwrap();
        assert!(r.changes[0].contains("WEB_TOKEN"), "{:?}", r.changes);
        assert!(seagent_kernel::vault::Vault::load(&c.paths.secrets()).unwrap().names().contains(&"WEB_TOKEN".to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn gateway_services_and_exec_credentials() {
        let _g = crate::testkit::env_lock();
        let root = seagent_core::tmp::scratch_path(format!("seagent-doc-svc-{}", seagent_kernel::util::random_hex(6)));
        std::env::set_var("XDG_CONFIG_HOME", root.join("xdg"));
        let c = ctx(|cfg| {
            cfg.exec.insert("sudo_password_secret".into(), toml::Value::String("SUDO_PW".into()));
            cfg.exec.insert("credential_files".into(), toml::Value::Array(vec![toml::Value::String("/nope/id_rsa".into())]));
        });
        // No unit installed: running seagentd by hand is not a defect.
        assert!(detect_gateway_services(&c).unwrap().is_empty());
        // A unit for another workspace is left alone …
        let dir = crate::ops::service::user_unit_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(crate::ops::service::unit_name());
        let exe = std::env::current_exe().unwrap();
        std::fs::write(&path, crate::ops::service::unit(&exe, Path::new("/other/ws"), None)).unwrap();
        assert!(detect_gateway_services(&c).unwrap().is_empty());
        // … and ours is audited: a hand-edited KillMode/hardening shows up, and --fix rewrites it.
        let ours = crate::ops::service::unit(&exe, &c.ws, None);
        let bad = ours.replace("KillMode=mixed", "KillMode=process").replace("NoNewPrivileges=yes", "NoNewPrivileges=no");
        std::fs::write(&path, &bad).unwrap();
        let f = detect_gateway_services(&c).unwrap();
        assert!(f.iter().any(|x| x.message.contains("KillMode=mixed")), "{f:?}");
        assert!(f.iter().all(|x| x.severity == Severity::Warning && x.requirement.as_deref() == Some("reinstall")));
        let r = repair_gateway_services(&c, &f, false).unwrap();
        assert!(r.changes[0].contains("rewrote") && r.changes[0].contains("daemon-reload"), "{:?}", r.changes);
        assert!(detect_gateway_services(&c).unwrap().is_empty(), "a rewritten unit passes");
        std::env::remove_var("XDG_CONFIG_HOME");

        // exec credentials: an unset sudo secret and a missing credential file are reported.
        let f = detect_exec_credential(&c).unwrap();
        assert!(f.iter().any(|x| x.message.contains("SUDO_PW") && x.path.as_deref() == Some("exec.sudo_password_secret")), "{f:?}");
        assert!(f.iter().any(|x| x.message.contains("/nope/id_rsa")), "{f:?}");
        let ok = Ctx { secret_names: vec!["SUDO_PW".into()], cfg: { let mut g = c.cfg.clone(); g.exec.remove("credential_files"); g }, ..ctx(|_| {}) };
        assert!(detect_exec_credential(&ok).unwrap().is_empty());
        // an ssh key readable by others is refused by ssh, so doctor says so
        let key = root.join("id_ed25519");
        std::fs::write(&key, "k").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let c2 = Ctx {
            cfg: {
                let mut g = Config::default();
                let mut ssh: toml::Table = format!("identity_file = {:?}", key.display().to_string()).parse().unwrap();
                g.exec.insert("ssh".into(), toml::Value::Table(std::mem::take(&mut ssh)));
                g
            },
            ..ctx(|_| {})
        };
        assert!(detect_exec_credential(&c2).unwrap().iter().any(|x| x.message.contains("readable by others")));
    }

    #[test]
    fn model_reference_findings() {
        let c = ctx(|cfg| {
            cfg.model.default = "nope/gpt".into();
            cfg.model.fallback = vec!["anthropic/claude-sonnet-4-5".into()];
            cfg.model.aux = String::new();
        });
        let f = detect_model_reference(&c).unwrap();
        assert!(f.iter().any(|x| x.severity == Severity::Warning && x.message.contains("unknown provider `nope`") && x.path.as_deref() == Some("model.default")), "{f:?}");
        // A provider with a declared model list: an id outside it is informational only.
        let c = ctx(|cfg| {
            cfg.model.default = "custom/other-model".into();
            cfg.model.aux = String::new();
            cfg.providers.insert("custom".into(), "format = \"openai_chat\"\nbase_url = \"http://127.0.0.1:1/v1\"\nmodels = [\"only-model\"]\napi_key = \"k\"\n".parse().unwrap());
        });
        let f = detect_model_reference(&c).unwrap();
        assert!(f.iter().any(|x| x.severity == Severity::Info && x.message.contains("other-model") && x.path.as_deref() == Some("model.default")), "{f:?}");
        assert!(!f.iter().any(|x| x.message.contains("no usable credentials")), "api_key in the config counts: {f:?}");
        // A provider this install knows but with no usable credential: the first turn would fail.
        let c = ctx(|cfg| {
            cfg.model.default = "openai-codex/gpt-5-codex".into();
            cfg.model.aux = String::new();
        });
        let f = detect_model_reference(&c).unwrap();
        assert!(f.iter().any(|x| x.message.contains("no usable credentials") && x.severity == Severity::Warning), "{f:?}");
        // An empty default is caught before any turn.
        let c = ctx(|cfg| cfg.model.default = String::new());
        assert!(detect_model_reference(&c).unwrap().iter().any(|x| x.message.contains("model.default is empty")));
        // A reference without a provider slash is an error.
        let c = ctx(|cfg| cfg.model.default = "gpt-4o".into());
        assert!(detect_model_reference(&c).unwrap().iter().any(|x| x.severity == Severity::Error && x.message.contains("not a provider/model")), "aliases resolve, plain ids do not");
    }
}
