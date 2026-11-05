//! `ark sandbox list|recreate|explain` (OpenClaw `src/cli/sandbox-cli.ts`, `commands/sandbox*.ts`),
//! plus the exec/code-mode host wiring called from `wire.rs`. (`ark worktree` / `/worktree` live
//! in `ops/worktree.rs`.)
//!
//! Sandboxes: per-scope state lives under `exec.sandbox.workspace_root` (default
//! `<ark data>/sandboxes/<scope key>`), and container backends label what they start with
//! `ark.sandbox=1` / `ark.scope=<scope key>`. `list` shows both, `recreate` removes them so the
//! next call rebuilds them from the current config, `explain` prints the effective policy for a
//! session. Containers of a running daemon are torn down by the daemon on its next use.

use ark_kernel::config::Paths;
use ark_tools::exec::sandbox::{ToolPolicy, DEFAULT_ALLOW, DEFAULT_DENY};
use ark_tools::exec::{ExecConfig, ExecEnv};
use serde_json::{json, Value};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const LABEL: &str = "ark.sandbox";
pub const SCOPE_LABEL: &str = "ark.scope";

/// `{{secret:NAME}}` resolver handed to a plugin exec backend (vault first, then the environment).
type SecretFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

struct Opts {
    pos: Vec<String>,
    flags: Vec<String>,
    vals: Vec<(String, String)>,
}

impl Opts {
    fn parse(argv: &[String], with_value: &[&str]) -> Opts {
        let mut o = Opts { pos: vec![], flags: vec![], vals: vec![] };
        let mut i = 0;
        while i < argv.len() {
            let a = &argv[i];
            if let Some(k) = a.strip_prefix("--").or_else(|| a.strip_prefix('-').filter(|k| k.len() == 1)) {
                if let Some((k, v)) = k.split_once('=') {
                    o.vals.push((k.into(), v.into()));
                } else if with_value.contains(&k) {
                    o.vals.push((k.into(), argv.get(i + 1).cloned().unwrap_or_default()));
                    i += 1;
                } else {
                    o.flags.push(k.into());
                }
            } else {
                o.pos.push(a.clone());
            }
            i += 1;
        }
        o
    }
    fn flag(&self, k: &str) -> bool {
        self.flags.iter().any(|f| f == k)
    }
    fn val(&self, k: &str) -> Option<&str> {
        self.vals.iter().rev().find(|(a, _)| a == k).map(|(_, v)| v.as_str())
    }
}

/// `[exec]` from the user's config file (project files may not change sandboxing).
pub fn exec_config(paths: &Paths) -> Result<ExecConfig, String> {
    let text = std::fs::read_to_string(paths.user_config()).unwrap_or_default();
    let t: toml::Table = toml::from_str(&text).map_err(|e| format!("{}: {e}", paths.user_config().display()))?;
    match t.get("exec") {
        Some(v) => ExecConfig::parse(&serde_json::to_value(v).map_err(|e| e.to_string())?),
        // No `[exec]` table: every name is unstated, so `auto` decides (A1 — the microVM when
        // this machine can boot one, else the strongest fallback with a warning).
        None => ExecConfig::parse(&Value::Null),
    }
}

/// `[security]` as the explain JSON needs it (broker, capability enforcement, egress policy).
/// Read from the same file `[exec]` came from; an unreadable table means "the defaults", which
/// is what the daemon would use too.
fn security_of(paths: &Paths) -> ark_security::SecurityConfig {
    let text = std::fs::read_to_string(paths.user_config()).unwrap_or_default();
    toml::from_str::<toml::Table>(&text)
        .ok()
        .and_then(|t| t.get("security").cloned())
        .and_then(|v| serde_json::to_value(v).ok())
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn age(secs: u64) -> String {
    match secs {
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86400 => format!("{}h", s / 3600),
        s => format!("{}d", s / 86400),
    }
}

fn dir_size(p: &Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(p) else { return 0 };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map(|m| m.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

fn scope_kind(key: &str) -> &'static str {
    if key == "shared" {
        "shared"
    } else if key.starts_with("ws-") {
        "agent"
    } else {
        "session"
    }
}

/// Scope directories under the sandbox root.
pub fn scopes(cfg: &ExecConfig, data: &Path) -> Vec<Value> {
    let root = cfg.sandbox.root(data);
    let mut v: Vec<Value> = std::fs::read_dir(&root)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| {
            let md = e.metadata().ok();
            let t = |f: fn(&std::fs::Metadata) -> std::io::Result<SystemTime>| md.as_ref().and_then(|m| f(m).ok()).and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0);
            let key = e.file_name().to_string_lossy().to_string();
            json!({"scope": key, "kind": scope_kind(&key), "path": e.path(), "bytes": dir_size(&e.path()), "created": t(|m| m.created()), "used": t(|m| m.modified())})
        })
        .collect();
    v.sort_by(|a, b| a["scope"].as_str().cmp(&b["scope"].as_str()));
    v
}

/// Labelled containers of `bin` (docker / podman), if that runtime is installed.
fn containers(bin: &str) -> Vec<Value> {
    let Ok(out) = std::process::Command::new(bin).args(["ps", "-a", "--filter", &format!("label={LABEL}"), "--format", "{{json .}}"]).output() else { return vec![] };
    if !out.status.success() {
        return vec![];
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .map(|c| {
            let labels = c.get("Labels").and_then(Value::as_str).unwrap_or("");
            let scope = labels.split(',').find_map(|kv| kv.strip_prefix(&format!("{SCOPE_LABEL}="))).unwrap_or("").to_string();
            json!({"runtime": bin, "name": c.get("Names").cloned().unwrap_or(Value::Null), "image": c.get("Image").cloned().unwrap_or(Value::Null), "status": c.get("Status").or_else(|| c.get("State")).cloned().unwrap_or(Value::Null), "scope": scope})
        })
        .collect()
}

fn remove_containers(bin: &str, scope: Option<&str>) -> Vec<String> {
    let filter = match scope {
        Some(s) => format!("label={SCOPE_LABEL}={s}"),
        None => format!("label={LABEL}"),
    };
    let Ok(out) = std::process::Command::new(bin).args(["ps", "-aq", "--filter", &filter]).output() else { return vec![] };
    let ids: Vec<String> = String::from_utf8_lossy(&out.stdout).split_whitespace().map(String::from).collect();
    if !ids.is_empty() {
        let _ = std::process::Command::new(bin).arg("rm").arg("-f").args(&ids).output();
    }
    ids
}

fn sandbox_list(cfg: &ExecConfig, paths: &Paths, o: &Opts) -> Result<String, String> {
    let s = scopes(cfg, &paths.data);
    let mut c = Vec::new();
    for bin in ["docker", "podman"] {
        if ark_tools::exec::local::which(bin).is_some() {
            c.extend(containers(bin));
        }
    }
    if o.flag("browser") {
        c.retain(|x| x["image"].as_str().is_some_and(|i| i.contains("browser") || i.contains("chrom")));
    }
    if o.flag("json") {
        return Ok(serde_json::to_string_pretty(&json!({"root": cfg.sandbox.root(&paths.data), "scopes": s, "containers": c})).unwrap_or_default());
    }
    let mut out = vec![format!("sandbox root: {}  (mode {}, backend {}, scope {})", cfg.sandbox.root(&paths.data).display(), cfg.sandbox.mode, cfg.sandbox.backend, cfg.sandbox.scope)];
    if s.is_empty() && c.is_empty() {
        out.push("no sandboxes".into());
    }
    if !s.is_empty() {
        out.push(format!("{:32} {:8} {:>9} {:>6} {:>6}", "SCOPE", "KIND", "SIZE", "AGE", "IDLE"));
        let n = now();
        for x in &s {
            out.push(format!("{:32} {:8} {:>8}K {:>6} {:>6}", x["scope"].as_str().unwrap_or(""), x["kind"].as_str().unwrap_or(""), x["bytes"].as_u64().unwrap_or(0) / 1024, age(n.saturating_sub(x["created"].as_u64().unwrap_or(n))), age(n.saturating_sub(x["used"].as_u64().unwrap_or(n)))));
        }
    }
    for x in &c {
        out.push(format!("{} {}  {}  {}  scope={}", x["runtime"].as_str().unwrap_or(""), x["name"].as_str().unwrap_or("?"), x["image"].as_str().unwrap_or("?"), x["status"].as_str().unwrap_or("?"), x["scope"].as_str().unwrap_or("")));
    }
    Ok(out.join("\n"))
}

/// Scope keys `recreate` targets.
fn targets(cfg: &ExecConfig, paths: &Paths, o: &Opts) -> Result<Option<Vec<String>>, String> {
    if o.flag("all") {
        return Ok(None);
    }
    if let Some(s) = o.val("session") {
        return Ok(Some(vec![format!("s-{}", ark_tools::exec::sanitize(s))]));
    }
    if let Some(a) = o.val("agent") {
        // An agent's sandbox is keyed by its workspace (scope = agent).
        let ws = std::fs::canonicalize(a).unwrap_or_else(|_| PathBuf::from(a));
        let mut c = cfg.clone();
        c.sandbox.scope = "agent".into();
        return Ok(Some(vec![ExecEnv::new(c).scope_key("", &ws)]));
    }
    let _ = paths;
    Err("pick what to recreate: --all, --session <id> or --agent <workspace>".into())
}

fn sandbox_recreate(cfg: &ExecConfig, paths: &Paths, o: &Opts, confirm: &dyn Fn(&str) -> bool) -> Result<String, String> {
    let t = targets(cfg, paths, o)?;
    let root = cfg.sandbox.root(&paths.data);
    let dirs: Vec<PathBuf> = scopes(cfg, &paths.data).iter().filter(|s| t.as_ref().is_none_or(|t| t.iter().any(|k| s["scope"] == k.as_str()))).filter_map(|s| s["path"].as_str().map(PathBuf::from)).collect();
    let what = match &t {
        None => "ALL sandboxes".to_string(),
        Some(k) => format!("sandbox {}", k.join(", ")),
    };
    if !o.flag("force") && !confirm(&format!("remove {what} ({} dir(s) under {})? They are rebuilt on next use.", dirs.len(), root.display())) {
        return Err("cancelled (pass --force to skip the confirmation)".into());
    }
    let mut removed = Vec::new();
    if !o.flag("browser") {
        for d in &dirs {
            if d.starts_with(&root) && std::fs::remove_dir_all(d).is_ok() {
                removed.push(d.display().to_string());
            }
        }
    }
    for bin in ["docker", "podman"] {
        if ark_tools::exec::local::which(bin).is_some() {
            match &t {
                None => removed.extend(remove_containers(bin, None).into_iter().map(|i| format!("{bin} container {i}"))),
                Some(keys) => {
                    for k in keys {
                        removed.extend(remove_containers(bin, Some(k)).into_iter().map(|i| format!("{bin} container {i}")));
                    }
                }
            }
        }
    }
    Ok(if removed.is_empty() { format!("nothing to remove for {what}") } else { format!("removed {} item(s); they are recreated with the current config on next use:\n{}", removed.len(), removed.join("\n")) })
}

/// The effective sandbox / tool policy for a session.
pub fn explain(cfg: &ExecConfig, paths: &Paths, session: &str, workspace: &Path, tools: &[String]) -> Value {
    let env = ExecEnv::new(cfg.clone());
    let sb = &cfg.sandbox;
    let sandboxed = env.sandboxed(session);
    let policy: &ToolPolicy = &sb.tools;
    let (mut allowed, mut denied): (Vec<String>, Vec<String>) = (vec![], vec![]);
    for t in tools {
        if policy.allows(t) {
            allowed.push(t.clone());
        } else {
            denied.push(t.clone());
        }
    }
    // A1: what the session's commands *will* run in — the same resolution the executor uses,
    // `auto` (microVM first) included, with the warning that goes with a weaker level.
    let plan = env.plan(session, workspace, &paths.data);
    // A3/A5: the VM's only way out, and what it will let through.
    let sec = security_of(paths);
    let broker_socket = sec.broker.socket_path(&paths.runtime);
    let broker_needed = plan.uses_microvm() || sec.broker.enabled;
    let declaring: Vec<String> = ark_security::capability::all().iter().filter(|m| !m.net.is_empty()).map(|m| m.name.clone()).collect();
    // B6: one line per backend name. `auto` repeats the name it resolved to; printing the same
    // sentence twice only makes the list look broken.
    let described = ark_tools::exec::unify::describe_names(cfg, &ark_tools::exec::BackendCtx {
        workspace: workspace.to_path_buf(),
        scope_key: env.scope_key(session, workspace),
        secrets: Arc::new(|s: &str| s.to_string()),
        home: paths.data.clone(),
        sandboxed,
    });
    let mut seen: Vec<&str> = Vec::new();
    for line in described.lines().filter(|l| !l.trim().is_empty()) {
        if !seen.contains(&line) {
            seen.push(line);
        }
    }
    let backends = seen.join("\n");
    json!({
        "session": session,
        "mode": sb.mode,
        "sandboxed": sandboxed,
        "sandboxed_note": if sb.mode == "non-main" { "non-main: sandboxed unless this is the operator's main session (the daemon decides per session)" } else { "" },
        "host_backend": cfg.backend,
        "sandbox_backend": sb.backend,
        "runs_in": plan.backend.clone(),
        "plan": {
            "backend": plan.backend, "level": plan.level.label(), "rank": plan.level.rank(),
            "provider": plan.provider, "origin": plan.origin.label(), "warning": plan.warning, "reason": plan.reason,
        },
        "scope": sb.scope,
        "scope_key": env.scope_key(session, workspace),
        "workspace_access": sb.workspace_access,
        "workspace": if sandboxed && sb.workspace_access == "none" { sb.scratch_workspace(&paths.data, &env.scope_key(session, workspace)) } else { workspace.to_path_buf() },
        "network": sb.network,
        "elevated": sb.elevated,
        "binds": sb.binds,
        "isolation": isolation_report(cfg, &plan, &env.plan_for(true, workspace, &paths.data)),
        // A1/A3: the guest has no network and no key; this socket is the only way out.
        "broker": {
            "needed": broker_needed,
            "socket": broker_socket.display().to_string(),
            "exists": broker_socket.exists(),
            "enforce_capabilities": sec.broker.enforce_capabilities,
            "exec_allow": sec.broker.exec_allow,
            "only_way_out": if plan.uses_microvm() { "the VM has no network interface: egress and privileged commands go through this socket only" } else { "no microVM in use, so this socket is not the boundary" },
        },
        // A5: which components declare what, and whether the broker/proxy enforce it.
        "capabilities": {
            "enforced": sec.broker.enforce_capabilities && plan.uses_microvm(),
            "declared": ark_security::capability::all().len(),
            "network": declaring,
            "tools": tools.iter().filter_map(|t| ark_security::capability::builtin(t).map(|m| m.summary())).take(40).collect::<Vec<_>>(),
        },
        // B6: every backend name behind one interface.
        "backends": backends,
        "prune": {"idle_hours": sb.prune_idle_hours, "max_age_days": sb.prune_max_age_days},
        "tools": {"allow": policy.allow, "deny": policy.deny, "allowed": allowed, "denied": if sandboxed { denied } else { vec![] }, "default_deny": DEFAULT_DENY},
        "env": {"scrub": cfg.scrub_env, "passthrough": cfg.env_passthrough},
    })
}

fn render_explain(v: &Value) -> String {
    let s = |k: &str| v[k].as_str().map(String::from).unwrap_or_else(|| v[k].to_string());
    let mut out = vec![
        format!("session {}: {}", s("session"), if v["sandboxed"].as_bool() == Some(true) { format!("SANDBOXED in {}", s("runs_in")) } else { format!("runs in {} (host backend)", s("runs_in")) }),
        format!("mode {} · scope {} (key {}) · workspace access {} · network {} · elevated {}", s("mode"), s("scope"), s("scope_key"), s("workspace_access"), s("network"), s("elevated")),
        format!("workspace: {}", s("workspace")),
    ];
    if !s("sandboxed_note").is_empty() {
        out.push(s("sandboxed_note"));
    }
    if !v["plan"].is_null() {
        let p = &v["plan"];
        out.push(format!("execution plan: {} ({}) via {} — {}", p["backend"].as_str().unwrap_or("?"), p["level"].as_str().unwrap_or("?"), p["provider"].as_str().unwrap_or("in-process"), p["origin"].as_str().unwrap_or("?")));
        if let Some(w) = p["warning"].as_str() {
            out.push(format!("WARNING: {w}"));
        }
    }
    if !v["broker"].is_null() {
        let b = &v["broker"];
        out.push(format!("broker: {} ({}; capabilities enforced: {})", b["socket"].as_str().unwrap_or(""), b["only_way_out"].as_str().unwrap_or(""), b["enforce_capabilities"].as_bool().unwrap_or(false)));
        if b["needed"].as_bool() == Some(true) && b["exists"].as_bool() != Some(true) {
            out.push("  note: this process has not started the broker socket yet (it starts with the daemon; `ark security broker` runs it standalone)".into());
        }
    }
    if !v["capabilities"].is_null() {
        let c = &v["capabilities"];
        out.push(format!("capabilities: enforced={} · {} declarations · network declared by {}", c["enforced"].as_bool().unwrap_or(false), c["declared"].as_u64().unwrap_or(0), c["network"].as_array().map(|a| a.len()).unwrap_or(0)));
    }
    if !v["isolation"].is_null() {
        let i = &v["isolation"];
        let f = |k: &str| i[k].as_str().or_else(|| i[k].as_u64().map(|_| "")).unwrap_or("").to_string();
        out.push(format!(
            "isolation: {} ({}, rank {}) for the host backend / {} ({}, rank {}) for the sandbox backend",
            f("host_backend_level"), i["host_backend"].as_str().unwrap_or("?"), i["host_backend_rank"], f("sandbox_backend_level"), i["sandbox_backend"].as_str().unwrap_or("?"), i["sandbox_backend_rank"]
        ));
        if let Some(w) = i["warning"].as_str() {
            out.push(format!("warning: {w}"));
        }
        if let Some(r) = i["host_kernel"]["report"].as_array() {
            out.push(format!("host: {}", r.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" · ")));
        }
        if !i["namespace_fallback"].is_null() {
            let nf = &i["namespace_fallback"];
            out.push(format!("without a microVM this host isolates with: {} ({})", nf["backend"].as_str().unwrap_or("?"), nf["level"].as_str().unwrap_or("?")));
            for d in nf["degraded"].as_array().into_iter().flatten().filter_map(|x| x.as_str()) {
                out.push(format!("  degraded: {d}"));
            }
        }
        if !i["vm"].is_null() {
            out.push(format!("microVM: provider {} ({}), {} running", i["vm"]["provider"].as_str().unwrap_or(""), i["vm"]["level"].as_str().unwrap_or(""), i["vm"]["running"]));
            if let Some(w) = i["vm"]["warning"].as_str() {
                out.push(format!("warning: {w}"));
            }
        }
    }
    if v["binds"].as_array().is_some_and(|b| !b.is_empty()) {
        out.push(format!("binds: {}", v["binds"]));
    }
    if let Some(b) = v["backends"].as_str() {
        out.push(format!("backends (one interface, B6):\n{b}"));
    }
    let list = |k: &str| v["tools"][k].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    if v["sandboxed"].as_bool() == Some(true) {
        out.push(format!("tools allowed in the sandbox: {}", list("allowed")));
        out.push(format!("tools denied in the sandbox: {}", list("denied")));
    } else {
        out.push("tool policy applies only to sandboxed sessions".into());
    }
    out.join("\n")
}

/// Where commands actually run under the *host* (or sandbox) backend, and how
/// much that protects (B1/B6): one table for every backend name.
fn isolation_report(cfg: &ExecConfig, plan: &ark_vm::policy::Plan, sandbox_plan: &ark_vm::policy::Plan) -> Value {
    let host = plan.level;
    let sandbox = sandbox_plan.level;
    let mut v = json!({
        "host_backend": plan.backend,
        "sandbox_backend": sandbox_plan.backend,
        "host_backend_level": host.label(),
        "sandbox_backend_level": sandbox.label(),
        "host_backend_rank": host.rank(),
        "sandbox_backend_rank": sandbox.rank(),
        "warning": host.warning().or_else(|| sandbox.warning()),
    });
    // ent-023/024/026: what this kernel gives a namespace sandbox, and the steps down the
    // fallback took on this machine (no Landlock, no user namespaces, cgroup v1 …).
    let caps = ark_vm::isolation::Capabilities::detect(None, None);
    let (fallback, degraded) = ark_vm::policy::namespace_choice(&caps);
    v["host_kernel"] = json!({"report": caps.host.report(), "landlock_abi": caps.host.landlock_abi, "userns": caps.host.userns, "seccomp": caps.host.seccomp, "cgroup": caps.host.cgroup});
    v["namespace_fallback"] = json!({"backend": fallback, "level": ark_vm::isolation::isolation_of_backend(fallback).label(), "degraded": degraded});
    if cfg.backend == "vm" || cfg.sandbox.backend == "vm" {
        let mgr = ark_tools::exec::vm::manager_for(&cfg.vm, Path::new(""));
        let (kind, warning) = mgr.selection();
        v["vm"] = json!({
            "provider": kind.name(),
            "level": kind.isolation().label(),
            "warning": warning,
            "capabilities": mgr.capabilities().report(),
            "running": mgr.status().len(),
        });
    }
    v
}

/// `ark sandbox vm …`: the microVM itself — status, image, undo points.
fn sandbox_vm(cfg: &ExecConfig, paths: &Paths, o: &Opts) -> Result<String, String> {
    let session = o.val("session").unwrap_or("main");
    let workspace = o.val("workspace").or(o.val("w")).map(PathBuf::from).unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
    let mgr = ark_tools::exec::vm::manager_for(&cfg.vm, &paths.data);
    let tier = ark_vm::trust::TrustTier::Owner;
    let json_out = o.flag("json");
    match o.pos.get(1).map(String::as_str).unwrap_or("status") {
        "status" | "ls" => {
            let (kind, warning) = mgr.selection();
            let caps = mgr.capabilities();
            let status = mgr.status();
            if json_out {
                return Ok(serde_json::to_string_pretty(&json!({
                    "provider": kind.name(),
                    "isolation": kind.isolation().label(),
                    "warning": warning,
                    "capabilities": caps.report(),
                    "vms": status.iter().map(|s| json!({
                        "key": s.key, "tier": s.tier, "provider": s.provider, "isolation": s.isolation.label(),
                        "pid": s.pid, "running": s.running, "commands": s.commands, "idle_secs": s.idle_secs,
                        "rss_kb": s.rss_kb, "snapshots": s.snapshots,
                    })).collect::<Vec<_>>(),
                })).unwrap());
            }
            let mut out = vec![format!("provider: {} ({} isolation)", kind.name(), kind.isolation().label())];
            if let Some(w) = &warning {
                out.push(format!("warning: {w}"));
            }
            for l in caps.report() {
                out.push(format!("  {l}"));
            }
            if status.is_empty() {
                out.push("no VM has been started by this process".into());
            }
            for s in status {
                out.push(format!("  {} tier={} provider={} pid={:?} commands={} idle={}s rss={}KiB snapshots={}", s.key, s.tier, s.provider, s.pid, s.commands, s.idle_secs, s.rss_kb, s.snapshots));
            }
            Ok(out.join("\n"))
        }
        "image" => {
            let action = o.pos.get(2).map(String::as_str).unwrap_or("show");
            match action {
                "build" => {
                    let img = ark_vm::image::GuestImage::build(&cfg.vm, &paths.data, o.flag("force"))?;
                    Ok(format!("guest image ready in {}\nkernel {} ({} bytes, sha256 {})\ninitramfs {} ({} bytes, sha256 {})",
                        img.dir.display(), img.manifest.kernel.path, img.manifest.kernel.size, img.manifest.kernel.sha256,
                        img.manifest.initramfs.path, img.manifest.initramfs.size, img.manifest.initramfs.sha256))
                }
                "verify" => {
                    let img = ark_vm::image::GuestImage::find(&cfg.vm, &paths.data)?;
                    img.verify()?;
                    Ok(format!("ok: {} verifies (image version {})", img.dir.display(), img.manifest.image_version))
                }
                _ => {
                    let img = ark_vm::image::GuestImage::find(&cfg.vm, &paths.data)?;
                    Ok(format!("{}\nkernel: {} ({} bytes)\ninitramfs: {} ({} bytes)", img.dir.display(), img.manifest.kernel.path, img.manifest.kernel.size, img.manifest.initramfs.path, img.manifest.initramfs.size))
                }
            }
        }
        "snapshot" | "save" => {
            let reason = o.val("reason").unwrap_or("manual");
            let m = mgr.snapshot(session, tier, &workspace, reason)?;
            Ok(format!("snapshot {} ({} files, {} bytes); undo with `ark sandbox vm undo --session {session}`", m.name, m.files, m.bytes))
        }
        "snapshots" => {
            let list = mgr.snapshots(session, tier, &workspace);
            if json_out {
                return Ok(serde_json::to_string_pretty(&list).unwrap_or_default());
            }
            Ok(if list.is_empty() {
                format!("no snapshots for {session} (they are taken on session start and before destructive commands)")
            } else {
                list.iter().map(|m| format!("{}  {}  {} files  {} bytes", m.name, m.reason, m.files, m.bytes)).collect::<Vec<_>>().join("\n")
            })
        }
        "undo" | "restore" => {
            let m = mgr.restore(session, tier, &workspace, o.val("snapshot"))?;
            Ok(format!("restored {} from snapshot {} (the previous state was snapshotted first)", workspace.display(), m.name))
        }
        "gc" => {
            let n = mgr.gc_idle();
            Ok(format!("stopped {n} idle VM(s)"))
        }
        other => Err(format!("ark sandbox vm: unknown action `{other}` (status | image [build|verify] | snapshot | snapshots | undo | gc)")),
    }
}

fn ask_tty(q: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("{q} [y/N] ");
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).is_ok() && matches!(s.trim(), "y" | "Y" | "yes")
}

pub fn sandbox(argv: &[String], paths: &Paths) -> Result<i32, String> {
    let o = Opts::parse(argv, &["session", "agent", "workspace", "w"]);
    let cfg = exec_config(paths)?;
    let out = match o.pos.first().map(String::as_str).unwrap_or("") {
        "list" | "ls" => sandbox_list(&cfg, paths, &o)?,
        "vm" | "microvm" => sandbox_vm(&cfg, paths, &o)?,
        "recreate" => sandbox_recreate(&cfg, paths, &o, &ask_tty)?,
        "explain" => {
            let ws = o.val("workspace").or(o.val("w")).map(PathBuf::from).unwrap_or_else(|| std::env::current_dir().unwrap_or_default());
            let session = o.val("session").unwrap_or("main");
            let mut names: Vec<String> = ark_tools::builtin_tools().iter().map(|t| t.spec().name).collect();
            names.extend(DEFAULT_ALLOW.iter().chain(DEFAULT_DENY).map(|s| s.to_string()));
            names.sort();
            names.dedup();
            let v = explain(&cfg, paths, session, &ws, &names);
            if o.flag("json") {
                serde_json::to_string_pretty(&v).unwrap_or_default()
            } else {
                render_explain(&v)
            }
        }
        _ => "usage: ark sandbox list [--json] [--browser] | recreate (--all | --session <id> | --agent <workspace>) [--browser] [--force] | explain [--session <id>] [--workspace DIR] [--json] | vm status|image|snapshot|snapshots|undo|gc [--json]".into(),
    };
    println!("{out}");
    Ok(0)
}

// ───────────── host wiring (called from wire.rs) ─────────────

/// Tools this module adds: xAI `code_execution` when an xAI key is configured (OpenClaw only
/// offers it with xAI credentials).
pub fn tools(paths: &Paths) -> Vec<Arc<dyn ark_core::Tool>> {
    let in_env = std::env::var("XAI_API_KEY").is_ok_and(|v| !v.trim().is_empty());
    let in_vault = ark_kernel::vault::Vault::load(&paths.secrets()).is_ok_and(|v| v.names().iter().any(|n| n == "XAI_API_KEY"));
    if !(in_env || in_vault) {
        return vec![];
    }
    vec![Arc::new(ark_tools::web::code_execution::CodeExecution { cfg: Arc::new(ark_tools::web::WebConfig::default()), env: ark_tools::web::http::process_env() })]
}

/// Install the process-wide execution environment from the user's `[exec]`, and — only when
/// that selects a non-local backend — the code-mode selector, so `run` happens where `shell`
/// runs (Hermes `terminal.backend`, OpenClaw sandbox backends). `ark_kernel::coderun` asks
/// `ark_core::exec::backend_for`; it stays `None` unless a selector is installed, which is what
/// keeps local mode on the plain host path. (The `ExecBackend` abstraction itself is g5's row;
/// this is the single install call it needs — see audit/round4/g4-wiring.md §C-2.)
pub fn install(paths: &Paths) -> Arc<ExecEnv> {
    let cfg = match exec_config(paths) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ark: warning: {e}; using the default [exec] (local)");
            ExecConfig::default()
        }
    };
    let remote = cfg.backend != "local" || (cfg.sandbox.mode != "off" && cfg.sandbox.backend != "local");
    let cgroups = cfg.cgroups.clone();
    let env = Arc::new(ExecEnv::new(cfg));
    // Plugin-provided execution environments (Hermes `agent/terminal_env_provider.py`): the
    // archive's providers become `exec.backend = "<name>"` options, configured by
    // `[exec.providers.<name>]`. Registered before `install` so `validate` knows the names.
    ark_plugin::exec::register_builtin();
    ark_plugin::exec::install_into(|name: &str, p: ark_plugin::exec::Provider| {
        let name = name.to_string();
        let err_name = name.clone();
        ark_tools::exec::register_provider(
            &name,
            Arc::new(move |v: &Value, c: &ark_tools::exec::BackendCtx| {
                let secrets = c.secrets.clone();
                let secret: SecretFn = Arc::new(move |n: &str| {
                    let ph = format!("{{{{secret:{n}}}}}");
                    let got = secrets(&ph);
                    (got != ph && !got.is_empty()).then_some(got).or_else(|| std::env::var(n).ok().filter(|s| !s.is_empty()))
                });
                let ctx = ark_plugin::exec::Ctx::new(c.workspace.clone(), c.scope_key.clone(), c.home.clone(), c.sandboxed, secret);
                p(v, &ctx).map_err(|e| format!("exec backend `{err_name}`: {e}"))
            }),
        );
    });
    // `/exec host=` and `/elevated` live in the security state (secgate updates them); the
    // shell/job/process tools read them back here, so routing needs no restart.
    let data = paths.data.clone();
    env.set_route_lookup(Arc::new(move |session: &str| {
        use ark_security::approvals::Elevated;
        let st = ark_security::approvals::session_state(&data, session);
        let host = match st.exec.host.as_deref() {
            Some("sandbox") | Some("gateway") => Some("sandbox".to_string()),
            Some("node") => Some("node".to_string()),
            Some("host") | Some("local") => Some("host".to_string()),
            _ => None,
        };
        let elevated = match st.elevated {
            Some(Elevated::On) | Some(Elevated::Full) => Some("on".to_string()),
            Some(Elevated::Ask) => Some("ask".to_string()),
            Some(Elevated::Off) => Some("off".to_string()),
            None => None,
        };
        ark_tools::exec::SessionOverride { host, elevated }
    }));
    ark_tools::exec::install(env.clone());
    // C7: where the reaper registry lives (`<data>/reaper/procs.jsonl`). Every exec/shell
    // call adds the process groups it starts; the daemon's sweeper reclaims the orphaned ones.
    ark_tools::exec::local::set_reaper_home(&paths.data);
    // ent-024: per-command cgroups (v1 or v2) when ark may write to its subtree.
    if cgroups.enabled {
        if let Err(e) = ark_tools::exec::local::enable_cgroups(&cgroups, Path::new("/")) {
            eprintln!("ark: warning: [exec.cgroups]: {e}; commands are tracked by process group only");
        }
    }
    if remote {
        let (home, installed) = (paths.data.clone(), env.clone());
        let vault = Arc::new(ark_kernel::vault::Vault::load(&paths.secrets()).unwrap_or_else(|_| ark_kernel::vault::Vault::empty()));
        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(move |s: &str| vault.substitute(s));
        ark_core::exec::install_selector(Arc::new(move |session: &str, ws: &Path| match installed.backend(session, ws, &home, &secrets, false) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("ark: warning: exec backend unavailable ({e}); running locally");
                Arc::new(ark_tools::exec::local::LocalBackend::new()) as Arc<dyn ark_core::exec::ExecBackend>
            }
        }));
    }
    env
}

/// After the kernel exists: `[exec]` itself, `[exec.code]`, hook-output spill settings and the
/// background-process completion notifier.
pub fn attach(k: &ark_kernel::kernel::Kernel) {
    // Install the environment first: everything below hangs off *that* instance (a later
    // `exec::install` would drop the notifier).
    let env = install(&k.paths);
    match serde_json::from_value::<ark_kernel::coderun::CodeConfig>(if env.cfg.code.is_null() { json!({}) } else { env.cfg.code.clone() }) {
        Ok(c) => ark_kernel::coderun::configure(c),
        Err(e) => eprintln!("ark: warning: [exec.code]: {e}"),
    }
    ark_kernel::hooks::spill::configure(ark_kernel::hooks::spill::SpillConfig::from_table(k.cfg.hooks_extra.get("output_spill")));
    // `sandbox.mode = "non-main"`: the operator's own session (no parent) runs on the host;
    // sessions spawned by an agent or a surface (`parent` set in the header) are sandboxed.
    // The answer never changes for a session, so it is cached.
    let kc = k.clone();
    let seen: std::sync::Mutex<std::collections::HashMap<String, bool>> = std::sync::Mutex::new(std::collections::HashMap::new());
    env.set_classifier(Arc::new(move |session: &str| {
        if let Some(v) = seen.lock().unwrap().get(session) {
            return *v;
        }
        let main = kc.store.read(session).ok().and_then(|evs| evs.first().map(|e| e.kind.clone())).map(|kind| match kind {
            ark_kernel::event::EventKind::Header { parent, .. } => parent.is_none(),
            _ => true,
        });
        let main = main.unwrap_or(true);
        seen.lock().unwrap().insert(session.to_string(), main);
        main
    }));
    // `job notify=true`: the completion notice is queued into the owning session as input.
    let kk = k.clone();
    env.set_notifier(Arc::new(move |session: &str, text: &str| {
        let _ = kk.submit(session, text, "process");
    }));
    start_vm_broker(k);
}

/// The daemon-side broker of the VM (A1/A3/A4). A VM has no network and no key of its own:
/// every privileged command and every outbound request goes guest → host broker → back. So
/// when the resolved execution plan is a microVM, this starts the socket the VM adapter talks
/// to (`ark_tools::exec::vm::install_socket_broker`) and installs it for every VM manager.
///
/// It is *not* an extra gate on ordinary work: `[security.broker]` ships the common reversible
/// commands (package installs, service reloads) as pre-authorised, the built-in dev hosts are
/// on the egress list, and only tier 2/3 work queues for the operator (§0). The one socket
/// handle is kept for the life of the process.
fn start_vm_broker(k: &ark_kernel::kernel::Kernel) {
    static DAEMON: std::sync::OnceLock<std::sync::Mutex<Option<ark_security::broker::Broker>>> = std::sync::OnceLock::new();
    let env = ark_tools::exec::global();
    // A VM cannot exist without a broker (its only channel is the guest agent), so "the plan
    // uses a VM" is what makes the broker needed; `[security.broker] enabled = true` forces it.
    let plan = env.plan("main", &std::env::current_dir().unwrap_or_default(), &k.paths.data);
    let needed = plan.uses_microvm() || env.cfg.sandbox.backend == "vm" || env.cfg.backend == "vm";
    if !(k.cfg.security.broker.enabled || needed) {
        return;
    }
    let vault = k.vault.clone();
    let secrets: ark_security::egress_proxy::Secrets = Arc::new(move |name: &str| {
        // Only a declared `{{secret:NAME}}` is expanded, and the value never leaves the host:
        // the broker injects it into the request, the VM only ever sees its own traffic.
        let got = vault.substitute(&format!("{{{{secret:{name}}}}}"));
        if got == format!("{{{{secret:{name}}}}}") {
            std::env::var(name).unwrap_or_default()
        } else {
            got
        }
    });
    let mut allow = k.cfg.gate.egress_allow.clone();
    // The built-in development hosts are pre-authorised (§0-3 A3): package registries, docs,
    // source hosts. `dev_hosts = false` in `[security.egress_proxy]` turns that off.
    if k.cfg.security.egress_proxy.dev_hosts {
        allow.extend(ark_security::risk::dev_hosts());
    }
    let started = ark_security::broker::start_daemon(
        ark_security::broker::Daemon { sec: &k.cfg.security, data: &k.paths.data, config_dir: &k.paths.config_dir, runtime: &k.paths.runtime, secret: secrets, gate_allow: &allow, gate_deny: &k.cfg.gate.egress_deny },
        needed,
    );
    match started {
        Ok(Some(b)) => {
            let path = b.path().to_path_buf();
            ark_tools::exec::vm::install_socket_broker(&path);
            // A5, second layer: the proxy only reaches hosts some component declares (built-in
            // tools ship their declarations, so ordinary work is unaffected).
            if k.cfg.security.broker.enforce_capabilities {
                ark_security::egress_proxy::set_capability_gate(Some(ark_security::capability::egress_gate(&allow)));
            }
            *DAEMON.get_or_init(Default::default).lock().unwrap_or_else(|p| p.into_inner()) = Some(b);
            eprintln!("ark: vm broker listening on {}", path.display());
        }
        Ok(None) => {}
        Err(e) => eprintln!("ark: warning: the VM broker could not start: {e} — a VM will refuse every privileged command and outbound request (fail closed)"),
    }
}

/// Self-registration (`ark_core::registry`): xAI `code_execution`, offered only when an xAI key
/// is configured (OpenClaw only offers it with xAI credentials). Replaces the binary's wiring
/// file naming this module.
pub fn register() {
    ark_core::registry::register_tool_provider("xai-code-execution", 150, |env| {
        let paths = ark_kernel::config::Paths { data: env.data.clone(), config_dir: env.config_dir.clone(), runtime: env.runtime.clone() };
        Ok(tools(&paths))
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ark-execcli-{tag}-{}", ark_kernel::util::random_hex(6)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn sandbox_list_recreate_and_explain() {
        let root = tmp("sb");
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.user_config(), "[exec]\nbackend = \"local\"\n[exec.sandbox]\nmode = \"all\"\nbackend = \"bwrap\"\nworkspace_access = \"none\"\n[exec.sandbox.tools]\ndeny = [\"web_fetch\"]\n").unwrap();
        let cfg = exec_config(&paths).unwrap();
        let sbroot = cfg.sandbox.root(&paths.data);
        for k in ["s-main", "s-other", "shared"] {
            std::fs::create_dir_all(sbroot.join(k).join("workspace")).unwrap();
            std::fs::write(sbroot.join(k).join("workspace/f"), vec![0u8; 4096]).unwrap();
        }
        let listed: Value = serde_json::from_str(&sandbox_list(&cfg, &paths, &Opts::parse(&s(&["list", "--json"]), &[])).unwrap()).unwrap();
        let keys: Vec<&str> = listed["scopes"].as_array().unwrap().iter().map(|x| x["scope"].as_str().unwrap()).collect();
        assert_eq!(keys, ["s-main", "s-other", "shared"]);
        assert_eq!(listed["scopes"][2]["kind"], "shared");
        assert!(listed["scopes"][0]["bytes"].as_u64().unwrap() >= 4096);
        let text = sandbox_list(&cfg, &paths, &Opts::parse(&s(&["list"]), &[])).unwrap();
        assert!(text.contains("SCOPE") && text.contains("s-other"), "{text}");

        let no = |_: &str| false;
        assert!(sandbox_recreate(&cfg, &paths, &Opts::parse(&s(&["recreate", "--session", "other"]), &["session"]), &no).unwrap_err().contains("--force"));
        let out = sandbox_recreate(&cfg, &paths, &Opts::parse(&s(&["recreate", "--session", "other", "--force"]), &["session"]), &no).unwrap();
        assert!(out.contains("s-other") && !sbroot.join("s-other").exists() && sbroot.join("s-main").exists(), "{out}");
        assert!(sandbox_recreate(&cfg, &paths, &Opts::parse(&s(&["recreate"]), &[]), &no).unwrap_err().contains("--all"));
        let yes = |_: &str| true;
        sandbox_recreate(&cfg, &paths, &Opts::parse(&s(&["recreate", "--all"]), &[]), &yes).unwrap();
        assert!(scopes(&cfg, &paths.data).is_empty());

        let tools = s(&["read", "shell", "web_fetch", "channel_send", "mcp__x__y"]);
        let v = explain(&cfg, &paths, "main", Path::new("/w"), &tools);
        assert_eq!((v["sandboxed"].as_bool(), v["runs_in"].as_str(), v["scope_key"].as_str()), (Some(true), Some("bwrap"), Some("s-main")));
        assert!(v["workspace"].as_str().unwrap().ends_with("s-main/workspace"), "private scratch workspace");
        assert_eq!(v["tools"]["denied"], json!(["web_fetch", "channel_send"]));
        assert!(render_explain(&v).contains("SANDBOXED in bwrap"));
        let host = explain(&ExecConfig::default(), &paths, "main", Path::new("/w"), &tools);
        assert_eq!(host["sandboxed"], false);
        // A hand-built `ExecConfig` names its backend, so the plan is that name — the line says
        // where commands run, not which field was set.
        assert!(render_explain(&host).contains("runs in local (host backend)"), "{}", render_explain(&host));
        std::fs::write(paths.user_config(), "[exec]\nbackend = \"nope\"\n").unwrap();
        assert!(exec_config(&paths).is_err());
    }

    #[test]
    fn attach_installs_the_completion_notifier_and_code_config() {
        let _g = EXEC.lock().unwrap_or_else(|e| e.into_inner());
        let kit = crate::testkit::kit_with(|c| {
            c.hooks_extra.insert("output_spill".into(), toml::Value::Table(toml::from_str("max_chars = 1234").unwrap()));
        });
        std::fs::create_dir_all(&kit.paths.config_dir).unwrap();
        std::fs::write(kit.paths.user_config(), "[exec.code]\nmax_tool_calls = 7\npersistent = false\n").unwrap();
        attach(&kit.k);
        assert_eq!(ark_kernel::coderun::config().max_tool_calls, 7);
        assert!(!ark_kernel::coderun::config().persistent);
        assert_eq!(ark_kernel::hooks::spill::config().max_chars, 1234);
        let sid = kit.k.create_session(&kit.ws, None, None, None).unwrap();
        assert!(ark_tools::exec::global().notify(&sid, "[IMPORTANT: Background process job 1 completed normally (exit code 0).]"));
        assert!(kit.k.queued(&sid).iter().any(|q| q.2.contains("Background process job 1")), "notice queued as session input: {:?}", kit.k.queued(&sid));
        ark_kernel::coderun::configure(Default::default());
        ark_kernel::hooks::spill::configure(Default::default());
    }

    /// The exec environment is process-wide, so the tests that install it run one at a time.
    static EXEC: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct NoHost;
    impl ark_core::ToolHost for NoHost {
        fn spawn_agent(&self, _: ark_core::tool::SpawnRequest, _: &ark_core::Cancel) -> Result<String, String> {
            Err("no sub-agents in this test".into())
        }
        fn ask_user(&self, _: &str) -> Result<String, String> {
            Err("no user in this test".into())
        }
    }

    fn tool_ctx(ws: PathBuf) -> ark_core::ToolCtx {
        ark_core::ToolCtx { artifacts: ws.join(".artifacts"), home: ws.join(".home"), workspace: ws, session_id: "e3".into(), cancel: ark_core::Cancel::new(), host: Arc::new(NoHost), secrets: Arc::new(|s: &str| s.to_string()) }
    }

    /// `[exec]` reaches the shell tool and code mode: nothing is installed for local mode
    /// (`backend_for` stays `None`, code mode keeps running on the host), and a configured
    /// backend — `exec.backend` or the sandbox backend of a sandboxed session — is what
    /// `ark_kernel::coderun` then runs in.
    #[test]
    fn install_wires_the_exec_env_and_the_code_mode_selector() {
        let _g = EXEC.lock().unwrap_or_else(|e| e.into_inner());
        use ark_core::exec::ExecBackend;
        struct Fake(&'static str);
        impl ExecBackend for Fake {
            fn id(&self) -> &str {
                self.0
            }
            fn describe(&self) -> String {
                format!("fake {}", self.0)
            }
            fn spawn(&self, _: &ark_core::exec::ExecRequest) -> std::io::Result<Box<dyn ark_core::exec::ExecChild>> {
                Err(std::io::Error::other("not runnable in this test"))
            }
        }
        let root = tmp("install");
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();

        // Nothing configured: local stays local, and code mode is not redirected anywhere.
        assert!(ark_core::exec::backend_for("main", &ws).is_none());
        let env = install(&paths);
        assert_eq!((env.cfg.backend.as_str(), env.cfg.failure_hints), ("local", true));
        assert!(ark_core::exec::backend_for("main", &ws).is_none());

        // A registered provider stands in for docker/ssh/modal: no binary, same selection path.
        ark_tools::exec::register_provider("e3-remote", Arc::new(|_, _| Ok(Arc::new(Fake("e3-remote")) as Arc<dyn ExecBackend>)));
        std::fs::write(paths.user_config(), "[exec]\nbackend = \"e3-remote\"\nsudo_password_secret = \"PW\"\n").unwrap();
        let env = install(&paths);
        assert_eq!((env.cfg.backend.as_str(), env.cfg.sudo_password_secret.as_str()), ("e3-remote", "PW"));
        assert_eq!(ark_tools::exec::global().cfg.backend, "e3-remote", "the tools read the installed environment");
        assert_eq!(ark_core::exec::backend_for("main", &ws).expect("configured backend is selectable").id(), "e3-remote");

        // Sandboxed sessions take `[exec.sandbox] backend`; the selector follows `sandboxed()`.
        std::fs::write(paths.user_config(), "[exec]\nbackend = \"local\"\n[exec.sandbox]\nmode = \"all\"\nbackend = \"e3-remote\"\n").unwrap();
        install(&paths);
        assert_eq!(ark_core::exec::backend_for("main", &ws).unwrap().id(), "e3-remote", "sandbox = all moves every session");

        // Leave a local-only environment behind: other tests in this binary must not run code
        // in a fake backend (the selector cannot be removed once installed).
        ark_core::exec::install_selector(Arc::new(|_, _| Arc::new(ark_tools::exec::local::LocalBackend::new()) as Arc<dyn ExecBackend>));
        ark_tools::exec::install(Arc::new(ExecEnv::default()));
    }

    /// Code mode still runs after the environment is installed (the local path, unchanged).
    #[test]
    fn code_mode_runs_locally_after_install() {
        let _g = EXEC.lock().unwrap_or_else(|e| e.into_inner());
        let root = tmp("codemode");
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.user_config(), "[exec]\nbackend = \"local\"\n").unwrap();
        install(&paths);
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let rt = root.join("rt");
        let cancel = ark_core::Cancel::new();
        let out = ark_kernel::coderun::run(&rt, "echo code-mode-local", "bash", std::time::Duration::from_secs(60), &ws, &cancel, &mut |_| unreachable!("no nested calls"));
        assert!(!out.is_error && out.content.contains("code-mode-local"), "{}", out.content);
        ark_tools::exec::install(Arc::new(ExecEnv::default()));
    }

    /// `/exec host=sandbox|host` and `/elevated on` (secgate persists them in the security
    /// state) reach the exec routing, and a plugin-registered backend is selectable by name.
    #[test]
    fn session_routes_plugin_backends_and_elevated_reach_the_tools() {
        let _g = EXEC.lock().unwrap_or_else(|e| e.into_inner());
        let root = tmp("route");
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.user_config(), "[exec]\n").unwrap();
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let env = install(&paths);
        assert!(!env.sandboxed("plain"));
        ark_security::approvals::update_session(&paths.data, "boxed", |st| st.exec.host = Some("sandbox".into())).unwrap();
        ark_security::approvals::update_session(&paths.data, "escaped", |st| st.exec.host = Some("host".into())).unwrap();
        ark_security::approvals::update_session(&paths.data, "root", |st| st.elevated = Some(ark_security::approvals::Elevated::On)).unwrap();
        assert!(ark_tools::exec::global().sandboxed("boxed"), "`/exec host=sandbox` opts the session in");
        assert!(!ark_tools::exec::global().sandboxed("escaped"));
        assert!(ark_tools::exec::global().elevated("root"), "`/elevated on` escapes the sandbox");
        assert!(!ark_tools::exec::global().elevated("plain"));

        // A backend a plugin registered (`ark_plugin::exec`) is `exec.backend = "<name>"`.
        std::fs::write(paths.user_config(), "[exec]\nbackend = \"workspace-copy\"\n[exec.providers.workspace-copy]\ndir = \"~/copies/one\"\n").unwrap();
        let env = install(&paths);
        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.to_string());
        let b = env.backend("main", &ws, &paths.data, &secrets, false).expect("plugin backend is selectable");
        assert_eq!(b.id(), "workspace-copy");
        assert!(b.describe().contains("copies/one"), "{}", b.describe());

        ark_tools::exec::install(Arc::new(ExecEnv::default()));
    }

    /// `sandbox.mode = "non-main"` sandboxes the sessions an agent or surface spawned
    /// (header has a `parent`); the operator's own session stays on the host.
    #[test]
    fn non_main_mode_sandboxes_child_sessions_only() {
        let _g = EXEC.lock().unwrap_or_else(|e| e.into_inner());
        let kit = crate::testkit::kit_with(|_| {});
        std::fs::create_dir_all(&kit.paths.config_dir).unwrap();
        std::fs::write(kit.paths.user_config(), "[exec]\nbackend = \"local\"\n[exec.sandbox]\nmode = \"non-main\"\nbackend = \"landlock\"\n").unwrap();
        attach(&kit.k);
        let main = kit.k.create_session(&kit.ws, None, None, None).unwrap();
        let child = kit.k.create_session(&kit.ws, None, Some(&main), None).unwrap();
        assert!(!ark_tools::exec::global().sandboxed(&main), "the operator's session runs on the host");
        assert!(ark_tools::exec::global().sandboxed(&child), "a spawned session is sandboxed");
        ark_core::exec::clear_selector();
        ark_tools::exec::install(Arc::new(ExecEnv::default()));
    }

    /// `[exec] failure_hints` reaches the shell tool (the `[exec]` keys used to be dead).
    #[test]
    fn shell_hints_follow_the_installed_exec_config() {
        let _g = EXEC.lock().unwrap_or_else(|e| e.into_inner());
        let root = tmp("hints");
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        let ws = root.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let c = tool_ctx(ws);
        std::fs::write(paths.user_config(), "[exec]\nfailure_hints = false\n").unwrap();
        let env = install(&paths);
        assert!(!env.cfg.failure_hints);
        let o = ark_core::Tool::call(&ark_tools::Shell, &c, json!({"command":"definitely_not_a_cmd_x1"}));
        assert!(o.is_error && !o.content.contains("[hint:"), "hints are off: {}", o.content);
        // Default: the same failure gets its hint.
        std::fs::write(paths.user_config(), "[exec]\n").unwrap();
        install(&paths);
        let o = ark_core::Tool::call(&ark_tools::Shell, &c, json!({"command":"definitely_not_a_cmd_x1"}));
        assert!(o.content.contains("[hint: `definitely_not_a_cmd_x1` is not installed"), "{}", o.content);
        ark_tools::exec::install(Arc::new(ExecEnv::default()));
    }

    /// `/exec host=` and `/elevated` are persisted by the kernel (`secgate::chat_command`) into
    /// `<data>/approvals/sessions.json`; `install()` must translate them for the exec tools via
    /// the route lookup (`sandbox|gateway -> sandbox`, `node -> node`, `host|local -> host`).
    #[test]
    fn exec_route_reads_the_security_state() {
        let _g = EXEC.lock().unwrap_or_else(|e| e.into_inner());
        let root = tmp("routeread");
        let paths = Paths { data: root.join("data"), config_dir: root.join("cfg"), runtime: root.join("run") };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.user_config(), "[exec]\nbackend = \"local\"\n").unwrap();
        install(&paths);
        let route = |s: &str| ark_tools::exec::global().route_of(s);
        // The session file is re-read by (mtime, len); separate the writes so a coarse clock
        // cannot serve the previous value to the lookup.
        let set_host = |h: &str| {
            std::thread::sleep(std::time::Duration::from_millis(2));
            ark_security::approvals::update_session(&paths.data, "s1", |st| st.exec.host = Some(h.into())).unwrap();
        };
        set_host("node");
        assert_eq!(route("s1").host, Some("node".into()), "`/exec host=node`");
        set_host("sandbox");
        assert_eq!(route("s1").host, Some("sandbox".into()), "`/exec host=sandbox`");
        set_host("host");
        assert_eq!(route("s1").host, Some("host".into()), "`/exec host=host`");
        assert_eq!(route("other").host, None, "another session keeps the default route");
        let set_elevated = |lvl: ark_security::approvals::Elevated| {
            std::thread::sleep(std::time::Duration::from_millis(2));
            ark_security::approvals::update_session(&paths.data, "s1", |st| st.elevated = Some(lvl)).unwrap();
        };
        use ark_security::approvals::Elevated;
        set_elevated(Elevated::On);
        assert_eq!(route("s1").elevated, Some("on".into()), "`/elevated on` escapes the sandbox");
        set_elevated(Elevated::Ask);
        assert_eq!(route("s1").elevated, Some("ask".into()), "`/elevated ask`");
        set_elevated(Elevated::Off);
        assert_eq!(route("s1").elevated, Some("off".into()), "`/elevated off`");
        ark_tools::exec::install(Arc::new(ExecEnv::default()));
    }

    /// The same values, but set the way a chat sets them (`secgate::chat_command`, i.e.
    /// `/exec host=…` and `/elevated …` from a channel sender): the route lookup installed by
    /// `install()` must read the chat's writes, not only direct `update_session` calls.
    #[test]
    fn chat_exec_and_elevated_commands_reach_the_route() {
        let _g = EXEC.lock().unwrap_or_else(|e| e.into_inner());
        let kit = crate::testkit::kit_with(|c| {
            c.approvals.forward.approvers.insert("test".into(), vec!["u1".into()]);
            c.approvals.elevated.enabled = true;
            c.approvals.elevated.allow_from.insert("test".into(), vec!["u1".into()]);
        });
        std::fs::write(kit.paths.user_config(), "[exec]\nbackend = \"local\"\n").unwrap();
        install(&kit.paths);
        let chat = |line: &str| ark_kernel::secgate::chat_command(&kit.k, line, Some("s1"), Some(("test", "u1", "Dana"))).unwrap();
        let route = |s: &str| ark_tools::exec::global().route_of(s);
        // The session file is re-read by (mtime, len): keep the writes apart.
        assert!(chat("/exec host=node security=allowlist ask=always").contains("exec defaults updated"));
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(route("s1").host, Some("node".into()), "a chat's `/exec host=node` reaches the route");
        assert_eq!(ark_security::approvals::session_state(&kit.paths.data, "s1").exec.security, Some(ark_security::approvals::ExecSecurity::Allowlist));
        assert_eq!(ark_security::approvals::effective_exec(&kit.k.cfg.approvals, &kit.paths.data, "s1", 0), (ark_security::approvals::ExecSecurity::Allowlist, ark_security::approvals::ExecAsk::Always), "the kicker reads `security=`/`ask=` from the same state");
        assert!(chat("/exec host=sandbox").contains("exec defaults updated"));
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(route("s1").host, Some("sandbox".into()));
        assert!(chat("/elevated on").contains("elevated → on"));
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(route("s1").elevated, Some("on".into()), "a chat's `/elevated on` escapes the sandbox");
        assert!(chat("/elevated ask").contains("elevated → ask"));
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(route("s1").elevated, Some("ask".into()));
        assert!(chat("/elevated off").contains("elevated → off"));
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_eq!(route("s1").elevated, Some("off".into()));
        assert_eq!(route("other").elevated, None, "another session is untouched");
        ark_tools::exec::install(Arc::new(ExecEnv::default()));
    }

    /// A1/A3/A5 in the daemon, without booting a VM: when the broker is on, `attach()` starts
    /// the socket the VM adapter talks to, hands it to every VM manager, and installs the
    /// capability gate on the egress proxy. The real-VM half of this is
    /// `crates/ark-tools/tests/vm_broker.rs` (guest → broker → daemon, `#[ignore]`).
    #[test]
    fn the_daemon_starts_the_vm_broker_and_installs_the_capability_gate() {
        use std::io::{BufRead, BufReader, Write};
        let _g = EXEC.lock().unwrap_or_else(|e| e.into_inner());
        let kit = crate::testkit::kit_with(|c| {
            c.security.broker.enabled = true;
            c.security.broker.exec_allow = vec!["echo *".into()];
        });
        std::fs::write(kit.paths.user_config(), "[exec]\nbackend = \"local\"\n[security.broker]\nenabled = true\n").unwrap();
        attach(&kit.k);
        let sock = kit.paths.runtime.join("broker.sock");
        assert!(sock.exists(), "the daemon created the broker socket at {}", sock.display());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(&sock).unwrap();
            assert_eq!(m.permissions().mode() & 0o777, 0o600, "only the daemon's user may talk to the broker");
        }
        assert_eq!(ark_tools::exec::vm::installed_broker().as_deref(), Some(sock.as_path()), "the VM adapter was pointed at it");
        // It answers, and says capability enforcement is on.
        let mut c = std::os::unix::net::UnixStream::connect(&sock).unwrap();
        c.write_all(b"{\"id\":1,\"op\":\"health\"}\n").unwrap();
        let mut line = String::new();
        BufReader::new(c).read_line(&mut line).unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!((v["ok"].as_bool(), v["result"]["broker"].as_bool(), v["result"]["capabilities"].as_bool()), (Some(true), Some(true), Some(true)), "{v}");
        // A5 at the proxy: a host no component declares is refused by the installed gate.
        let gate = ark_security::egress_proxy::capability_gate();
        assert!(gate("crates.io", 443).is_ok(), "a public host is covered by the built-in declarations");
        assert!(gate("10.9.9.9", 80).is_err(), "a private host needs an explicit declaration: {}", gate("10.9.9.9", 80).unwrap_err());
        // The VM keeps its own identity: `auto` resolves through the same policy explain prints.
        let plan = ark_tools::exec::global().plan("main", &kit.ws, &kit.paths.data);
        assert_eq!(plan.backend, ark_tools::exec::global().plan("main", &kit.ws, &kit.paths.data).backend);
        ark_tools::exec::install(Arc::new(ExecEnv::default()));
        ark_security::egress_proxy::set_capability_gate(None);
        let _ = std::fs::remove_dir_all(kit.paths.data.parent().unwrap());
    }
}
