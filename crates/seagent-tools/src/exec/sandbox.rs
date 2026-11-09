//! OpenClaw sandbox policy: which sessions are sandboxed (`mode`), container
//! lifetime (`scope`), workspace mount (`workspace_access`), which tools a
//! sandboxed session may use (`tools`), plus the environment and bind-mount
//! safety checks applied before anything crosses into a sandbox.

use super::ExecEnv;
use seagent_core::{Effect, Tool, ToolCtx, ToolOutput, ToolSpec};
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// `[exec.sandbox]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    /// off | non-main | all
    pub mode: String,
    /// Backend for sandboxed sessions: auto | bwrap | landlock | vm | docker | podman |
    /// singularity | apptainer | ssh | openshell | modal | daytona | vercel. `auto` (the
    /// default when the operator names none) is a microVM when this machine can boot one.
    pub backend: String,
    /// Did the config file name `backend`? `false` means `auto` resolves it (A1/B1).
    #[serde(skip)]
    pub backend_set: bool,
    /// session | agent (one per workspace) | shared
    pub scope: String,
    /// none (private scratch workspace) | ro | rw
    pub workspace_access: String,
    /// none | host (bwrap/landlock); containers use `[exec.docker] network`.
    pub network: String,
    /// Where `none` workspaces and per-scope state live (default `<seagent data>/sandboxes`).
    pub workspace_root: String,
    pub tools: ToolPolicy,
    /// May a sandboxed call set `elevated=true` and run on the host? off | ask | on.
    /// `ask` sends it through the egress gate as a remote effect.
    pub elevated: String,
    /// Host paths additionally bind-mounted (`/src:/dst[:ro]`).
    pub binds: Vec<String>,
    /// Remove idle sandboxes after this many hours / older than this many days (0 = keep).
    pub prune_idle_hours: u64,
    pub prune_max_age_days: u64,
}

/// `[exec.sandbox.tools]`: allow wins over the default deny list; deny wins over allow.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ToolPolicy {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        SandboxConfig {
            mode: "off".into(),
            backend: "auto".into(),
            // Same rule as `ExecConfig::backend_set`: a hand-built config is explicit, a
            // config *file* that does not name the sandbox backend gets `auto` (microVM first).
            backend_set: true,
            scope: "session".into(),
            workspace_access: "none".into(),
            network: "none".into(),
            workspace_root: String::new(),
            tools: ToolPolicy::default(),
            elevated: "ask".into(),
            binds: vec![],
            prune_idle_hours: 24,
            prune_max_age_days: 7,
        }
    }
}

impl SandboxConfig {
    pub fn validate(&self) -> Result<(), String> {
        let one = |k: &str, v: &str, ok: &[&str]| if ok.contains(&v) { Ok(()) } else { Err(format!("exec.sandbox.{k} `{v}`: use {}", ok.join(" | "))) };
        one("mode", &self.mode, &["off", "non-main", "all"])?;
        one("scope", &self.scope, &["session", "agent", "shared"])?;
        one("workspace_access", &self.workspace_access, &["none", "ro", "rw"])?;
        one("network", &self.network, &["none", "host"])?;
        one("elevated", &self.elevated, &["off", "ask", "on"])?;
        if self.backend == "local" {
            return Err("exec.sandbox.backend cannot be `local` (that is no sandbox); use bwrap, landlock, docker, podman, …".into());
        }
        for b in &self.binds {
            parse_bind(b)?;
        }
        Ok(())
    }
    pub fn root(&self, home: &Path) -> PathBuf {
        if self.workspace_root.is_empty() {
            home.join("sandboxes")
        } else {
            seagent_core::tool::expand_home(&self.workspace_root)
        }
    }
    /// Private workspace of a scope (used when `workspace_access = "none"`).
    pub fn scratch_workspace(&self, home: &Path, scope_key: &str) -> PathBuf {
        self.root(home).join(scope_key).join("workspace")
    }
}

/// OpenClaw DEFAULT_TOOL_ALLOW / DEFAULT_TOOL_DENY mapped to seagent tool names.
pub const DEFAULT_ALLOW: &[&str] = &["shell", "process", "terminal", "read", "write", "edit", "patch", "apply_patch", "glob", "grep", "run", "todo", "ask_user", "spawn", "session_search", "context_fetch", "skill", "memory", "job", "goal_done", "tool_describe", "tool_call"];
pub const DEFAULT_DENY: &[&str] = &["node_invoke", "channel_send", "browser", "computer", "canvas", "acp_delegate", "cron", "schedule", "gateway"];

impl ToolPolicy {
    /// Is `name` usable inside the sandbox? Tool names may be glob-ish `mcp__*`.
    pub fn allows(&self, name: &str) -> bool {
        let hit = |l: &[String]| l.iter().any(|p| pat_match(p, name));
        if hit(&self.deny) {
            return false;
        }
        if hit(&self.allow) {
            return true;
        }
        if DEFAULT_DENY.contains(&name) || name.starts_with("a2a_") {
            return false;
        }
        // Unknown tools (MCP, plugins): allowed only when the user allow-lists them,
        // unless the allow list is empty (then defaults decide: allowed).
        self.allow.is_empty() || DEFAULT_ALLOW.contains(&name)
    }
}

fn pat_match(p: &str, name: &str) -> bool {
    match p.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => p == name,
    }
}

/// `src:dst[:ro|rw]` → (src, dst, read_only).
pub fn parse_bind(s: &str) -> Result<(PathBuf, String, bool), String> {
    #[cfg(unix)]
    let parts: Vec<&str> = s.split(':').collect();
    // Windows: the host side may start with a drive (`C:\src:/data:ro`); its colon is not a
    // field separator.
    #[cfg(not(unix))]
    let parts: Vec<&str> = {
        let b = s.as_bytes();
        let drive = b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/');
        let (head, rest) = if drive { s.split_at(2) } else { ("", s) };
        let mut v: Vec<&str> = rest.split(':').collect();
        if drive {
            v[0] = &s[..head.len() + v[0].len()];
        }
        v
    };
    let (src, dst, ro) = match parts.as_slice() {
        [src, dst] => (*src, *dst, false),
        [src, dst, mode @ ("ro" | "rw")] => (*src, *dst, *mode == "ro"),
        _ => return Err(format!("bind `{s}`: expected /host/path:/container/path[:ro|rw]")),
    };
    let src = seagent_core::tool::expand_home(src);
    validate_bind_source(&src)?;
    if !dst.starts_with('/') {
        return Err(format!("bind `{s}`: container path must be absolute"));
    }
    Ok((src, dst.to_string(), ro))
}

/// OpenClaw validate-sandbox-security: host paths that must never be exposed.
const BLOCKED_HOST_PATHS: &[&str] = &["/etc", "/proc", "/sys", "/dev", "/root", "/boot", "/run", "/var/run", "/var/run/docker.sock", "/run/docker.sock", "/run/podman"];
#[cfg_attr(not(unix), allow(dead_code))]
const BLOCKED_HOME_SUBPATHS: &[&str] = &[".aws", ".cargo", ".config", ".docker", ".gnupg", ".netrc", ".npm", ".ssh", ".kube", ".local/share/seagent"];

/// Windows counterparts of [`BLOCKED_HOST_PATHS`]: the system directory, machine-wide program
/// data (service secrets, the Docker engine's state) and the container engines' named pipes.
#[cfg(not(unix))]
fn windows_blocked_host_paths() -> Vec<PathBuf> {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let mut v: Vec<PathBuf> = [env("SystemRoot").unwrap_or_else(|| PathBuf::from(r"C:\Windows")), env("ProgramData").unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))].into_iter().collect();
    v.extend([r"\\.\pipe\docker_engine", r"\\.\pipe\dockerDesktopLinuxEngine", r"\\.\pipe\podman-machine-default"].map(PathBuf::from));
    v
}

/// Home subpaths a bind may not expose on Windows, on top of [`BLOCKED_HOME_SUBPATHS`]:
/// seagent's own data (`AppData\Local\seagent`, config in `AppData\Roaming`), the Edge / Chrome
/// profiles and Windows' credential vaults. `AppData\Local\Temp` stays bindable.
#[cfg(not(unix))]
const WINDOWS_BLOCKED_HOME_SUBPATHS: &[&str] = &[".aws", ".cargo", ".config", ".docker", ".gnupg", ".netrc", ".npm", ".ssh", ".kube", ".local/share/seagent", "appdata/roaming", "appdata/local/seagent", "appdata/local/microsoft", "appdata/local/google"];

#[cfg(not(unix))]
fn win_lower(p: &Path) -> PathBuf {
    PathBuf::from(p.to_string_lossy().replace('/', "\\").to_lowercase())
}

pub fn validate_bind_source(src: &Path) -> Result<(), String> {
    // Windows: the profile (`USERPROFILE`) holds the keys and AppData even when some tool set
    // a different `HOME`; both are floors.
    #[cfg(not(unix))]
    if let Some(profile) = std::env::var_os("USERPROFILE").filter(|p| !p.is_empty()).map(PathBuf::from) {
        if profile != host_home() {
            validate_bind_source_in(src, &profile)?;
        }
    }
    validate_bind_source_in(src, &host_home())
}

/// [`validate_bind_source`] against an explicit home (credential mounts validate the same
/// floor against the home their entries are relative to).
pub fn validate_bind_source_in(src: &Path, home: &Path) -> Result<(), String> {
    #[cfg(unix)]
    return validate_bind_source_with(src, home, BLOCKED_HOME_SUBPATHS);
    #[cfg(not(unix))]
    return validate_bind_source_with(src, home, WINDOWS_BLOCKED_HOME_SUBPATHS);
}

/// The floor itself: system paths, container sockets, `/`, the whole home, plus `denied`
/// home subpaths.
fn validate_bind_source_with(src: &Path, home: &Path, denied: &[&str]) -> Result<(), String> {
    if !src.is_absolute() {
        return Err(format!("bind source {} must be absolute", src.display()));
    }
    #[cfg(unix)]
    let norm = src.canonicalize().unwrap_or_else(|_| src.to_path_buf());
    // Windows: no `\\?\` prefix and lowercase (paths are case-insensitive), so it compares
    // with `C:\Windows` and the home below.
    #[cfg(not(unix))]
    let norm = win_lower(&seagent_core::platform::layout::canonicalize(src).unwrap_or_else(|_| src.to_path_buf()));
    if norm == Path::new("/") {
        return Err("refusing to bind-mount the host root into a sandbox".into());
    }
    #[cfg(not(unix))]
    if norm.parent().is_none() {
        return Err("refusing to bind-mount the host root into a sandbox".into());
    }
    for b in BLOCKED_HOST_PATHS {
        let b = Path::new(b);
        if norm.starts_with(b) || b.starts_with(&norm) {
            return Err(format!("refusing to bind-mount {} into a sandbox: it exposes {}", src.display(), b.display()));
        }
    }
    #[cfg(not(unix))]
    for b in windows_blocked_host_paths().iter().map(|b| win_lower(b)) {
        if norm.starts_with(&b) || b.starts_with(&norm) {
            return Err(format!("refusing to bind-mount {} into a sandbox: it exposes {}", src.display(), b.display()));
        }
    }
    if !home.as_os_str().is_empty() {
        #[cfg(unix)]
        let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
        #[cfg(not(unix))]
        let home = win_lower(&seagent_core::platform::layout::canonicalize(home).unwrap_or_else(|_| home.to_path_buf()));
        if norm == home {
            return Err("refusing to bind-mount the whole home directory into a sandbox".into());
        }
        for s in denied {
            let b = home.join(s);
            if norm.starts_with(&b) || b.starts_with(&norm) && norm != home {
                return Err(format!("refusing to bind-mount {} into a sandbox: it exposes ~/{s}", src.display()));
            }
        }
    }
    Ok(())
}

/// `[exec] credential_files` may name `~/.config/gh/hosts.yml`, `~/.aws/credentials` and the
/// like — that is its purpose, so the blanket `~/.config` style floor does not apply — but
/// never the ssh keys/agent (`~/.ssh`) or any path above.
const CREDENTIAL_DENIED_HOME: &[&str] = &[".ssh"];

/// The user's home: `[exec] credential_files` entries are relative to it.
pub fn host_home() -> PathBuf {
    #[cfg(not(unix))]
    if std::env::var_os("HOME").is_none() {
        // Windows has no `HOME` unless a POSIX shell set one; the profile is the home.
        return std::env::var_os("USERPROFILE").map(PathBuf::from).unwrap_or_default();
    }
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default()
}

/// seagent's own config/data dirs (`seagent_core::layout`, exactly what the kernel's `Paths` uses) —
/// `credential_files` validation needs them to refuse seagent's own secret store.
fn seagent_dirs() -> seagent_security::paths::SeagentDirs {
    let l = seagent_core::layout::detect();
    seagent_security::paths::SeagentDirs { config_dir: l.config, data_dir: l.data }
}

/// `[exec] credential_files` as read-only sandbox mounts: `(host, container path, ro)` plus
/// the refused entries (logged here, never mounted). Validation is
/// `seagent_security::credfiles`; the host-path floor is the one `[exec.sandbox] binds` meet.
pub fn credential_binds(entries: &[String], container_home: &str, home: &Path) -> (Vec<(PathBuf, String, bool)>, Vec<String>) {
    let (binds, mut errs) = seagent_security::credfiles::sandbox_binds(entries, container_home, home, &seagent_dirs());
    let mut ok = Vec::new();
    for (src, dst, ro) in binds {
        match validate_bind_source_with(&src, home, CREDENTIAL_DENIED_HOME) {
            Ok(()) => ok.push((src, dst, ro)),
            Err(e) => errs.push(format!("credential_files: {e}")),
        }
    }
    for e in &errs {
        eprintln!("seagent: credential_files entry skipped: {e}");
    }
    (ok, errs)
}

// ───────────── environment sanitizing ─────────────

/// Should `name` be kept out of a sandboxed child's environment? The rules live in
/// `seagent_security::envscrub` (one implementation for the kernel, MCP servers and the exec
/// backends): the `Sandbox` surface is the `Server` set plus credential-shaped names.
pub fn is_secret_env(name: &str) -> bool {
    seagent_security::envscrub::is_blocked(name, seagent_security::envscrub::Surface::Sandbox)
}

/// OpenClaw validateEnvVarValue: values unsafe to forward into a sandbox.
pub fn unsafe_env_value(v: &str) -> Option<&'static str> {
    if v.contains('\0') {
        return Some("contains null bytes");
    }
    if v.len() > 32 * 1024 {
        return Some("value exceeds maximum length");
    }
    if v.len() >= 80 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)) {
        return Some("looks like base64-encoded credential data");
    }
    None
}

/// Is `name` explicitly forwarded by `[exec] env_passthrough`?
///
/// The operator opt-in covers the credential-*shape* heuristic only (`BUILD_TOKEN` holding a
/// build tag); `envscrub::passthrough_allows` is the shared rule for what it can never
/// re-allow — Tier-1 secrets and seagent-managed provider / bot credentials.
pub fn passthrough_forwards(name: &str, passthrough: &[String]) -> bool {
    passthrough.iter().any(|p| p == name) && seagent_security::envscrub::passthrough_allows(name)
}

/// Names to remove from a child's inherited environment (Hermes subprocess scrub).
pub fn scrubbed_names(passthrough: &[String]) -> Vec<String> {
    std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()).filter(|k| is_secret_env(k) && !passthrough_forwards(k, passthrough)).collect()
}

/// Environment forwarded into a container / remote sandbox: explicit config
/// values, minus credential names and unsafe values (returns kept, blocked).
pub fn sanitize_forwarded(vars: &[(String, String)], passthrough: &[String]) -> (Vec<(String, String)>, Vec<String>) {
    let mut kept = Vec::new();
    let mut blocked = Vec::new();
    for (k, v) in vars {
        let allowed = passthrough_forwards(k, passthrough);
        if !allowed && (is_secret_env(k) || unsafe_env_value(v).is_some()) {
            blocked.push(k.clone());
        } else {
            kept.push((k.clone(), v.clone()));
        }
    }
    (kept, blocked)
}

// ───────────── tool policy wrapper ─────────────

/// Wraps a tool so sandboxed sessions get OpenClaw's sandbox semantics: tools
/// outside the sandbox tool policy are refused, `workspace_access = "none"`
/// points file tools at the private scratch workspace, and `ro` refuses writes
/// inside the real workspace.
///
/// The policy is read from [`super::global()`] on every call, so it does not
/// matter whether the host installs `[exec]` before or after the tools are
/// built (a `/exec` override or a config reload is picked up immediately).
pub struct Sandboxed {
    pub inner: Arc<dyn Tool>,
    /// Pinned environment. `None` (what [`wrap_all`] builds) means "follow
    /// [`super::global()`]", which is what the binary and the tests of other
    /// modules rely on; embedders that own an `ExecEnv` without installing it can
    /// pin it with [`wrap_with`].
    pub env: Option<Arc<ExecEnv>>,
}

impl Sandboxed {
    fn env(&self) -> Arc<ExecEnv> {
        match &self.env {
            Some(e) => e.clone(),
            None => super::global(),
        }
    }
}

/// Wrap every tool for the sandbox policy. The host calls this once over its
/// tool list (`crates/seagent/src/main.rs`); wrapping is safe with `mode = "off"`
/// too, because `/exec host=sandbox` can opt a single session in later.
pub fn wrap_all(tools: Vec<Arc<dyn Tool>>) -> Vec<Arc<dyn Tool>> {
    wrap_with(tools, None)
}

/// Same, against a specific environment instead of the installed one (tests, and
/// embedders that build their own `ExecEnv`).
pub fn wrap_with(tools: Vec<Arc<dyn Tool>>, env: Option<Arc<ExecEnv>>) -> Vec<Arc<dyn Tool>> {
    tools.into_iter().map(|t| Arc::new(Sandboxed { inner: t, env: env.clone() }) as Arc<dyn Tool>).collect()
}

/// The context a sandboxed call sees: with `workspace_access = "none"` the file
/// tools are re-rooted at the scope's private scratch workspace.
fn sandbox_ctx(env: &ExecEnv, ctx: &ToolCtx) -> ToolCtx {
    let mut c = ctx.clone();
    if env.cfg.sandbox.workspace_access == "none" {
        let key = env.scope_key(&ctx.session_id, &ctx.workspace);
        let ws = env.cfg.sandbox.scratch_workspace(&ctx.home, &key);
        let _ = std::fs::create_dir_all(&ws);
        c.workspace = ws;
    }
    c
}

impl Tool for Sandboxed {
    fn spec(&self) -> ToolSpec {
        self.inner.spec()
    }
    fn effects(&self, ctx: &ToolCtx, input: &Value) -> Vec<Effect> {
        let env = self.env();
        if env.sandboxed(&ctx.session_id) {
            self.inner.effects(&sandbox_ctx(&env, ctx), input)
        } else {
            self.inner.effects(ctx, input)
        }
    }
    fn call(&self, ctx: &ToolCtx, input: Value) -> ToolOutput {
        let env = self.env();
        // A5: every broker request the tool's command makes is attributed to *this* tool, so
        // the capability manifest checked at the broker/proxy is the one that acted. A program
        // inside the VM cannot name itself; this wrapper is the only place that can.
        let name = self.inner.spec().name;
        if !env.sandboxed(&ctx.session_id) {
            return super::vm::with_component(&name, || self.inner.call(ctx, input));
        }
        if !env.cfg.sandbox.tools.allows(&name) {
            return ToolOutput::err(format!("tool `{name}` is not available inside the sandbox (exec.sandbox.tools); ask the operator to allow it or run outside the sandbox"));
        }
        let sctx = sandbox_ctx(&env, ctx);
        if env.cfg.sandbox.workspace_access == "ro" {
            for e in self.inner.effects(&sctx, &input) {
                if let Effect::Write { path } = e {
                    if path.starts_with(&ctx.workspace) {
                        return ToolOutput::err(format!("{} is read-only inside the sandbox (exec.sandbox.workspace_access = \"ro\")", path.display()));
                    }
                }
            }
        }
        super::vm::with_component(&name, || self.inner.call(&sctx, input))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::ExecConfig;
    use crate::testutil::ctx;
    use serde_json::json;

    #[test]
    fn tool_policy_defaults_and_overrides() {
        let p = ToolPolicy::default();
        assert!(p.allows("shell") && p.allows("read") && p.allows("mcp__x__y"));
        assert!(!p.allows("node_invoke") && !p.allows("channel_send") && !p.allows("a2a_send"));
        let p = ToolPolicy { allow: vec!["channel_send".into(), "mcp__fs__*".into()], deny: vec!["shell".into()] };
        assert!(p.allows("channel_send") && p.allows("mcp__fs__read"));
        assert!(!p.allows("shell"), "deny wins");
        assert!(!p.allows("mcp__web__get"), "explicit allow list: unknown tools refused");
        assert!(p.allows("read"), "defaults still allowed");
    }

    #[test]
    fn env_scrub_and_forward_rules() {
        assert!(is_secret_env("OPENAI_API_KEY") && is_secret_env("GITHUB_TOKEN") && is_secret_env("DB_PASSWORD") && is_secret_env("AWS_SECRET_ACCESS_KEY") && is_secret_env("MODAL_TOKEN_ID"));
        assert!(!is_secret_env("PATH") && !is_secret_env("HOME") && !is_secret_env("LC_ALL") && !is_secret_env("EDITOR"));
        // `env_passthrough` relaxes the credential-*shape* heuristic (a name whose value is
        // metadata) and nothing more: an seagent-managed credential stays out.
        let (kept, blocked) = sanitize_forwarded(&[("A".into(), "1".into()), ("X_TOKEN".into(), "t".into()), ("B".into(), "Q".repeat(100)), ("X_TOKEN2".into(), "z".into())], &["X_TOKEN".into()]);
        assert_eq!(kept, vec![("A".to_string(), "1".to_string()), ("X_TOKEN".to_string(), "t".to_string()), ("X_TOKEN2".to_string(), "z".to_string())]);
        assert_eq!(blocked, vec!["B".to_string()]);
        let (kept, blocked) = sanitize_forwarded(&[("GITHUB_TOKEN".into(), "g".into()), ("OPENAI_API_KEY".into(), "k".into()), ("TELEGRAM_BOT_TOKEN".into(), "b".into())], &["GITHUB_TOKEN".into(), "OPENAI_API_KEY".into(), "TELEGRAM_BOT_TOKEN".into()]);
        assert!(kept.is_empty(), "a passthrough can never re-allow a credential: {kept:?}");
        assert_eq!(blocked, vec!["GITHUB_TOKEN".to_string(), "OPENAI_API_KEY".to_string(), "TELEGRAM_BOT_TOKEN".to_string()]);
        assert_eq!(unsafe_env_value("a\0b"), Some("contains null bytes"));
    }

    #[test]
    fn env_scrub_matches_the_security_layer() {
        // One rule set: `envscrub::is_blocked(Surface::Sandbox)` is what `sanitize_forwarded`
        // applies, so both must give the same verdict for the same name.
        let names = [
            "OPENAI_API_KEY", "GITHUB_TOKEN", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "VERCEL_TOKEN", "SSH_AUTH_SOCK", "SEAGENT_CALL_SOCK", "AZURE_OPENAI_KEY", "MODAL_TOKEN_ID", "MY_OWN_KEY", "PATH", "HOME",
            "LANG", "LC_ALL", "EDITOR", "TERM", "VIRTUAL_ENV",
        ];
        let vars: Vec<(String, String)> = names.iter().map(|n| (n.to_string(), "v".to_string())).collect();
        let (kept, blocked) = sanitize_forwarded(&vars, &[]);
        for n in names {
            let rule = seagent_security::envscrub::is_blocked(n, seagent_security::envscrub::Surface::Sandbox);
            assert_eq!(is_secret_env(n), rule, "{n}: is_secret_env is the shared rule");
            assert_eq!(blocked.iter().any(|b| b == n), rule, "{n}: sanitize_forwarded follows it");
            assert_eq!(kept.iter().any(|(k, _)| k == n), !rule, "{n}");
        }
        // An explicit passthrough wins for a shape-only name; a Tier-1 secret it cannot lift
        // stays blocked. An unsafe value is refused.
        let (kept, blocked) = sanitize_forwarded(&[("X_TOKEN".into(), "t".into()), ("B".into(), "Q".repeat(100)), ("GITHUB_TOKEN".into(), "g".into())], &["X_TOKEN".into(), "GITHUB_TOKEN".into()]);
        assert_eq!(blocked, vec!["B".to_string(), "GITHUB_TOKEN".to_string()], "a base64-shaped value and a Tier-1 secret are refused");
        assert_eq!(kept, vec![("X_TOKEN".to_string(), "t".to_string())]);
    }

    #[test]
    fn credential_files_become_read_only_binds_and_dangerous_ones_are_refused() {
        let home = crate::testutil::tmpdir("credbinds");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        std::fs::write(home.join(".ssh/id_rsa"), "k").unwrap();
        std::fs::create_dir_all(home.join(".config/gh")).unwrap();
        std::fs::write(home.join(".config/gh/hosts.yml"), "x").unwrap();
        std::fs::write(home.join("api-token"), "t").unwrap();
        let entries: Vec<String> = ["api-token", ".config/gh/hosts.yml", ".ssh/id_rsa", "/etc/passwd", "../x", "missing"].iter().map(|s| s.to_string()).collect();
        let (binds, errs) = credential_binds(&entries, "/home/seagent", &home);
        // `layout::canonicalize` = std on Unix; no `\\?\` prefix on Windows (like the binds).
        let canon = |p: &str| seagent_core::platform::layout::canonicalize(&home.join(p)).unwrap();
        assert_eq!(
            binds,
            vec![
                (canon("api-token"), "/home/seagent/api-token".to_string(), true),
                (canon(".config/gh/hosts.yml"), "/home/seagent/.config/gh/hosts.yml".to_string(), true),
            ],
            "a legal file (even under ~/.config) is mounted read-only"
        );
        assert!(binds.iter().all(|(_, _, ro)| *ro));
        for (needle, why) in [(".ssh/id_rsa", "exposes ~/.ssh"), ("/etc/passwd", "must be relative"), ("../x", "traversal"), ("missing", "does not exist")] {
            // Windows prints the refused host path with `\`.
            assert!(errs.iter().any(|e| e.replace('\\', "/").contains(needle) && e.contains(why)), "{needle}/{why}: {errs:?}");
        }
        assert_eq!(errs.len(), 4, "{errs:?}");
        assert_eq!(credential_binds(&[], "/home/seagent", &home), (vec![], vec![]), "nothing configured: nothing mounted");
    }

    /// Windows counterpart of `dangerous_binds_refused`: drive-letter sources, the system
    /// directory, ProgramData, the Docker engine pipe, a drive root and the profile.
    #[cfg(windows)]
    #[test]
    fn dangerous_windows_binds_refused() {
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        assert!(parse_bind(&format!(r"{sysroot}:/x")).is_err());
        assert!(parse_bind(&format!(r"{sysroot}\System32\config:/x")).is_err());
        assert!(parse_bind(r"C:\:/x").is_err(), "a drive root is the host root");
        assert!(parse_bind(r"\\.\pipe\docker_engine:/var/run/docker.sock").is_err());
        assert!(parse_bind(r"relative:/x").is_err());
        let tmp = crate::testutil::tmpdir("winbind");
        assert!(parse_bind(&format!("{}:x", tmp.display())).is_err(), "container side must be absolute");
        let profile = std::env::var("USERPROFILE").unwrap();
        assert!(parse_bind(&format!(r"{profile}\.ssh:/k")).is_err());
        assert!(parse_bind(&format!(r"{profile}\AppData\Local:/k")).is_err());
        assert!(parse_bind(&format!("{profile}:/h")).is_err());
        let (src, dst, ro) = parse_bind(&format!("{}:/data:ro", tmp.display())).unwrap();
        assert_eq!((src, dst.as_str(), ro), (tmp.clone(), "/data", true));
        let (src, _, ro) = parse_bind(&format!("{}:/data", tmp.display().to_string().replace('\\', "/"))).unwrap();
        assert_eq!((src, ro), (PathBuf::from(tmp.display().to_string().replace('\\', "/")), false));
        let e = ExecConfig::parse(&json!({"sandbox": {"binds": [format!("{sysroot}:/x")]}})).unwrap_err();
        assert!(e.contains("refusing to bind-mount"), "{e}");
        assert!(ExecConfig::parse(&json!({"sandbox": {"binds": [format!("{}:/data:ro", tmp.display())]}})).is_ok());
    }

    // Unix host paths (`/etc`, `/var/run/docker.sock`); Windows: `dangerous_windows_binds_refused`.
    #[cfg(unix)]
    #[test]
    fn dangerous_binds_refused() {
        // `/tmp` binds are judged against the ambient HOME (see `testutil::home_lock`).
        let _home = crate::testutil::home_lock();
        assert!(parse_bind("/etc:/x").is_err());
        assert!(parse_bind("/:/x").is_err());
        assert!(parse_bind("/var/run/docker.sock:/var/run/docker.sock").is_err());
        assert!(parse_bind("relative:/x").is_err());
        assert!(parse_bind("/tmp:x").is_err());
        if let Some(h) = std::env::var_os("HOME") {
            assert!(parse_bind(&format!("{}/.ssh:/k", Path::new(&h).display())).is_err());
            assert!(parse_bind(&format!("{}:/h", Path::new(&h).display())).is_err());
        }
        let (src, dst, ro) = parse_bind("/tmp:/data:ro").unwrap();
        assert_eq!((src, dst.as_str(), ro), (PathBuf::from("/tmp"), "/data", true));
        assert!(SandboxConfig { backend: "local".into(), ..Default::default() }.validate().is_err());
    }

    // Unix host paths; Windows: `dangerous_windows_binds_refused` covers the config path too.
    #[cfg(unix)]
    #[test]
    fn sandbox_config_refuses_dangerous_binds() {
        let _home = crate::testutil::home_lock();
        // `[exec.sandbox] binds = ["/etc:/x"]` must not deserialize into a usable config,
        // and must be refused again when a container is built from it.
        let e = ExecConfig::parse(&json!({"sandbox": {"binds": ["/etc:/x"]}})).unwrap_err();
        assert!(e.contains("refusing to bind-mount") && e.contains("/etc"), "{e}");
        let e = ExecConfig::parse(&json!({"sandbox": {"binds": ["/var/run/docker.sock:/s"]}})).unwrap_err();
        assert!(e.contains("refusing to bind-mount"), "{e}");
        let sb = SandboxConfig { binds: vec!["/etc:/x".into()], ..Default::default() };
        assert!(sb.validate().is_err());
        assert!(ExecConfig::parse(&json!({"sandbox": {"binds": ["/tmp:/data:ro"]}})).is_ok());
    }

    /// A sandboxed environment for exactly one session id (`mode = "non-main"` plus a
    /// classifier that keeps every other session main), pinned into the wrapper: tests
    /// must not swap the process-wide `exec::global()`, which other modules' persistent
    /// shell state is keyed on.
    fn sandboxed_env(workspace_access: &str, deny: &[&str]) -> Arc<ExecEnv> {
        let mut cfg = ExecConfig::default();
        cfg.sandbox.mode = "non-main".into();
        cfg.sandbox.workspace_access = workspace_access.into();
        cfg.sandbox.tools.deny = deny.iter().map(|s| s.to_string()).collect();
        let env = Arc::new(ExecEnv::new(cfg));
        env.set_classifier(Arc::new(|s: &str| !s.contains("sbxwrap")));
        env
    }

    #[test]
    fn wrapper_enforces_policy_and_workspace_access() {
        let c = ctx("sbxwrap");
        // ro: a denied tool is refused, and writes inside the real workspace are read-only.
        let env = sandboxed_env("ro", &["write"]);
        let tools = wrap_with(vec![Arc::new(crate::Write), Arc::new(crate::Edit)], Some(env.clone()));
        let (w, e) = (tools[0].clone(), tools[1].clone());
        assert!(w.call(&c, json!({"path":"a.txt","content":"x"})).content.contains("not available inside the sandbox"));
        std::fs::write(c.workspace.join("b.txt"), "one").unwrap();
        let o = e.call(&c, json!({"path":"b.txt","old_string":"one","new_string":"two"}));
        assert!(o.is_error && o.content.contains("read-only inside the sandbox"), "{}", o.content);
        // none: file tools see the private scratch workspace.
        let env = sandboxed_env("none", &[]);
        let key = env.scope_key(&c.session_id, &c.workspace);
        let w = wrap_with(vec![Arc::new(crate::Write)], Some(env))[0].clone();
        assert!(!w.call(&c, json!({"path":"n.txt","content":"x"})).is_error);
        assert!(!c.workspace.join("n.txt").exists());
        assert!(c.home.join("sandboxes").join(key).join("workspace/n.txt").exists());
        // Unsandboxed: untouched.
        let h = ctx("plainhost");
        assert!(!w.call(&h, json!({"path":"m.txt","content":"x"})).is_error);
        assert!(h.workspace.join("m.txt").exists());
    }

    /// `[exec.sandbox] scope = "agent"`: one sandbox per workspace, shared by every session in
    /// that workspace and isolated from another workspace. `session` and `shared` were covered;
    /// this is the third value the config offers.
    #[test]
    fn agent_scope_shares_one_sandbox_per_workspace() {
        let a = ctx("sbxagent");
        let mut b = crate::testutil::ctx_with(a.workspace.clone(), Arc::new(crate::testutil::FakeHost::default()));
        b.session_id = format!("{}-second", a.session_id);
        assert_ne!(a.session_id, b.session_id);
        assert_eq!(a.workspace, b.workspace);
        let other = ctx("sbxagent-elsewhere");

        let env = |scope: &str| {
            let mut cfg = ExecConfig::default();
            cfg.sandbox.mode = "non-main".into();
            cfg.sandbox.scope = scope.into();
            cfg.sandbox.workspace_access = "none".into();
            let env = Arc::new(ExecEnv::new(cfg));
            env.set_classifier(Arc::new(|s: &str| !s.contains("sbxagent")));
            env
        };
        let scratch = |e: &Arc<ExecEnv>, c: &ToolCtx| e.cfg.sandbox.scratch_workspace(&c.home, &e.scope_key(&c.session_id, &c.workspace));

        let agent = env("agent");
        let key = agent.scope_key(&a.session_id, &a.workspace);
        assert_eq!(key, agent.scope_key(&b.session_id, &b.workspace), "one sandbox per workspace, not per session");
        assert_ne!(key, agent.scope_key(&other.session_id, &other.workspace), "another workspace gets its own sandbox");
        assert!(key.starts_with("ws-") && key.len() == 15, "workspace-keyed name: {key}");

        let w = wrap_with(vec![Arc::new(crate::Write)], Some(agent.clone()))[0].clone();
        let o = w.call(&a, json!({"path": "shared.txt", "content": "x"}));
        assert!(!o.is_error, "{}", o.content);
        assert!(!a.workspace.join("shared.txt").exists(), "nothing is written to the real workspace");
        assert!(scratch(&agent, &a).join("shared.txt").exists(), "the file landed in the scope's sandbox");
        assert_eq!(scratch(&agent, &a), scratch(&agent, &b), "session B shares session A's sandbox (that is the point of `agent`)");
        assert_ne!(scratch(&agent, &a), scratch(&agent, &other), "another workspace cannot see it");

        // Contrast: `session` keeps two sessions of the same workspace apart; `shared` is one
        // sandbox for every session and workspace.
        let sess = env("session");
        assert_ne!(sess.scope_key(&a.session_id, &a.workspace), sess.scope_key(&b.session_id, &b.workspace));
        assert_ne!(scratch(&sess, &a), scratch(&sess, &b));
        let shared = env("shared");
        assert_eq!(shared.scope_key(&a.session_id, &a.workspace), "shared");
        assert_eq!(shared.scope_key(&a.session_id, &a.workspace), shared.scope_key(&other.session_id, &other.workspace), "one sandbox for every session and workspace");
    }

    #[test]
    fn wrapper_follows_the_installed_environment() {
        // The policy is read on every call, not captured when the tools are wrapped:
        // `wrap_all` has no environment, so `/exec host=sandbox` on the *installed*
        // environment sandboxes a session that was not sandboxed a moment ago.
        let c = ctx("sbxwrap-global");
        let g = crate::exec::global();
        let w = wrap_all(vec![Arc::new(crate::Write)])[0].clone();
        assert!(!g.sandboxed(&c.session_id) || g.cfg.sandbox.mode != "off", "precondition: not sandboxed yet");
        g.set_override(&c.session_id, Some(Some("sandbox".into())), None);
        assert!(g.sandboxed(&c.session_id), "/exec host=sandbox opts in");
        let o = w.call(&c, json!({"path":"g.txt","content":"x"}));
        assert!(!o.is_error, "{}", o.content);
        let key = g.scope_key(&c.session_id, &c.workspace);
        let scratch = if g.cfg.sandbox.workspace_access == "none" { c.home.join("sandboxes").join(&key).join("workspace/g.txt") } else { c.workspace.join("g.txt") };
        assert!(scratch.exists(), "the installed policy applied: {:?}", scratch);
        // Back on the host, the same wrapped tool writes the real workspace.
        g.set_override(&c.session_id, Some(Some("host".into())), None);
        assert!(!g.sandboxed(&c.session_id));
        let o = w.call(&c, json!({"path":"h.txt","content":"x"}));
        assert!(!o.is_error, "{}", o.content);
        assert!(c.workspace.join("h.txt").exists());
        g.set_override(&c.session_id, None, None);
        g.overrides.lock().unwrap().remove(&c.session_id);
    }
}
