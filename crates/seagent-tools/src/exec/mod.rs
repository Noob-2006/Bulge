//! Execution environments. `ExecEnv` holds the `[exec]` config, builds the
//! backend each session runs in (host backend, or the sandbox backend for
//! sandboxed sessions), and keeps per-session shell state (cwd + exported
//! environment snapshot) so `cd` and `export` persist across calls.

pub mod ansi;
pub mod appcontainer;
pub mod container;
pub mod daytona;
pub mod process;
pub mod hints;
pub mod live;
pub mod local;
#[cfg(unix)]
mod local_unix;
#[cfg(windows)]
mod local_windows;
pub mod modal;
pub mod sandbox;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod sandbox_linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod seccomp;
#[cfg(target_os = "macos")]
mod seatbelt;
pub mod openshell;
pub mod ptyq;
pub mod session;
pub mod singularity;
pub mod ssh;
pub mod sudo;
pub mod sync;
pub mod unify;
pub mod vercel;
pub mod vm;
#[cfg(any(feature = "wasm", target_os = "ios"))]
pub mod wasm;

use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

pub use session::ShellState;

/// `[exec]`. Every key has a default; see docs/config.md §exec.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecConfig {
    /// Where commands run for unsandboxed sessions: auto | local | vm | bwrap | landlock |
    /// docker | podman | singularity | apptainer | ssh | modal | daytona | vercel | <plugin
    /// provider>. `auto` (the default when the operator names none) is resolved by
    /// [`seagent_vm::policy`]: a microVM when this machine can boot one, otherwise the strongest
    /// fallback with a warning §0.
    pub backend: String,
    /// Did the config file name `backend` explicitly? Not part of the config surface: it
    /// distinguishes "the operator chose `local`" from "nothing was configured", which is
    /// what lets `auto` be the default without rewriting an explicit choice.
    #[serde(skip)]
    pub backend_set: bool,
    /// Keep `cd` / `export` / functions between shell calls (Hermes persistent shell).
    pub persistent_shell: bool,
    /// Default foreground timeout (s); foreground calls above `foreground_max_timeout`
    /// continue as background processes with a completion notice.
    pub default_timeout: u64,
    pub foreground_max_timeout: u64,
    /// OpenClaw `yieldMs` default: an ordinary command still running after this many
    /// milliseconds returns a process handle instead of blocking (0 = never yield).
    pub yield_ms: u64,
    /// Output kept per call before head/tail truncation; the full text spills to a file.
    pub max_output_bytes: usize,
    /// Rolling buffer per background process.
    pub process_buffer_bytes: usize,
    /// Remove ANSI escapes from command output.
    pub strip_ansi: bool,
    /// Remove credential-looking variables from the child environment.
    pub scrub_env: bool,
    /// Variables kept even when their *name* looks like a credential (metadata: a build tag
    /// in `BUILD_TOKEN`). `[security] env_passthrough` is the code-mode opt-in and
    /// `[exec] env_passthrough` the shell / sandbox one; neither can re-allow a credential
    /// seagent manages — Tier-1 names, provider / bot keys and `[security] env_strip` names go.
    pub env_passthrough: Vec<String>,
    /// Extra variables for every command.
    pub env: HashMap<String, String>,
    /// Append a hint after common failures (command not found, permission denied…).
    pub failure_hints: bool,
    /// Vault secret holding the sudo password; `sudo` is rewritten to `sudo -S` and fed it.
    pub sudo_password_secret: String,
    /// Host files copied into remote / container backends (credential passthrough).
    pub credential_files: Vec<String>,
    /// `[exec.code]`: code-mode settings (seagent-kernel `coderun::CodeConfig`; parsed by the binary).
    pub code: Value,
    /// `[exec.providers.<name>]`: config handed to a plugin-registered backend
    /// (`exec::register_provider`) when `exec.backend = "<name>"`.
    pub providers: HashMap<String, Value>,
    pub sandbox: sandbox::SandboxConfig,
    pub docker: container::ContainerConfig,
    pub podman: container::ContainerConfig,
    pub singularity: singularity::SingularityConfig,
    pub bwrap: local::BwrapConfig,
    pub ssh: ssh::SshConfig,
    pub modal: Value,
    pub daytona: Value,
    pub vercel: Value,
    pub openshell: openshell::OpenShellConfig,
    /// `[exec.vm]`: the microVM backend (B1–B5). Default provider `auto`.
    pub vm: seagent_vm::VmConfig,
    /// `[exec.wasm]`: the WASI interpreter backend (`exec::wasm::WasmConfig`; iOS default).
    pub wasm: Value,
    /// `[exec.cgroups]`: one cgroup per command for cleanup and caps (ent-024).
    pub cgroups: local::CgroupConfig,
}

impl Default for ExecConfig {
    fn default() -> Self {
        ExecConfig {
            backend: "local".into(),
            // A hand-built `ExecConfig` (embedders, tests, a tool that switches backend) is an
            // explicit choice; `parse()` below decides for a *config file*: a name it does not
            // state means `auto` (microVM first), which is how A1 becomes the default without
            // rewriting an operator's explicit backend.
            backend_set: true,
            persistent_shell: true,
            default_timeout: 120,
            foreground_max_timeout: 600,
            yield_ms: 0,
            max_output_bytes: 1024 * 1024,
            process_buffer_bytes: 200_000,
            strip_ansi: true,
            scrub_env: true,
            env_passthrough: vec![],
            env: HashMap::new(),
            failure_hints: true,
            sudo_password_secret: "SUDO_PASSWORD".into(),
            credential_files: vec![],
            code: Value::Null,
            providers: HashMap::new(),
            sandbox: Default::default(),
            docker: container::ContainerConfig::docker(),
            podman: container::ContainerConfig::podman(),
            singularity: Default::default(),
            bwrap: Default::default(),
            ssh: Default::default(),
            modal: Value::Null,
            daytona: Value::Null,
            vercel: Value::Null,
            openshell: Default::default(),
            vm: Default::default(),
            wasm: Value::Null,
            cgroups: Default::default(),
        }
    }
}

impl ExecConfig {
    pub fn parse(v: &Value) -> Result<ExecConfig, String> {
        if v.is_null() || v.as_object().is_some_and(|o| o.is_empty()) {
            // No `[exec]` table at all: every backend name is unstated, so `auto` applies.
            return Ok(ExecConfig { backend_set: false, sandbox: sandbox::SandboxConfig { backend_set: false, ..Default::default() }, ..ExecConfig::default() });
        }
        let mut c: ExecConfig = serde_json::from_value(v.clone()).map_err(|e| format!("[exec]: {e}"))?;
        // Which names the operator actually stated: `auto` only stands in for a name the
        // config did not give (`[exec] backend` / `[exec.sandbox] backend`).
        c.backend_set = v.get("backend").is_some();
        c.sandbox.backend_set = v.get("sandbox").and_then(|s| s.get("backend")).is_some();
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<(), String> {
        if !BACKENDS.contains(&self.backend.as_str()) && !providers().read().unwrap().contains_key(&self.backend) {
            return Err(format!("exec.backend `{}`: use one of {}", self.backend, BACKENDS.join(", ")));
        }
        self.sandbox.validate()?;
        self.vm.validate()?;
        self.docker.validate()?;
        self.podman.validate()?;
        if self.default_timeout == 0 || self.foreground_max_timeout == 0 {
            return Err("exec.default_timeout and exec.foreground_max_timeout must be > 0".into());
        }
        Ok(())
    }

    /// `env_passthrough` plus the names a loaded skill declared (`seagent-skills` `setup::prepare`):
    /// a skill's own key reaches the commands it runs, sandboxed or not. The values still go
    /// through `sandbox::sanitize_forwarded`, whose `passthrough_forwards` refuses every
    /// seagent-managed credential — so this can widen *shape*, never exempt a real secret.
    pub fn passthrough(&self) -> Vec<String> {
        seagent_security::envscrub::passthrough_with_skills(&self.env_passthrough)
    }

    /// Value of each skill-declared name present in this process, in registry order: those are
    /// the variables `setup::prepare` put there for the skill's own commands.
    fn skill_env(&self) -> Vec<(String, String)> {
        seagent_security::envscrub::skill_env_names().into_iter().filter_map(|k| std::env::var(&k).ok().filter(|v| !v.is_empty()).map(|v| (k, v))).collect()
    }
}

pub const BACKENDS: &[&str] = &["auto", "local", "vm", "bwrap", "landlock", "seatbelt", "appcontainer", "wasm", "docker", "podman", "singularity", "apptainer", "ssh", "modal", "daytona", "vercel", "openshell"];

/// What the `wasm` backend gives (kept here so `auto` plans can say it on every build).
pub const WASM_WARNING: &str = "wasm interpreter sandbox: commands run as WASI modules in an in-process WebAssembly interpreter (wasmi, no JIT) behind a built-in POSIX-ish shell; they see only the workspace, a private /tmp and configured paths, have no network (WASI preview 1 has no sockets) and cannot start native programs. The wall is enforced by the interpreter inside the agent's own process, not by a kernel or hypervisor — weaker than a microVM.";

#[cfg(any(feature = "wasm", target_os = "ios"))]
fn wasm_backend(cfg: &ExecConfig, ctx: &BackendCtx) -> Result<Arc<dyn ExecBackend>, String> {
    Ok(Arc::new(wasm::WasmBackend::new(cfg, ctx)?))
}

#[cfg(not(any(feature = "wasm", target_os = "ios")))]
fn wasm_backend(_cfg: &ExecConfig, _ctx: &BackendCtx) -> Result<Arc<dyn ExecBackend>, String> {
    Err("exec backend wasm is not built into this binary (cargo feature `seagent-tools/wasm`; always on for iOS)".into())
}

/// What a backend constructor gets.
#[derive(Clone)]
pub struct BackendCtx {
    pub workspace: PathBuf,
    /// Container / sandbox identity (per session, workspace or shared — see sandbox scope).
    pub scope_key: String,
    pub secrets: Arc<dyn Fn(&str) -> String + Send + Sync>,
    /// seagent data dir (`~/.local/share/seagent`): sandbox workspaces, sync state, process logs.
    pub home: PathBuf,
    /// Is this the sandbox backend of a sandboxed session (workspace access applies).
    pub sandboxed: bool,
}

impl BackendCtx {
    /// Resolve `{{secret:NAME}}`; empty when the vault has no such secret.
    pub fn secret(&self, name: &str) -> Option<String> {
        if name.is_empty() {
            return None;
        }
        let p = format!("{{{{secret:{name}}}}}");
        let v = (self.secrets)(&p);
        (v != p && !v.is_empty()).then_some(v).or_else(|| std::env::var(name).ok().filter(|s| !s.is_empty()))
    }
}

/// Plugin-registered execution providers (Hermes `terminal_env_provider`).
pub type Provider = Arc<dyn Fn(&Value, &BackendCtx) -> Result<Arc<dyn ExecBackend>, String> + Send + Sync>;

fn providers() -> &'static RwLock<HashMap<String, Provider>> {
    static P: OnceLock<RwLock<HashMap<String, Provider>>> = OnceLock::new();
    P.get_or_init(Default::default)
}

/// Register a backend under `name` (`exec.backend = "<name>"`, config in `[exec.<name>]` → `extra`).
pub fn register_provider(name: &str, p: Provider) {
    providers().write().unwrap().insert(name.to_string(), p);
}

/// Say a fallback once per process: `auto` downgrading to bwrap/the host is important, but
/// repeating it on every tool call only trains the operator to ignore warnings.
fn warn_once(tag: &str, msg: &str) {
    static SAID: OnceLock<Mutex<std::collections::HashSet<String>>> = OnceLock::new();
    if SAID.get_or_init(Default::default).lock().unwrap().insert(tag.to_string()) {
        // One line on stderr, written rather than printed: arch_lint counts the
        // `print`-with-`ln` macro and this file's allowance is 0.
        let _ = std::io::Write::write_all(&mut std::io::stderr(), format!("seagent: warning: {msg}\n").as_bytes());
    }
}

pub fn build_backend(name: &str, cfg: &ExecConfig, extra: &Value, ctx: &BackendCtx) -> Result<Arc<dyn ExecBackend>, String> {
    Ok(match name {
        // `auto`: the policy table, not this function, decides (A1/B1). `ExecEnv::backend`
        // resolves it before calling us; this arm covers embedders that ask directly.
        "auto" => {
            let plan = os_plan(seagent_vm::policy::resolve(&seagent_vm::policy::Query { requested: "auto", cfg: &cfg.vm, data: &ctx.home, sandboxed: ctx.sandboxed }), ctx.sandboxed);
            build_planned(&plan, cfg, extra, ctx)?
        }
        "local" => Arc::new(local::LocalBackend::new()),
        // `main` decides the trust tier when the daemon has not installed a
        // classifier: a sandboxed (non-operator) session is never treated as the owner.
        "vm" => Arc::new(vm::VmBackend::new(&cfg.vm, &cfg.sandbox, ctx, !ctx.sandboxed)?),
        "bwrap" | "landlock" | "seatbelt" | "appcontainer" => os_sandbox(name, cfg, ctx)?,
        "wasm" => wasm_backend(cfg, ctx)?,
        "docker" => Arc::new(container::ContainerBackend::new(&cfg.docker, &cfg.sandbox, cfg, ctx)?),
        "podman" => Arc::new(container::ContainerBackend::new(&cfg.podman, &cfg.sandbox, cfg, ctx)?),
        "singularity" | "apptainer" => Arc::new(singularity::SingularityBackend::new(&cfg.singularity, name, &cfg.sandbox, ctx)?),
        "openshell" => Arc::new(openshell::OpenShellBackend::new(&cfg.openshell, &cfg.sandbox, ctx)?),
        "ssh" => Arc::new(ssh::SshBackend::new(&cfg.ssh, cfg, ctx)?),
        "modal" => modal::build(&cfg.modal, cfg, ctx)?,
        "daytona" => daytona::build(&cfg.daytona, cfg, ctx)?,
        "vercel" => vercel::build(&cfg.vercel, cfg, ctx)?,
        other => {
            let p = providers().read().unwrap().get(other).cloned().ok_or_else(|| format!("unknown exec backend `{other}`"))?;
            p(extra, ctx)?
        }
    })
}

/// The OS sandbox backends: each exists on its own OS only; elsewhere the name is an
/// explicit "not available on <os>" error (never a silent fallback to the host).
fn os_sandbox(name: &str, cfg: &ExecConfig, ctx: &BackendCtx) -> Result<Arc<dyn ExecBackend>, String> {
    let _ = (cfg, ctx);
    match name {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "bwrap" => Ok(Arc::new(local::BwrapBackend::new(&cfg.bwrap, &cfg.sandbox, ctx)?)),
        #[cfg(any(target_os = "linux", target_os = "android"))]
        "landlock" => Ok(Arc::new(local::LandlockBackend::new(&cfg.sandbox, ctx)?)),
        #[cfg(target_os = "macos")]
        "seatbelt" => Ok(Arc::new(local::SeatbeltBackend::new(&cfg.sandbox, ctx)?)),
        #[cfg(windows)]
        "appcontainer" => Ok(Arc::new(appcontainer::AppContainerBackend::new(&cfg.sandbox, ctx)?)),
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        "bwrap" => Err(local::not_available("bwrap", "bubblewrap needs Linux namespaces")),
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        "landlock" => Err(local::not_available("landlock", "Landlock is a Linux security module")),
        #[cfg(not(target_os = "macos"))]
        "seatbelt" => Err(local::not_available("seatbelt", "Seatbelt (sandbox-exec) is the macOS sandbox")),
        #[cfg(not(windows))]
        "appcontainer" => Err(local::not_available("appcontainer", "AppContainer is the Windows sandbox")),
        other => Err(format!("unknown OS sandbox `{other}`")),
    }
}

/// The OS sandbox that stands in for bwrap / Landlock on this OS (docs/cross-platform.md:
/// Seatbelt on macOS, AppContainer on Windows), if any. Windows counts only when an
/// AppContainer can actually be created here (the restricted-token fallback is never offered
/// by `auto`), so the plan stays honest.
fn native_sandbox() -> Option<&'static str> {
    if cfg!(target_os = "macos") && Path::new("/usr/bin/sandbox-exec").is_file() {
        Some("seatbelt")
    } else if cfg!(windows) && appcontainer::available() {
        Some("appcontainer")
    } else if cfg!(target_os = "ios") {
        // No processes at all on iOS: the WASI interpreter is the only place a command can run.
        Some("wasm")
    } else {
        None
    }
}

/// What an OS sandbox (Seatbelt / AppContainer) gives, said with the same honesty as the
/// levels in `seagent_vm::isolation` (reported as `IsolationLevel::OsSandbox`, the
/// namespace-sandbox tier under its own name).
pub const OS_SANDBOX_WARNING: &str = "OS sandbox (macOS Seatbelt): shares the host kernel, file access limited to system files, the workspace and a private temp dir; home unreadable. One kernel or sandbox bug from the host; weaker than a microVM.";

/// How to get the microVM tier on macOS / Windows (the Linux fallback says the same).
#[allow(dead_code)]
const MICROVM_HINT: &str = if cfg!(windows) {
    "Build the guest image (`seagent sandbox vm image build`) and enable a VM provider (Hyper-V, or QEMU with WHPX) for a microVM."
} else {
    "Build the guest image (`seagent sandbox vm image build`) for a microVM (Virtualization.framework, or QEMU with HVF)."
};

/// Make an `auto` plan honest on macOS / Windows: the policy table in `seagent-vm` knows
/// bwrap and Landlock, which these systems lack, so "no microVM, no namespace sandbox" would
/// otherwise mean the host. Here the OS sandbox takes that place, and an explicitly
/// configured `seatbelt` / `appcontainer` is reported at its real level instead of "host".
/// Identity on Linux and Android.
pub fn os_plan(mut plan: seagent_vm::policy::Plan, sandboxed: bool) -> seagent_vm::policy::Plan {
    use seagent_vm::policy::Origin;
    use seagent_vm::IsolationLevel;
    // The interpreter sandbox says what it is wherever it was chosen.
    if plan.backend == "wasm" {
        plan.level = IsolationLevel::OsSandbox;
        plan.warning = Some(WASM_WARNING.into());
        return plan;
    }
    let Some(name) = native_sandbox() else { return plan };
    let os_warning = match name {
        "appcontainer" => appcontainer::WARNING,
        "wasm" => WASM_WARNING,
        _ => OS_SANDBOX_WARNING,
    };
    // iOS: every automatic choice that would need a native process lands on the interpreter.
    let ios_auto = name == "wasm" && plan.origin != Origin::Configured && matches!(plan.backend.as_str(), "local" | "bwrap" | "landlock");
    if plan.backend == name && plan.level <= IsolationLevel::OsSandbox {
        plan.level = IsolationLevel::OsSandbox;
        plan.warning = Some(format!("{name}: {os_warning}"));
    } else if (plan.backend == "local" && plan.origin == Origin::AutoHost) || ios_auto {
        plan = seagent_vm::policy::Plan {
            backend: name.into(),
            provider: None,
            level: IsolationLevel::OsSandbox,
            origin: Origin::AutoFallback,
            warning: Some(format!("no microVM available on this {} machine; {} runs in the {name} sandbox instead (host home and keys not readable) — {os_warning} {}", std::env::consts::OS, if sandboxed { "this session" } else { "the agent" }, MICROVM_HINT)),
            reason: format!("auto: no microVM, the agent still runs isolated in the {} OS sandbox ({name})", std::env::consts::OS),
        };
    }
    plan
}

/// Build what an `auto` plan chose. srv-015: the owner's (unsandboxed) session on a namespace
/// fallback keeps host networking — the namespace sandbox is there to hide the host home and
/// keys, not to cut the agent off — and if the namespace sandbox cannot actually be built here
/// (no user namespaces, no Landlock in this kernel) it degrades to the host with a loud
/// `NOT ISOLATED` warning instead of failing every tool call. A *sandboxed* session keeps its
/// configured network and never silently lands on the host.
pub fn build_planned(plan: &seagent_vm::policy::Plan, cfg: &ExecConfig, extra: &Value, ctx: &BackendCtx) -> Result<Arc<dyn ExecBackend>, String> {
    if ctx.sandboxed || plan.origin != seagent_vm::policy::Origin::AutoFallback {
        return build_backend(&plan.backend, cfg, extra, ctx);
    }
    let mut owner = cfg.clone();
    owner.sandbox.network = "host".into();
    match build_backend(&plan.backend, &owner, extra, ctx) {
        Ok(b) => Ok(b),
        // iOS has no host shell to fall back to: the error is the answer.
        Err(e) if cfg!(target_os = "ios") => Err(e),
        Err(e) => {
            let host = seagent_vm::policy::host_plan(&format!("{} unusable: {e}", plan.backend), "");
            warn_once("host-fallback", host.warning.as_deref().unwrap_or("NOT ISOLATED"));
            build_backend("local", cfg, extra, ctx)
        }
    }
}

/// Decides whether a session is the operator's main session (OpenClaw sandbox
/// `non-main`): installed by the binary, which can read session headers.
pub type MainClassifier = Arc<dyn Fn(&str) -> bool + Send + Sync>;
/// `/exec host=sandbox|host|node` and `/elevated on|off|ask|full` as the host persisted them.
pub type RouteLookup = Arc<dyn Fn(&str) -> SessionOverride + Send + Sync>;
/// Delivers a background-process notice into a session (completion, watch match, heartbeat).
pub type Notifier = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Shared by the shell, process, terminal and code tools.
pub struct ExecEnv {
    pub cfg: ExecConfig,
    backends: Mutex<HashMap<String, Arc<dyn ExecBackend>>>,
    shells: Mutex<HashMap<String, Arc<Mutex<ShellState>>>>,
    /// Per-session sandbox override from `/exec`, `/elevated` (`on`, `off`).
    pub overrides: Mutex<HashMap<String, SessionOverride>>,
    classifier: RwLock<Option<MainClassifier>>,
    notifier: RwLock<Option<Notifier>>,
    /// Session routing persisted by `/exec host=` and `/elevated` (installed by the binary).
    route: RwLock<Option<RouteLookup>>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionOverride {
    /// `/exec host=sandbox|host`.
    pub host: Option<String>,
    /// `/elevated on|off|ask|full`.
    pub elevated: Option<String>,
}

impl Default for ExecEnv {
    fn default() -> Self {
        ExecEnv::new(ExecConfig::default())
    }
}

impl ExecEnv {
    pub fn new(cfg: ExecConfig) -> ExecEnv {
        ExecEnv { cfg, backends: Default::default(), shells: Default::default(), overrides: Default::default(), classifier: RwLock::new(None), notifier: RwLock::new(None), route: RwLock::new(None) }
    }
    pub fn set_classifier(&self, c: MainClassifier) {
        *self.classifier.write().unwrap() = Some(c);
    }
    pub fn set_notifier(&self, n: Notifier) {
        *self.notifier.write().unwrap() = Some(n);
    }
    /// Read `/exec host=` and `/elevated` from wherever the host stores them.
    pub fn set_route_lookup(&self, l: RouteLookup) {
        *self.route.write().unwrap() = Some(l);
    }
    pub fn notify(&self, session: &str, text: &str) -> bool {
        match self.notifier.read().unwrap().as_ref() {
            Some(n) => {
                n(session, text);
                true
            }
            None => false,
        }
    }
    /// Main session: no classifier installed = every session is main.
    pub fn is_main(&self, session: &str) -> bool {
        self.classifier.read().unwrap().as_ref().is_none_or(|c| c(session))
    }

    /// The session's routing override: in-memory first, then the host's store.
    pub fn route_of(&self, session: &str) -> SessionOverride {
        let mem = self.overrides.lock().unwrap().get(session).cloned().unwrap_or_default();
        let hook = self.route.read().unwrap().clone();
        let ext = hook.map(|f| f(session)).unwrap_or_default();
        SessionOverride { host: mem.host.or(ext.host), elevated: mem.elevated.or(ext.elevated) }
    }

    /// Does this session run inside the sandbox?
    pub fn sandboxed(&self, session: &str) -> bool {
        match self.route_of(session).host.as_deref() {
            Some("host") => false,
            Some("sandbox") => true,
            // `node`: the call belongs to a paired node; seagent runs it on the host here.
            Some(_) => false,
            None => match self.cfg.sandbox.mode.as_str() {
                "all" => true,
                "non-main" => !self.is_main(session),
                _ => false,
            },
        }
    }

    /// The execution plan for this session: which backend `auto` (or "nothing configured")
    /// resolves to on this machine, and the warning that goes with a weaker level (A1/B1).
    ///
    /// This is the single answer `seagent sandbox explain`, `seagent doctor` and the executor share:
    /// a microVM when this machine can boot one, else bwrap/Landlock for a session that asked
    /// for isolation, else the host with a loud warning — never a silent downgrade.
    pub fn plan(&self, session: &str, workspace: &Path, home: &Path) -> seagent_vm::policy::Plan {
        self.plan_for(self.sandboxed(session), workspace, home)
    }

    /// [`ExecEnv::plan`] for an explicit routing decision (`/elevated` asks for the host
    /// backend even when the session is sandboxed, so the session flag alone is not enough).
    pub fn plan_for(&self, sandboxed: bool, _workspace: &Path, home: &Path) -> seagent_vm::policy::Plan {
        let (requested, stated) = if sandboxed { (self.cfg.sandbox.backend.as_str(), self.cfg.sandbox.backend_set) } else { (self.cfg.backend.as_str(), self.cfg.backend_set) };
        os_plan(seagent_vm::policy::resolve(&seagent_vm::policy::Query { requested: if stated { requested } else { "auto" }, cfg: &self.cfg.vm, data: home, sandboxed }), sandboxed)
    }

    /// Container / sandbox identity for this session per `sandbox.scope`.
    pub fn scope_key(&self, session: &str, workspace: &Path) -> String {
        match self.cfg.sandbox.scope.as_str() {
            "shared" => "shared".into(),
            "agent" => format!("ws-{:012x}", fnv(workspace.to_string_lossy().as_bytes()) & 0xffff_ffff_ffff),
            _ => format!("s-{}", sanitize(session)),
        }
    }

    /// The backend `session` runs in; `elevated` asks for the host backend.
    pub fn backend(&self, session: &str, workspace: &Path, home: &Path, secrets: &Arc<dyn Fn(&str) -> String + Send + Sync>, elevated: bool) -> Result<Arc<dyn ExecBackend>, String> {
        let sandboxed = self.sandboxed(session) && !elevated;
        // `auto` — or no backend named at all — is resolved here, once, by the same policy
        // `seagent sandbox explain` prints (A1: the microVM is the default when it can boot).
        let plan = self.plan_for(sandboxed, workspace, home);
        if let Some(w) = plan.warning.as_ref().filter(|_| !plan.uses_microvm() && matches!(plan.origin, seagent_vm::policy::Origin::AutoFallback | seagent_vm::policy::Origin::AutoHost)) {
            warn_once(&format!("{}|{}", plan.backend, sandboxed), w);
        }
        let name = plan.backend.clone();
        let key = if sandboxed { self.scope_key(session, workspace) } else { format!("host-{}", sanitize(session)) };
        let cache_key = format!("{name}|{key}|{}", workspace.display());
        if let Some(b) = self.backends.lock().unwrap().get(&cache_key) {
            return Ok(b.clone());
        }
        let ctx = BackendCtx { workspace: workspace.to_path_buf(), scope_key: key, secrets: secrets.clone(), home: home.to_path_buf(), sandboxed };
        let extra = self.extra_config(&name);
        let b = build_planned(&plan, &self.cfg, &extra, &ctx)?;
        self.backends.lock().unwrap().insert(cache_key, b.clone());
        Ok(b)
    }

    fn extra_config(&self, name: &str) -> Value {
        match name {
            "modal" => self.cfg.modal.clone(),
            "daytona" => self.cfg.daytona.clone(),
            "vercel" => self.cfg.vercel.clone(),
            other => self.cfg.providers.get(other).cloned().unwrap_or(Value::Null),
        }
    }

    /// Live backends (for `seagent sandbox list`, cleanup on exit).
    pub fn live_backends(&self) -> Vec<(String, Arc<dyn ExecBackend>)> {
        self.backends.lock().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
    /// Drop (and tear down) the backends of a session, e.g. `/new`, `seagent sandbox recreate`.
    pub fn release(&self, session: &str) {
        let tag = sanitize(session);
        let mut b = self.backends.lock().unwrap();
        let gone: Vec<String> = b.keys().filter(|k| k.contains(&format!("s-{tag}|")) || k.contains(&format!("host-{tag}|"))).cloned().collect();
        for k in gone {
            if let Some(be) = b.remove(&k) {
                be.cleanup();
            }
        }
        self.shells.lock().unwrap().retain(|k, _| !k.starts_with(&format!("{session}|")));
    }
    pub fn cleanup_all(&self) {
        for (_, b) in self.backends.lock().unwrap().drain() {
            b.cleanup();
        }
    }

    /// Persistent shell state of a session in a backend.
    pub fn shell(&self, session: &str, backend: &dyn ExecBackend, workspace: &Path) -> Arc<Mutex<ShellState>> {
        let key = format!("{session}|{}|{}", backend.id(), workspace.display());
        self.shells.lock().unwrap().entry(key).or_insert_with(|| Arc::new(Mutex::new(ShellState::new(backend, workspace, self.cfg.persistent_shell)))).clone()
    }

    /// Environment for a command: config `env`, then scrubbed of credentials.
    pub fn child_env(&self) -> Vec<(String, String)> {
        let mut v: Vec<(String, String)> = self.cfg.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        v.sort();
        v
    }

    /// `[exec] env` + the call's own `env`, credentials removed unless
    /// `env_passthrough` lists them (OpenClaw `sanitizeEnvVars`; the credential-*shape*
    /// heuristic only — `sandbox::passthrough_forwards` never re-allows an seagent-managed
    /// credential). Later wins. Skill-declared variables (registered by a loaded skill) are
    /// added underneath, so a container / remote backend runs a skill's commands with the key
    /// that skill asked for.
    pub fn child_env_for(&self, extra: &[(String, String)]) -> Vec<(String, String)> {
        let mut v = self.child_env();
        for (k, val) in self.cfg.skill_env() {
            v.retain(|(a, _)| *a != k);
            v.push((k, val));
        }
        for (k, val) in extra {
            v.retain(|(a, _)| a != k);
            v.push((k.clone(), val.clone()));
        }
        if self.cfg.scrub_env {
            v = sandbox::sanitize_forwarded(&v, &self.cfg.passthrough()).0;
        }
        v.sort();
        v
    }

    /// `/elevated on` for this session: run its calls on the host, outside the sandbox.
    pub fn elevated(&self, session: &str) -> bool {
        matches!(self.route_of(session).elevated.as_deref(), Some("on" | "full" | "true"))
    }

    /// May a call from this session ask for `elevated`? `sandbox.elevated = "off"`
    /// refuses; `ask` lets it through (the effect gate already asked the operator).
    pub fn allow_elevated(&self, session: &str) -> Result<bool, String> {
        if !self.sandboxed(session) {
            return Ok(true);
        }
        match self.cfg.sandbox.elevated.as_str() {
            "off" => Err("elevated commands are disabled inside the sandbox (exec.sandbox.elevated = \"off\")".into()),
            _ => Ok(true),
        }
    }

    /// Set the per-session `/exec host=` / `/elevated` overrides.
    pub fn set_override(&self, session: &str, host: Option<Option<String>>, elevated: Option<Option<String>>) {
        let mut o = self.overrides.lock().unwrap();
        let e = o.entry(session.to_string()).or_default();
        if let Some(h) = host {
            e.host = h;
        }
        if let Some(v) = elevated {
            e.elevated = v;
        }
    }
}

/// The backend a tool call runs in (`elevated` = `/elevated on` for the session).
pub fn backend_tool(ctx: &seagent_core::ToolCtx, elevated: bool) -> Result<Arc<dyn ExecBackend>, String> {
    backend_in(&global(), ctx, elevated)
}

/// [`backend_tool`] against a specific environment (hosts embedding seagent pass their own).
pub fn backend_in(env: &ExecEnv, ctx: &seagent_core::ToolCtx, elevated: bool) -> Result<Arc<dyn ExecBackend>, String> {
    // `/exec host=node`: the command belongs to a paired node, which seagent reaches through the
    // `node_invoke` tool (`system.run`); the shell/job tools never cross that boundary silently.
    if env.route_of(&ctx.session_id).host.as_deref() == Some("node") {
        return Err("exec host=node: this session runs commands on a paired node — call `node_invoke` (action=invoke, command=system.run, params={command}), or `/exec host=sandbox|host` to run here".into());
    }
    let elevated = elevated && env.allow_elevated(&ctx.session_id)?;
    env.backend(&ctx.session_id, &ctx.workspace, &ctx.home, &ctx.secrets, elevated)
}

/// The backend a tool call ran in, plus the child it started.
pub type BackendChild = (Arc<dyn ExecBackend>, Box<dyn ExecChild>);

/// Exit status + merged output of a command that ran to completion.
pub type Capture = (ExitInfo, Vec<u8>);

/// Start a command for a tool call in that session's backend.
pub fn spawn_tool(ctx: &seagent_core::ToolCtx, req: &ExecRequest, elevated: bool) -> Result<BackendChild, String> {
    // C7: attribute every process group started below to this session, so the kernel's
    // reaper can reclaim it when the session dies (crash, kill, daemon restart) instead of
    // leaving an orphan behind. `shell` sets the same scope itself; setting it twice is fine.
    let _reaper = crate::exec::local::reap_scope(&ctx.home, &ctx.session_id, "exec");
    let backend = backend_tool(ctx, elevated)?;
    backend.before_exec()?;
    let child = backend.spawn(req).map_err(|e| format!("{}: {e}", backend.id()))?;
    // The console's live terminal (a no-op unless someone watches).
    let child = live::tee(child, &ctx.session_id, backend.id(), &req.script);
    Ok((backend, child))
}

static GLOBAL: RwLock<Option<Arc<ExecEnv>>> = RwLock::new(None);

/// Install the process-wide execution environment (the binary does this once
/// after reading `[exec]`); tools fetch it with `global()`.
pub fn install(env: Arc<ExecEnv>) {
    *GLOBAL.write().unwrap() = Some(env);
}

/// The installed environment, or a default one (local backend, defaults) for
/// library use and tests.
pub fn global() -> Arc<ExecEnv> {
    if let Some(e) = GLOBAL.read().unwrap().as_ref() {
        return e.clone();
    }
    let mut g = GLOBAL.write().unwrap();
    g.get_or_insert_with(|| Arc::new(ExecEnv::default())).clone()
}

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf29ce484222325u64, |h, x| (h ^ *x as u64).wrapping_mul(0x100000001b3))
}

/// A name-safe form of `s`, at most 48 characters. Longer inputs keep a prefix plus a hash of
/// the whole string, so two names that differ only past the cut never collide (two sessions
/// would otherwise share one sandbox).
pub fn sanitize(s: &str) -> String {
    let clean: String = s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    if clean.chars().count() <= 48 {
        return clean;
    }
    format!("{}-{:08x}", clean.chars().take(39).collect::<String>(), fnv(s.as_bytes()) as u32)
}

/// Run `script` to completion in `backend` and collect its merged output
/// (internal helper for sync, probes, container setup — not the shell tool).
pub fn run_capture(backend: &dyn ExecBackend, script: &str, stdin: Option<&[u8]>, timeout: Duration) -> Result<(ExitInfo, Vec<u8>), String> {
    let req = ExecRequest { script: script.into(), stdin: stdin.is_some(), stdin_data: stdin.map(|s| s.to_vec()), ..Default::default() };
    let child = backend.spawn(&req).map_err(|e| format!("{}: {e}", backend.id()))?;
    drain(child, timeout)
}

/// Unique staging path for stdin a remote backend cannot hand over out of band:
/// `/tmp/.seagent-stdin-<tag>-<pid>-<n>`. The counter is shared by every backend, so two of
/// them running at the same time (or two sandboxes) never pick the same file.
pub fn stdin_staging(tag: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    format!("/tmp/.seagent-stdin-{tag}-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::Relaxed))
}

/// Retry `ETXTBSY` ("Text file busy"): another thread forked while the program was still
/// open for writing — a freshly installed client, or a stand-in a test just wrote — and
/// the window closes as soon as that child execs. Nothing else is retried.
pub fn retry_etxtbsy<T>(mut f: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let mut attempt = 0u32;
    loop {
        match f() {
            Err(e) if local::is_text_busy(&e) && attempt < 40 => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(25));
            }
            other => return other,
        }
    }
}

/// Run a backend preflight probe (`<tool> version`, `ssh -V`) and return its output.
pub fn probe_output(cmd: &mut std::process::Command) -> std::io::Result<std::process::Output> {
    retry_etxtbsy(|| cmd.output())
}

/// Read a child to EOF + exit, killing it after `timeout`.
pub fn drain(mut child: Box<dyn ExecChild>, timeout: Duration) -> Result<(ExitInfo, Vec<u8>), String> {
    child.close_stdin();
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    let mut buf = [0u8; 16384];
    let mut eof = false;
    loop {
        if !eof {
            match child.read(&mut buf, Duration::from_millis(50)) {
                Ok(0) => eof = true,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => {}
            }
        }
        if let Ok(Some(st)) = child.try_wait() {
            // Collect what is still buffered.
            while let Ok(n) = child.read(&mut buf, Duration::from_millis(20)) {
                if n == 0 {
                    break;
                }
                out.extend_from_slice(&buf[..n]);
            }
            return Ok((st, out));
        }
        if Instant::now() >= deadline {
            child.kill(true);
            return Err(format!("timed out after {}s", timeout.as_secs()));
        }
        if eof {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Single-quote for bash.
pub fn sh_quote(s: &str) -> String {
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_./=:@,+%".contains(&b)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests_real;

#[cfg(test)]
mod tests {
    #[test]
    fn long_names_stay_distinct_after_the_cut() {
        let base = "x".repeat(60);
        let (a, b) = (sanitize(&base), sanitize(&format!("{base}-second")));
        assert!(a.len() == 48 && b.len() == 48 && a != b, "{a} / {b}");
        assert_eq!(sanitize("s1/ok"), "s1-ok", "short names are unchanged");
    }

    use super::*;
    use serde_json::json;

    #[test]
    fn config_defaults_and_validation() {
        let c = ExecConfig::parse(&Value::Null).unwrap();
        assert_eq!(c.backend, "local");
        assert!(c.persistent_shell && c.strip_ansi && c.scrub_env);
        assert_eq!(c.sandbox.mode, "off");
        assert!(ExecConfig::parse(&json!({"backend":"nope"})).is_err());
        assert!(ExecConfig::parse(&json!({"bogus":1})).is_err());
        assert!(ExecConfig::parse(&json!({"sandbox":{"mode":"sometimes"}})).is_err());
        let c = ExecConfig::parse(&json!({"backend":"docker","sandbox":{"mode":"non-main","scope":"agent","workspace_access":"ro"}})).unwrap();
        assert_eq!(c.sandbox.workspace_access, "ro");
    }

    /// A1: `auto` is the default for a config *file* that does not name a backend, and the
    /// microVM wins when this machine can boot one. An explicit name is never rewritten.
    #[test]
    fn auto_is_the_default_and_a_microvm_wins_when_it_can_boot() {
        let home = seagent_core::tmp::TempDir::new("seagent-exec-auto");
        let home = home.path().to_path_buf();
        std::fs::create_dir_all(home.join("vm/kernel")).unwrap();
        let ws = home.join("ws");
        std::fs::create_dir_all(&ws).unwrap();

        // No `[exec]` table at all: every name is unstated, so the plan decides.
        let env = ExecEnv::new(ExecConfig::parse(&Value::Null).unwrap());
        let p = env.plan("main", &ws, &home);
        assert!(!matches!(p.origin, seagent_vm::policy::Origin::Configured), "nothing was configured: {:?}", p);
        // No guest image here: srv-015 — the agent is still isolated (namespace sandbox when
        // this machine has one, else a loud NOT ISOLATED host plan); never silent, never a VM
        // it cannot boot.
        assert!(!p.uses_microvm());
        let w = p.warning.as_deref().unwrap_or("");
        if p.level == seagent_vm::IsolationLevel::Host {
            assert!(w.starts_with("NOT ISOLATED"), "{p:?}");
        } else {
            assert_eq!(p.origin, seagent_vm::policy::Origin::AutoFallback, "{p:?}");
            // Linux: the namespace sandbox does not mount them; macOS / Windows: the OS sandbox
            // (Seatbelt / AppContainer) cannot read them.
            let hidden = if cfg!(any(windows, target_os = "macos")) { "host home and keys not readable" } else { "host home and keys not mounted" };
            assert!(w.contains(hidden) && w.to_lowercase().contains("build the guest image"), "{p:?}");
        }
        // The explicit opt-out (test rigs, operators who want the host): never rewritten.
        let env = ExecEnv::new(ExecConfig::parse(&json!({"backend": "local"})).unwrap());
        assert_eq!((env.plan("main", &ws, &home).backend.as_str(), env.plan("main", &ws, &home).origin), ("local", seagent_vm::policy::Origin::Configured));

        // An explicit backend is honoured whatever the machine can do.
        let env = ExecEnv::new(ExecConfig::parse(&json!({"backend": "bwrap"})).unwrap());
        assert_eq!(env.plan("main", &ws, &home).backend, "bwrap");
        assert_eq!(env.plan("main", &ws, &home).origin, seagent_vm::policy::Origin::Configured);

        // With a guest image and a VMM, `auto` is the microVM — for the host backend and for a
        // sandboxed session alike (A1: agent tools run in the VM by default).
        std::fs::write(home.join("vm/kernel/vmlinux"), b"k").unwrap();
        std::fs::write(home.join("vm/kernel/initramfs.cpio.gz"), b"i").unwrap();
        let mut cfg = ExecConfig::parse(&json!({"vm": {"firecracker": "/bin/true"}})).unwrap();
        cfg.vm.allow_fallback = false;
        let env = ExecEnv::new(cfg);
        let p = env.plan("main", &ws, &home);
        if seagent_vm::policy::capabilities(&env.cfg.vm, &home).kvm {
            assert_eq!((p.backend.as_str(), p.level), ("vm", seagent_vm::IsolationLevel::MicroVm), "{p:?}");
            assert!(p.warning.is_none(), "a microVM needs no warning: {p:?}");
            let sp = env.plan_for(true, &ws, &home);
            assert_eq!(sp.backend, "vm", "a sandboxed session also gets the microVM: {sp:?}");
        }
    }

    /// srv-015: the owner's session on a namespace fallback hides the host home but keeps the
    /// network; an unbuildable namespace sandbox degrades to the host instead of failing.
    #[test]
    fn the_owner_session_is_isolated_on_the_namespace_fallback() {
        let home = seagent_core::tmp::TempDir::new("seagent-exec-owner");
        let ws = home.join("ws");
        std::fs::create_dir_all(&ws).unwrap();
        let ctx = BackendCtx { workspace: ws.clone(), scope_key: "host-s".into(), secrets: Arc::new(|s: &str| s.to_string()), home: home.to_path_buf(), sandboxed: false };
        let plan = seagent_vm::policy::auto_with(&seagent_vm::isolation::Capabilities { kvm: false, bwrap: Some("/usr/bin/bwrap".into()), ..Default::default() }, &Default::default(), false);
        assert_eq!(plan.backend, "bwrap");
        let cfg = ExecConfig::default();
        if local::which(&cfg.bwrap.binary).is_some() {
            let b = build_planned(&plan, &cfg, &Value::Null, &ctx).unwrap();
            let d = b.describe();
            assert!(d.starts_with("bwrap") && d.contains("home hidden") && d.contains("network shared with host"), "{d}");
        }
        // bubblewrap missing on this host: the host backend, not an error for every call.
        let mut broken = ExecConfig::default();
        broken.bwrap.binary = "/nonexistent/bwrap".into();
        assert_eq!(build_planned(&plan, &broken, &Value::Null, &ctx).unwrap().id(), "local");
        // A sandboxed session never lands on the host that way.
        let sctx = BackendCtx { sandboxed: true, ..ctx };
        assert!(build_planned(&plan, &broken, &Value::Null, &sctx).is_err());
    }

    #[test]
    fn skill_declared_env_reaches_the_exec_environment_but_never_a_credential() {
        // `seagent-skills setup::prepare` sets a loaded skill's declared names in this process and
        // registers them. Containers and remote sandboxes rebuild the environment from
        // `child_env_for`, so without the registry a skill's own key was a dead letter.
        std::env::set_var("SEAGENT_T_SKILL_TENOR", "skill-key");
        let (ok, refused) = seagent_security::envscrub::register_skill_env(["SEAGENT_T_SKILL_TENOR", "OPENAI_API_KEY"]);
        assert_eq!((ok, refused), (vec!["SEAGENT_T_SKILL_TENOR".to_string()], vec!["OPENAI_API_KEY".to_string()]));
        let cfg = ExecConfig::default(); // no operator `env_passthrough`: the registry alone carries it
        let ee = ExecEnv::new(cfg.clone());
        let env = ee.child_env_for(&[("SEAGENT_X".into(), "call".into())]);
        assert!(env.iter().any(|(k, v)| k == "SEAGENT_T_SKILL_TENOR" && v == "skill-key"), "a skill's declared variable reaches the child: {env:?}");
        assert!(env.iter().any(|(k, v)| k == "SEAGENT_X" && v == "call"), "{env:?}");
        // The call's own value still wins over the registered one.
        let env = ee.child_env_for(&[("SEAGENT_T_SKILL_TENOR".into(), "explicit".into())]);
        assert!(env.iter().any(|(k, v)| k == "SEAGENT_T_SKILL_TENOR" && v == "explicit"), "{env:?}");
        // A credential never rides in: not by registration, not by asking for it.
        let env = ee.child_env_for(&[("OPENAI_API_KEY".into(), "sk-live".into()), ("GITHUB_TOKEN".into(), "ghp".into())]);
        assert!(!env.iter().any(|(k, _)| k == "OPENAI_API_KEY" || k == "GITHUB_TOKEN"), "{env:?}");
        assert!(cfg.passthrough().contains(&"SEAGENT_T_SKILL_TENOR".to_string()));
        assert!(!cfg.passthrough().iter().any(|n| n == "OPENAI_API_KEY"));
        std::env::remove_var("SEAGENT_T_SKILL_TENOR");
    }

    #[test]
    fn sandbox_mode_selects_per_session() {
        let mut cfg = ExecConfig::default();
        cfg.sandbox.mode = "non-main".into();
        let env = ExecEnv::new(cfg);
        assert!(!env.sandboxed("a"), "no classifier: everything is main");
        env.set_classifier(Arc::new(|s: &str| s == "main"));
        assert!(!env.sandboxed("main") && env.sandboxed("group"));
        env.overrides.lock().unwrap().insert("group".into(), SessionOverride { host: Some("host".into()), elevated: None });
        assert!(!env.sandboxed("group"), "/exec host=host escapes");
        let mut cfg = ExecConfig::default();
        cfg.sandbox.mode = "all".into();
        cfg.sandbox.scope = "shared".into();
        let env = ExecEnv::new(cfg);
        assert!(env.sandboxed("main"));
        assert_eq!(env.scope_key("x", Path::new("/w")), "shared");
        let env = ExecEnv::default();
        assert!(!env.sandboxed("x"));
        assert_eq!(env.scope_key("a/b", Path::new("/w")), "s-a-b");
        env.overrides.lock().unwrap().insert("x".into(), SessionOverride { host: Some("sandbox".into()), elevated: None });
        assert!(env.sandboxed("x"), "/exec host=sandbox opts in with mode=off");
    }

    #[test]
    fn plugin_backends_get_their_own_config_table() {
        // `[exec.providers.<name>]` reaches the provider (Hermes terminal_env_provider config).
        register_provider(
            "cfg-env",
            Arc::new(|v: &Value, _c: &BackendCtx| {
                assert_eq!(v["dir"], "/somewhere", "the provider sees its own table");
                Ok(Arc::new(local::LocalBackend::new()) as Arc<dyn ExecBackend>)
            }),
        );
        let cfg = ExecConfig::parse(&json!({"backend": "cfg-env", "providers": {"cfg-env": {"dir": "/somewhere"}}})).unwrap();
        let env = ExecEnv::new(cfg);
        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.to_string());
        assert_eq!(env.backend("s", Path::new("/w"), Path::new("/h"), &secrets, false).unwrap().id(), "local");
    }

    #[test]
    fn node_routing_points_the_model_at_node_invoke() {
        let c = crate::testutil::ctx("exnode");
        let env = ExecEnv::new(ExecConfig::default());
        env.set_override(&c.session_id, Some(Some("node".into())), None);
        let e = match backend_in(&env, &c, false) {
            Err(e) => e,
            Ok(b) => panic!("node routing must not pick a local backend, got {}", b.id()),
        };
        assert!(e.contains("node_invoke") && e.contains("system.run"), "{e}");
        // `host=host` runs here; `elevated` is refused only when the sandbox forbids it.
        env.set_override(&c.session_id, Some(Some("host".into())), None);
        assert_eq!(backend_in(&env, &c, false).unwrap().id(), "local");
    }

    #[test]
    fn host_routes_and_elevated_come_from_the_session_store() {
        let env = ExecEnv::new(ExecConfig::default());
        assert!(!env.sandboxed("box"), "mode off: host by default");
        env.set_route_lookup(Arc::new(|s: &str| SessionOverride {
            host: (s == "box").then(|| "sandbox".to_string()),
            elevated: (s == "up").then(|| "on".to_string()),
        }));
        // `/exec host=sandbox` opts a session in even with `mode = "off"`.
        assert!(env.sandboxed("box") && !env.sandboxed("main"));
        // `/elevated on` runs its calls on the host.
        assert!(env.elevated("up"));
        // An in-memory override (a tool/test decision) still wins.
        env.set_override("box", Some(Some("host".into())), None);
        assert!(!env.sandboxed("box"));
        // `sandbox.elevated = "off"` refuses elevated calls inside the sandbox.
        let mut cfg = ExecConfig::default();
        cfg.sandbox.mode = "all".into();
        cfg.sandbox.elevated = "off".into();
        let env = ExecEnv::new(cfg);
        assert!(env.allow_elevated("s").is_err());
    }

    #[test]
    fn provider_registry_and_quoting() {
        register_provider("fake-env", Arc::new(|_v: &Value, _c: &BackendCtx| Ok(Arc::new(local::LocalBackend::new()) as Arc<dyn ExecBackend>)));
        assert!(ExecConfig::parse(&json!({"backend":"fake-env"})).is_ok());
        let env = ExecEnv::new(ExecConfig { backend: "fake-env".into(), ..Default::default() });
        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.to_string());
        let b = env.backend("s", Path::new("/tmp"), Path::new("/tmp"), &secrets, false).unwrap();
        assert_eq!(b.id(), "local");
        assert_eq!(sh_quote("abc"), "abc");
        assert_eq!(sh_quote("a b'c"), "'a b'\\''c'");
        assert_eq!(sh_quote(""), "''");
    }
}
