//! Docker / Podman backend: one hardened container per sandbox scope, commands
//! run with `docker exec` through [`super::local::spawn_command`] (the pattern
//! the Modal / Daytona backends use for their client program).
//!
//! Ported from Hermes `tools/environments/docker.py` (+ `docker_egress.py`) and
//! OpenClaw `src/agents/sandbox/{docker,podman-runtime,validate-sandbox-security,
//! sanitize-env-vars}.ts`:
//!
//! * the container *is* the security boundary — all capabilities dropped,
//!   `no-new-privileges`, a PID ceiling, `--user uid:gid` so bind-mount writes
//!   stay owned by the host user, an optional read-only rootfs with size-limited
//!   tmpfs, and `--network none` unless the operator opts in;
//! * the workspace is bind-mounted per `[exec.sandbox] workspace_access`
//!   (`none` → the scope's private scratch dir, `ro` → read-only, `rw`);
//! * `[exec.sandbox] binds` go through `sandbox::parse_bind` (blocked host paths
//!   such as `/etc`, `/proc`, the docker socket and `~/.ssh` are refused);
//! * environment variables are filtered by `sandbox::sanitize_forwarded`; values
//!   travel in the client process environment under a name-only `-e NAME` flag so
//!   credentials never appear in `docker`'s world-readable `/proc/<pid>/cmdline`;
//! * with networking on, traffic is routed through the host egress proxy
//!   (`HTTP_PROXY`/`HTTPS_PROXY` → `host.docker.internal:<proxy_port>`, whose
//!   allowlist is `[exec.docker] egress_allow` / `[security.egress_proxy]`);
//!   with `network = "none"` the proxy variables are dropped, never forwarded.
//!
//! Limitation (documented upstream too): `HTTP_PROXY` only covers programs that
//! honour proxy env vars. `--network none` is the only airtight network policy;
//! a joined network relies on the proxy plus per-host allowlisting.

use super::local::{spawn_command, which};
use super::sandbox::{parse_bind, sanitize_forwarded, unsafe_env_value, SandboxConfig};

/// `--user uid:gid` of the host user, so bind-mount writes are owned by us (Unix). Docker
/// Desktop (macOS, Windows) runs the engine in a VM and maps file ownership itself: omitted.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn host_user() -> Option<String> {
    // SAFETY: getuid/getgid are always safe.
    Some(format!("{}:{}", unsafe { libc::getuid() }, unsafe { libc::getgid() }))
}
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn host_user() -> Option<String> {
    None
}
use super::{BackendCtx, ExecConfig};
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest};
use serde::Deserialize;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Labels `seagent sandbox list` / `prune` look for (also `crates/seagent/src/exec_cli.rs`).
pub const LABEL: &str = "seagent.sandbox";
pub const SCOPE_LABEL: &str = "seagent.scope";

/// Hermes `_DEFAULT_PIDS_LIMIT`: 2048 leaves room for a browser and is still
/// three orders of magnitude under the host's `pid_max`.
const DEFAULT_PIDS_LIMIT: u64 = 2048;
/// How the container reaches the host's egress proxy (Docker Desktop provides it;
/// Linux needs the explicit `--add-host …:host-gateway` mapping).
const HOST_GATEWAY: &str = "host.docker.internal";
/// Private home inside the container (bind-mounted from the scope directory).
const CONTAINER_HOME: &str = "/home/seagent";
const SHORT: Duration = Duration::from_secs(30);

/// Variables that would weaken or bypass the egress proxy if a config value
/// overrode them (Hermes `docker_egress._PROXY_CONTROL_ENV`).
const PROXY_CONTROL_ENV: &[&str] = &[
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "SEAGENT_EGRESS_PROXY",
];

/// `[exec.docker]` / `[exec.podman]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContainerConfig {
    /// `docker` / `podman` (or an absolute path to the client).
    pub binary: String,
    /// Image the sandbox container is created from.
    pub image: String,
    /// `uid[:gid]` the container runs as; empty = the host user (bind-mount
    /// ownership), `none` = omit `--user` and keep the image's user.
    pub user: String,
    /// Podman rootless: `keep-id` (or `keep-id:uid=…`). Empty = no `--userns`.
    pub userns: String,
    /// `--pids-limit` (fork-bomb guard); 0 = omit.
    pub pids_limit: u64,
    /// `--cap-drop` entries. Default: everything.
    pub cap_drop: Vec<String>,
    pub cap_add: Vec<String>,
    /// `--security-opt no-new-privileges`.
    pub no_new_privileges: bool,
    /// `none` (air-gapped, default) | `host` | `bridge` | a user-defined network.
    pub network: String,
    /// Optional image for an in-network egress-proxy sidecar (`seagent-egress-<scope>`).
    /// Empty = use the host proxy at `host.docker.internal:<proxy_port>`.
    pub proxy_image: String,
    /// Port of the host/sidecar egress proxy; 0 = no egress proxy (direct network).
    pub proxy_port: u16,
    /// Hosts the sandbox may reach through the proxy (`api.openai.com`, `*.example.com`).
    pub egress_allow: Vec<String>,
    /// `--read-only` rootfs (writable state lives in the workspace / home / tmpfs).
    pub read_only: bool,
    /// `--tmpfs` entries (the only writable paths on a read-only rootfs).
    pub tmpfs: Vec<String>,
    /// `--shm-size` (Chromium/Playwright tabs and PyTorch need more than 64 MB).
    pub shm_size: String,
    /// `--memory` (`512m`); empty = unlimited.
    pub memory: String,
    /// `--cpus`; 0 = unlimited.
    pub cpus: f64,
    /// Where the workspace is mounted.
    pub workdir: String,
    /// `--init` (PID 1 reaper so orphaned children do not sit on the PID limit).
    pub init: bool,
    /// Extra `docker run` arguments, appended last before the image.
    pub extra_args: Vec<String>,
    /// Container-level environment (also filtered by `sanitize_forwarded`).
    pub env: HashMap<String, String>,
    /// Host variable names forwarded into the container at creation.
    pub forward_env: Vec<String>,
    /// Remove labelled sandboxes idle for this many hours / older than this many
    /// days (0 = keep).
    pub prune_idle_hours: u64,
    pub prune_max_age_days: u64,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        ContainerConfig {
            binary: "docker".into(),
            image: "debian:bookworm-slim".into(),
            user: String::new(),
            userns: String::new(),
            pids_limit: DEFAULT_PIDS_LIMIT,
            cap_drop: vec!["ALL".into()],
            cap_add: vec![],
            no_new_privileges: true,
            network: "none".into(),
            proxy_image: String::new(),
            proxy_port: 0,
            egress_allow: vec![],
            read_only: true,
            tmpfs: ["/tmp:rw,exec,size=512m", "/var/tmp:rw,noexec,size=256m", "/run:rw,noexec,size=64m"].map(String::from).to_vec(),
            shm_size: "1g".into(),
            memory: String::new(),
            cpus: 0.0,
            workdir: "/workspace".into(),
            init: true,
            extra_args: vec![],
            env: HashMap::new(),
            forward_env: vec![],
            prune_idle_hours: 24,
            prune_max_age_days: 7,
        }
    }
}

impl ContainerConfig {
    pub fn docker() -> Self {
        ContainerConfig::default()
    }
    /// Rootless Podman: `--userns keep-id` preserves bind-mount ownership, so no
    /// `--user` is passed by default (OpenClaw `podman-runtime.ts`).
    pub fn podman() -> Self {
        ContainerConfig { binary: "podman".into(), userns: "keep-id".into(), ..ContainerConfig::default() }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.image.trim().is_empty() {
            return Err(format!("exec.{}.image: an image name is required", self.binary.trim()));
        }
        let net = self.network.trim();
        if net.to_ascii_lowercase().starts_with("container:") {
            return Err(format!("exec.{}.network `{net}`: joining another container's network namespace is not allowed", self.binary.trim()));
        }
        if !net.is_empty() && net != "none" && net != "host" && net != "bridge" && net != "default" && !net.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) {
            return Err(format!("exec.{}.network `{net}`: use none | host | bridge | <network name>", self.binary.trim()));
        }
        for c in self.cap_drop.iter().chain(&self.cap_add) {
            if c.trim().is_empty() || !c.bytes().all(|b| b.is_ascii_alphanumeric() || b"_".contains(&b)) {
                return Err(format!("exec.{}.cap_drop/cap_add `{c}`: not a capability name", self.binary.trim()));
            }
        }
        for t in &self.tmpfs {
            if !t.starts_with('/') {
                return Err(format!("exec.{}.tmpfs `{t}`: must be an absolute container path", self.binary.trim()));
            }
        }
        if !self.workdir.starts_with('/') {
            return Err(format!("exec.{}.workdir `{}`: must be absolute", self.binary.trim(), self.workdir));
        }
        for h in &self.egress_allow {
            let h = h.trim();
            if h.is_empty() || h == "*" || h.bytes().any(|b| b.is_ascii_whitespace() || b == b'/') {
                return Err(format!("exec.{}.egress_allow `{h}`: use host names or `*.domain` (a bare `*` opens everything)", self.binary.trim()));
            }
        }
        if !self.cfg_names_ok() {
            return Err(format!("exec.{}.env: variable names must be [A-Za-z_][A-Za-z0-9_]*", self.binary.trim()));
        }
        Ok(())
    }

    fn cfg_names_ok(&self) -> bool {
        self.env.keys().chain(&self.forward_env).all(|k| name_ok(k))
    }
}

fn name_ok(k: &str) -> bool {
    let mut b = k.bytes();
    match b.next() {
        Some(c) if c == b'_' || c.is_ascii_alphabetic() => {}
        _ => return false,
    }
    b.all(|c| c == b'_' || c.is_ascii_alphanumeric())
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `docker` / `podman` from the configured client path (used in messages).
fn kind_of(binary: &str) -> String {
    Path::new(binary).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// One hardened container per sandbox scope.
pub struct ContainerBackend {
    cfg: ContainerConfig,
    kind: String,
    bin: PathBuf,
    /// `seagent-<scope key>`
    name: String,
    scope: String,
    workdir: String,
    /// The host workspace (`ctx.workspace`); differs from `ws_src` with
    /// `workspace_access = "none"`, where the scratch copy is what gets mounted.
    host_ws: PathBuf,
    ws_src: PathBuf,
    ws_ro: bool,
    home_src: PathBuf,
    binds: Vec<(PathBuf, String, bool)>,
    /// Environment baked into the container at creation.
    env: Vec<(String, String)>,
    /// `[exec] env_passthrough`: credential-shaped names the operator allows — the shape
    /// heuristic only; `sandbox::passthrough_forwards` still refuses seagent-managed credentials.
    passthrough: Vec<String>,
    /// Egress proxy URL when networking and a proxy are both configured.
    proxy: Option<String>,
    allow: Vec<String>,
    /// Set once the container is known to be running.
    state: Mutex<Option<String>>,
    /// The stale-sandbox sweep runs once per backend.
    pruned: Mutex<bool>,
}

impl ContainerBackend {
    pub fn new(cfg: &ContainerConfig, sb: &SandboxConfig, exec_cfg: &ExecConfig, ctx: &BackendCtx) -> Result<ContainerBackend, String> {
        let kind = kind_of(&cfg.binary);
        let kind = if kind.is_empty() { "docker".to_string() } else { kind };
        // `which` accepts an absolute path, so a client outside PATH works too.
        let bin = which(&cfg.binary).ok_or_else(|| format!("exec backend {kind}: `{}` not found — install Docker/Podman or set exec.{kind}.binary", cfg.binary.trim()))?;
        cfg.validate()?;
        // Refuses `[exec.sandbox] binds` on blocked host paths (also validates names).
        sb.validate()?;

        let (ws_src, ws_ro) = match (ctx.sandboxed, sb.workspace_access.as_str()) {
            (true, "none") => {
                let w = sb.scratch_workspace(&ctx.home, &ctx.scope_key);
                std::fs::create_dir_all(&w).map_err(|e| format!("create {}: {e}", w.display()))?;
                (w, false)
            }
            (true, "ro") => (ctx.workspace.clone(), true),
            _ => (ctx.workspace.clone(), false),
        };
        let home_src = sb.root(&ctx.home).join(&ctx.scope_key).join("home");
        std::fs::create_dir_all(&home_src).map_err(|e| format!("create {}: {e}", home_src.display()))?;

        let workdir = if cfg.workdir.is_empty() { "/workspace".into() } else { cfg.workdir.clone() };
        let mut binds = sb.binds.iter().map(|b| parse_bind(b)).collect::<Result<Vec<_>, _>>()?;
        // `[exec] credential_files`: validated read-only file mounts under the sandbox home
        // (same host-path floor as operator binds: /etc, /proc, sockets and ~/.ssh are refused).
        let (creds, _errs) = super::sandbox::credential_binds(&exec_cfg.credential_files, CONTAINER_HOME, &super::sandbox::host_home());
        binds.extend(creds);
        for (_, dst, _) in &binds {
            if dst == &workdir || dst == CONTAINER_HOME {
                return Err(format!(
                    "exec.sandbox.binds: `{dst}` is used by the sandbox itself (workspace at {workdir}, home at {CONTAINER_HOME}); pick another container path"
                ));
            }
        }

        let network = network_mode(cfg);
        let proxy = proxy_url(cfg, &network, &ctx.scope_key);
        let allow: Vec<String> = cfg.egress_allow.iter().map(|h| h.trim().to_string()).filter(|h| !h.is_empty()).collect();

        // Container environment: explicit `[exec.docker] env`, then `forward_env`
        // values from the host, filtered by the shared sanitizer.
        let mut raw: Vec<(String, String)> = cfg.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        raw.sort();
        for n in &cfg.forward_env {
            if let Ok(v) = std::env::var(n) {
                raw.retain(|(k, _)| k != n);
                raw.push((n.clone(), v));
            }
        }
        let (mut env, _blocked) = sanitize_forwarded(&raw, &exec_cfg.passthrough());
        env.retain(|(k, v)| unsafe_env_value(v).is_none() && name_ok(k));
        if proxy.is_some() {
            if let Some((bad, _)) = env.iter().find(|(k, _)| PROXY_CONTROL_ENV.contains(&k.as_str())) {
                return Err(format!(
                    "exec.{kind}.env overrides egress-proxy variable `{bad}` — sandbox traffic would leave the proxy; remove it (egress isolation is enforced)",
                    kind = kind
                ));
            }
        }
        // `--network none`: a proxy variable would be a lie and a foot-gun, so it never reaches the container.
        env.retain(|(k, _)| !PROXY_CONTROL_ENV.contains(&k.as_str()));
        env.extend(proxy_env(cfg, proxy.as_deref()));
        env.sort();

        Ok(ContainerBackend {
            cfg: cfg.clone(),
            kind,
            bin,
            name: format!("seagent-{}", ctx.scope_key),
            scope: ctx.scope_key.clone(),
            workdir,
            host_ws: ctx.workspace.clone(),
            ws_src,
            ws_ro,
            home_src,
            binds,
            env,
            passthrough: exec_cfg.passthrough(),
            proxy,
            allow,
            state: Mutex::new(None),
            pruned: Mutex::new(false),
        })
    }

    /// `seagent-<scope>` container name.
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn scope(&self) -> &str {
        &self.scope
    }
    /// Egress proxy URL, if the sandbox has one.
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
    }
    fn net(&self) -> String {
        network_mode(&self.cfg)
    }
    fn sidecar(&self) -> String {
        format!("seagent-egress-{}", self.scope)
    }
    fn use_sidecar(&self) -> bool {
        self.proxy.is_some() && !self.cfg.proxy_image.trim().is_empty()
    }

    /// `--user uid:gid` so bind-mount writes are owned by the host user.
    fn user_spec(&self) -> Option<String> {
        let u = self.cfg.user.trim();
        if u == "none" {
            return None;
        }
        if !u.is_empty() {
            return Some(u.to_string());
        }
        if !self.cfg.userns.trim().is_empty() {
            return None; // rootless keep-id already maps the host user
        }
        host_user()
    }

    fn labels(&self) -> Vec<String> {
        vec![
            format!("{LABEL}=1"),
            format!("{SCOPE_LABEL}={}", self.scope),
            format!("seagent.image={}", self.cfg.image),
            format!("seagent.egress={}", self.proxy.as_deref().map(|p| p.to_string()).unwrap_or_else(|| "off".into())),
            format!("seagent.created={}", now()),
        ]
    }

    /// `docker run -d … <image> sleep infinity` for this scope.
    pub fn run_args(&self) -> Vec<String> {
        let mut a: Vec<String> = vec!["run".into(), "-d".into(), "--rm".into()];
        a.extend(["--name".into(), self.name.clone()]);
        if self.cfg.init {
            a.push("--init".into());
        }
        for l in self.labels() {
            a.push("--label".into());
            a.push(l);
        }
        if self.cfg.read_only {
            a.push("--read-only".into());
        }
        for t in &self.cfg.tmpfs {
            a.push("--tmpfs".into());
            a.push(t.clone());
        }
        let shm = self.cfg.shm_size.trim();
        if !shm.is_empty() && shm != "0" {
            a.extend(["--shm-size".into(), shm.to_string()]);
        }
        let net = self.net();
        if net == "none" {
            a.push("--network=none".into());
        } else {
            a.extend(["--network".into(), net]);
        }
        if self.proxy.is_some() && !self.use_sidecar() {
            a.extend(["--add-host".into(), format!("{HOST_GATEWAY}:host-gateway")]);
        }
        if let Some(u) = self.user_spec() {
            a.extend(["--user".into(), u]);
        }
        if !self.cfg.userns.trim().is_empty() {
            a.extend(["--userns".into(), self.cfg.userns.trim().to_string()]);
        }
        for c in &self.cfg.cap_drop {
            a.extend(["--cap-drop".into(), c.clone()]);
        }
        for c in &self.cfg.cap_add {
            a.extend(["--cap-add".into(), c.clone()]);
        }
        if self.cfg.no_new_privileges {
            a.extend(["--security-opt".into(), "no-new-privileges".into()]);
        }
        if self.cfg.pids_limit > 0 {
            a.extend(["--pids-limit".into(), self.cfg.pids_limit.to_string()]);
        }
        if !self.cfg.memory.trim().is_empty() {
            a.extend(["--memory".into(), self.cfg.memory.trim().to_string()]);
        }
        if self.cfg.cpus > 0.0 {
            a.extend(["--cpus".into(), self.cfg.cpus.to_string()]);
        }
        // Mounts: workspace (or its scratch copy), private home, operator binds.
        a.extend(["-v".into(), format!("{}:{}:{}", self.ws_src.display(), self.workdir, if self.ws_ro { "ro" } else { "rw" })]);
        a.extend(["-v".into(), format!("{}:{CONTAINER_HOME}:rw", self.home_src.display())]);
        for (src, dst, ro) in &self.binds {
            a.extend(["-v".into(), format!("{}:{}:{}", src.display(), dst, if *ro { "ro" } else { "rw" })]);
        }
        a.extend(["--workdir".into(), self.workdir.clone()]);
        for (k, v) in &self.env {
            a.extend(["-e".into(), format!("{k}={v}")]);
        }
        a.extend(self.cfg.extra_args.iter().cloned());
        a.push(self.cfg.image.clone());
        a.extend(["sleep".into(), "infinity".into()]);
        a
    }

    /// Egress-proxy sidecar (`proxy_image`), reached as `http://seagent-egress-<scope>:<port>`.
    pub fn sidecar_args(&self) -> Vec<String> {
        let mut a: Vec<String> = vec!["run".into(), "-d".into(), "--rm".into(), "--name".into(), self.sidecar()];
        a.extend(["--label".into(), format!("{LABEL}=1"), "--label".into(), format!("{SCOPE_LABEL}={}", self.scope), "--label".into(), "seagent.role=egress".into()]);
        for c in &self.cfg.cap_drop {
            a.extend(["--cap-drop".into(), c.clone()]);
        }
        if self.cfg.no_new_privileges {
            a.extend(["--security-opt".into(), "no-new-privileges".into()]);
        }
        if self.cfg.pids_limit > 0 {
            a.extend(["--pids-limit".into(), self.cfg.pids_limit.to_string()]);
        }
        let net = self.net();
        if net != "none" {
            a.extend(["--network".into(), net]);
        }
        if let Some(p) = &self.proxy {
            let port = p.rsplit(':').next().unwrap_or_default().to_string();
            a.extend(["-e".into(), format!("SEAGENT_EGRESS_PORT={port}")]);
        }
        if !self.allow.is_empty() {
            a.extend(["-e".into(), format!("SEAGENT_EGRESS_ALLOW={}", self.allow.join(","))]);
        }
        a.push(self.cfg.proxy_image.trim().to_string());
        a
    }

    /// `docker exec … bash -c <script>`. Forwarded values travel in the client
    /// environment (name-only `-e KEY`), never in the command line.
    pub fn exec_args(&self, req: &ExecRequest, fwd: &[(String, String)]) -> Vec<String> {
        let mut a: Vec<String> = vec!["exec".into()];
        if req.pty.is_some() {
            a.push("-t".into());
        }
        if req.pty.is_some() || req.stdin || req.stdin_data.is_some() {
            a.push("-i".into());
        }
        for (k, _) in fwd {
            a.extend(["-e".into(), k.clone()]);
        }
        let cwd = req.cwd.as_ref().map(|c| self.map_path(c)).filter(|c| c.starts_with('/'));
        if let Some(c) = cwd {
            a.extend(["-w".into(), c]);
        }
        a.extend([self.name.clone(), "bash".into(), if req.login { "-lc" } else { "-c" }.into(), req.script.clone()]);
        a
    }

    /// Run a client subcommand to completion; `None` when it exits nonzero.
    fn capture(&self, args: &[String], timeout: Duration) -> Result<Option<String>, String> {
        let mut cmd = Command::new(&self.bin);
        cmd.args(args);
        cmd.stdin(Stdio::null());
        let child = spawn_command(cmd, &ExecRequest::default(), None).map_err(|e| format!("{}: {e}", self.bin.display()))?;
        let (st, out) = super::drain(child, timeout)?;
        Ok(st.success().then(|| String::from_utf8_lossy(&out).to_string()))
    }

    fn must(&self, args: &[String], what: &str) -> Result<String, String> {
        match self.capture(args, Duration::from_secs(180))? {
            Some(out) => Ok(out),
            None => Err(format!("exec backend {}: {what} failed ({}: `{}`)", self.kind, self.bin.display(), args.join(" "))),
        }
    }

    /// Create (or re-attach to) the scope's container.
    pub fn ensure(&self) -> Result<(), String> {
        let mut st = self.state.lock().unwrap();
        if st.is_some() {
            return Ok(());
        }
        self.prune_once();
        let state = self.capture(&["inspect".into(), "--format".into(), "{{.State.Running}}".into(), self.name.clone()], SHORT)?;
        match state.as_deref().map(str::trim) {
            Some("true") => {}
            Some(s) if !s.is_empty() => {
                self.must(&["start".into(), self.name.clone()], "starting the existing container")?;
            }
            _ => {
                if self.use_sidecar() {
                    let running = self.capture(&["inspect".into(), "--format".into(), "{{.State.Running}}".into(), self.sidecar()], SHORT)?;
                    if running.as_deref().map(str::trim) != Some("true") {
                        self.must(&self.sidecar_args(), "starting the egress-proxy sidecar")?;
                    }
                }
                self.must(&self.run_args(), "creating the sandbox container")?;
            }
        }
        *st = Some(self.name.clone());
        Ok(())
    }

    fn prune_once(&self) {
        let mut done = self.pruned.lock().unwrap();
        if *done || (self.cfg.prune_idle_hours == 0 && self.cfg.prune_max_age_days == 0) {
            *done = true;
            return;
        }
        *done = true;
        let _ = self.prune();
    }

    /// Remove labelled sandbox containers that are idle for
    /// `prune_idle_hours` or older than `prune_max_age_days`; returns the ids.
    pub fn prune(&self) -> Result<Vec<String>, String> {
        let hours = match (self.cfg.prune_idle_hours, self.cfg.prune_max_age_days) {
            (0, 0) => return Ok(vec![]),
            (0, d) => d * 24,
            (h, 0) => h,
            (h, d) => h.min(d * 24),
        };
        let args: Vec<String> = vec!["ps".into(), "-aq".into(), "--filter".into(), format!("label={LABEL}"), "--filter".into(), format!("until={hours}h")];
        let ids = self.capture(&args, SHORT)?.unwrap_or_default();
        let ids: Vec<String> = ids.split_whitespace().map(String::from).collect();
        if ids.is_empty() {
            return Ok(vec![]);
        }
        let mut rm: Vec<String> = vec!["rm".into(), "-f".into()];
        rm.extend(ids.iter().cloned());
        self.must(&rm, "pruning stale sandboxes")?;
        Ok(ids)
    }
}

fn network_mode(cfg: &ContainerConfig) -> String {
    let n = cfg.network.trim().to_ascii_lowercase();
    if n.is_empty() {
        "none".into() // fail closed
    } else {
        n
    }
}

/// Where the container's proxy variables point, if the sandbox has a proxy at all.
fn proxy_url(cfg: &ContainerConfig, network: &str, scope: &str) -> Option<String> {
    if cfg.proxy_port == 0 || network == "none" {
        return None;
    }
    if cfg.proxy_image.trim().is_empty() {
        Some(format!("http://{HOST_GATEWAY}:{}", cfg.proxy_port))
    } else {
        Some(format!("http://seagent-egress-{scope}:{}", cfg.proxy_port))
    }
}

/// `HTTP_PROXY`/`HTTPS_PROXY` (both casings) + loopback-only `NO_PROXY`, as Hermes
/// `docker_egress` builds them (no CA bundle: seagent's proxy does not MITM TLS).
fn proxy_env(cfg: &ContainerConfig, proxy: Option<&str>) -> Vec<(String, String)> {
    let Some(url) = proxy else { return vec![] };
    let loopback = "127.0.0.1,localhost,::1";
    let mut v: Vec<(String, String)> = vec![
        ("HTTP_PROXY".into(), url.into()),
        ("http_proxy".into(), url.into()),
        ("HTTPS_PROXY".into(), url.into()),
        ("https_proxy".into(), url.into()),
        ("ALL_PROXY".into(), url.into()),
        ("all_proxy".into(), url.into()),
        ("NO_PROXY".into(), loopback.into()),
        ("no_proxy".into(), loopback.into()),
        ("SEAGENT_EGRESS_PROXY".into(), "1".into()),
    ];
    if !cfg.egress_allow.is_empty() {
        // Advertise the allowlist to tooling inside the sandbox; enforcement is the
        // proxy's job, this only lets clients skip obvious refusals.
        v.push(("SEAGENT_EGRESS_ALLOW".into(), cfg.egress_allow.join(",")));
    }
    v
}

impl ExecBackend for ContainerBackend {
    fn id(&self) -> &str {
        &self.kind
    }
    fn describe(&self) -> String {
        let egress = match (&self.proxy, self.allow.is_empty()) {
            (Some(p), true) => format!("via egress proxy {p}"),
            (Some(p), false) => format!("via egress proxy {p} (allow {})", self.allow.join(",")),
            (None, _) => "no egress proxy".into(),
        };
        format!(
            "{} ({}): image {}, workspace {} mounted at {} {}, network {}, caps dropped {}, pids {}, {}{}, home {}, {}",
            self.kind,
            self.name,
            self.cfg.image,
            self.ws_src.display(),
            self.workdir,
            if self.ws_ro { "read-only" } else { "read-write" },
            self.net(),
            self.cfg.cap_drop.join(","),
            self.cfg.pids_limit,
            if self.cfg.read_only { "read-only rootfs" } else { "writable rootfs" },
            if self.cfg.no_new_privileges { ", no-new-privileges" } else { "" },
            CONTAINER_HOME,
            egress
        )
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        self.ensure().map_err(io::Error::other)?;
        let (kept, _blocked) = sanitize_forwarded(&req.env, &self.passthrough);
        let kept: Vec<(String, String)> = kept.into_iter().filter(|(k, v)| name_ok(k) && unsafe_env_value(v).is_none()).collect();
        let mut cmd = Command::new(&self.bin);
        cmd.args(self.exec_args(req, &kept));
        let mut r = req.clone();
        r.env = kept;
        r.cwd = None; // the host cwd does not exist here; `-w` carries the mapped path
        spawn_command(cmd, &r, None)
    }
    fn map_path(&self, host: &Path) -> String {
        let join = |root: &str, rel: &Path| {
            if rel.as_os_str().is_empty() {
                root.trim_end_matches('/').to_string()
            } else {
                format!("{}/{}", root.trim_end_matches('/'), rel.display())
            }
        };
        if let Ok(rel) = host.strip_prefix(&self.ws_src) {
            return join(&self.workdir, rel);
        }
        if self.ws_src != self.host_ws {
            // `workspace_access = "none"`: the sandbox sees its private copy at the
            // workdir, so host-workspace paths still land inside the container.
            if let Ok(rel) = host.strip_prefix(&self.host_ws) {
                return join(&self.workdir, rel);
            }
        }
        for (src, dst, _) in &self.binds {
            if let Ok(rel) = host.strip_prefix(src) {
                return join(dst, rel);
            }
        }
        if let Ok(rel) = host.strip_prefix(&self.home_src) {
            return join(CONTAINER_HOME, rel);
        }
        host.display().to_string()
    }
    fn shares_host_fs(&self) -> bool {
        true // the workspace is a bind mount
    }
    fn temp_dir(&self) -> String {
        "/tmp".into()
    }
    fn before_exec(&self) -> Result<(), String> {
        self.ensure()
    }
    fn cleanup(&self) {
        let _ = self.capture(&["rm".into(), "-f".into(), self.name.clone()], SHORT);
        if self.use_sidecar() {
            let _ = self.capture(&["rm".into(), "-f".into(), self.sidecar()], SHORT);
        }
        *self.state.lock().unwrap() = None;
    }
}

#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code, unused_imports))]
mod tests {
    use super::*;
    use crate::exec::drain;
    use crate::testutil::tmpdir;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    /// A stand-in for the `docker` / `podman` client: records its argv and runs
    /// `exec … bash -c <script>` locally, so create / exec / env forwarding /
    /// cleanup are exercised end to end without a daemon.
    const FAKE: &str = r#"#!/bin/sh
d=$(dirname "$0")
{ printf '@@'; for a in "$@"; do printf '[%s]' "$a"; done; printf '\n'; } >> "$d/calls.log"
case "$1" in
  run)
    n=""; prev=""
    for a in "$@"; do if [ "$prev" = "--name" ]; then n="$a"; fi; prev="$a"; done
    echo "id-$n" ;;
  inspect)
    if [ -f "$d/exists" ]; then
      if [ -f "$d/paused" ]; then echo "false"; else echo "true"; fi
    else
      echo "Error: No such container" >&2; exit 1
    fi ;;
  ps) [ -f "$d/stale" ] && cat "$d/stale" ;;
  exec)
    shift
    while [ $# -gt 0 ]; do
      case "$1" in
        -e|-w) shift 2 2>/dev/null || shift ;;
        seagent-*) shift; break ;;
        *) shift ;;
      esac
    done
    [ $# -gt 0 ] && exec "$@"
    ;;
  rm|start|stop|kill) : ;;
esac
exit 0
"#;

    struct Fake {
        dir: PathBuf,
        bin: PathBuf,
    }

    impl Fake {
        #[cfg(unix)]
        fn new(tag: &str) -> Fake {
            let dir = tmpdir(tag);
            let bin = dir.join("docker");
            std::fs::write(&bin, FAKE).unwrap();
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
            Fake { dir, bin }
        }
        fn cfg(&self) -> ContainerConfig {
            ContainerConfig { binary: self.bin.display().to_string(), ..ContainerConfig::docker() }
        }
        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.join("calls.log")).unwrap_or_default()
        }
        fn clear_log(&self) {
            let _ = std::fs::remove_file(self.dir.join("calls.log"));
        }
        fn touch(&self, name: &str) {
            std::fs::write(self.dir.join(name), "").unwrap();
        }
        fn write(&self, name: &str, data: &str) {
            std::fs::write(self.dir.join(name), data).unwrap();
        }
    }

    fn build(_f: &Fake, cfg: &ContainerConfig, access: &str, sandboxed: bool) -> (ContainerBackend, BackendCtx) {
        let ctx = BackendCtx {
            workspace: tmpdir("ctrws"),
            scope_key: "s1".into(),
            secrets: Arc::new(|s: &str| s.to_string()),
            home: tmpdir("ctrhome"),
            sandboxed,
        };
        let sb = SandboxConfig { workspace_access: access.into(), ..Default::default() };
        let be = ContainerBackend::new(cfg, &sb, &ExecConfig::default(), &ctx).unwrap_or_else(|e| panic!("{e}"));
        (be, ctx)
    }

    fn has(args: &[String], seq: &[&str]) -> bool {
        args.windows(seq.len()).any(|w| w.iter().zip(seq).all(|(a, b)| a == b))
    }
    fn has_run(log: &str, seq: &str) -> bool {
        log.contains(&format!("@@[run]{seq}"))
    }

    #[cfg(unix)]
    #[test]
    fn exec_env_builds_the_container_backend_for_host_and_sandbox() {
        let f = Fake::new("ctr10");
        let ws = tmpdir("ctr10ws");
        let home = tmpdir("ctr10h");
        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.to_string());
        // `exec.backend = "docker"`: the host backend is a container (`build_backend` coercion).
        let cfg = ExecConfig { backend: "docker".into(), docker: f.cfg(), ..ExecConfig::default() };
        let env = crate::exec::ExecEnv::new(cfg);
        let b = env.backend("host-sess", &ws, &home, &secrets, false).unwrap();
        assert_eq!(b.id(), "docker");
        assert!(b.describe().contains("seagent-host-host-sess"), "{}", b.describe());
        assert!(b.shares_host_fs());
        assert_eq!(b.temp_dir(), "/tmp");
        // Sandboxed sessions get the sandbox backend and the scope key as the container name.
        let mut cfg = ExecConfig { backend: "local".into(), ..ExecConfig::default() };
        cfg.sandbox.mode = "all".into();
        cfg.sandbox.backend = "docker".into();
        cfg.docker = f.cfg();
        let env = crate::exec::ExecEnv::new(cfg);
        let b = env.backend("boxed", &ws, &home, &secrets, false).unwrap();
        assert_eq!(b.id(), "docker");
        assert!(b.describe().contains("seagent-s-boxed"), "{}", b.describe());
        // `/elevated` escapes back to the host backend.
        let b = env.backend("boxed", &ws, &home, &secrets, true).unwrap();
        assert_eq!(b.id(), "local");
    }

    #[test]
    fn config_fields_have_defaults_and_unknown_keys_fail() {
        let c: ContainerConfig = serde_json::from_value(serde_json::json!({"image": "x"})).unwrap();
        assert_eq!(c.image, "x");
        assert_eq!(c.pids_limit, 2048);
        assert!(c.no_new_privileges && c.read_only && c.init);
        assert_eq!(c.cap_drop, vec!["ALL".to_string()]);
        assert_eq!((c.network.as_str(), c.proxy_port, c.prune_idle_hours, c.prune_max_age_days), ("none", 0, 24, 7));
        assert_eq!((c.user.as_str(), c.workdir.as_str()), ("", "/workspace"));
        assert!(serde_json::from_value::<ContainerConfig>(serde_json::json!({"nope": 1})).is_err());
        let e = ExecConfig::parse(&serde_json::json!({"backend": "docker", "docker": {"image": "seagent/x:1", "network": "bridge", "pids_limit": 64, "egress_allow": ["api.example.com"]}})).unwrap();
        assert_eq!((e.docker.image.as_str(), e.docker.network.as_str(), e.docker.pids_limit), ("seagent/x:1", "bridge", 64));
        assert_eq!(e.podman.binary, "podman");
        assert!(e.docker.validate().is_ok());
        assert!(ExecConfig::parse(&serde_json::json!({"docker": {"pidslimit": 64}})).is_err(), "typos are refused");
        assert!(ExecConfig::parse(&serde_json::json!({"podman": {"image": ""}})).is_err(), "an empty image is refused at config time");
    }

    #[cfg(unix)]
    #[test]
    fn hardening_args_labels_and_mounts() {
        let f = Fake::new("ctr1");
        let (be, ctx) = build(&f, &f.cfg(), "rw", true);
        assert_eq!(be.name(), "seagent-s1");
        let a = be.run_args();
        // Security hardening (OpenClaw buildSandboxCreateArgs / Hermes _BASE_SECURITY_ARGS).
        assert!(has(&a, &["--cap-drop", "ALL"]), "{a:?}");
        assert!(has(&a, &["--security-opt", "no-new-privileges"]), "{a:?}");
        assert!(has(&a, &["--pids-limit", "2048"]), "{a:?}");
        assert!(has(&a, &["--network=none"]), "{a:?}");
        assert!(a.iter().any(|x| x == "--read-only"), "{a:?}");
        assert!(has(&a, &["--tmpfs", "/tmp:rw,exec,size=512m"]), "{a:?}");
        assert!(!has(&a, &["--package-placeholder"]));
        // uid:gid of the host user, so bind-mount writes are owned by us.
        let me = format!("{}:{}", unsafe { libc::getuid() }, unsafe { libc::getgid() });
        assert!(has(&a, &["--user", me.as_str()]), "{a:?}");
        // Labels that `seagent sandbox list` / prune key on.
        assert!(has(&a, &["--label", "seagent.sandbox=1"]), "{a:?}");
        assert!(has(&a, &["--label", "seagent.scope=s1"]), "{a:?}");
        assert!(has(&a, &["--label", "seagent.egress=off"]), "{a:?}");
        // Workspace + private home bind mounts, then the image and the idle command.
        let ws_mount = format!("{}:/workspace:rw", ctx.workspace.display());
        assert!(has(&a, &["-v", ws_mount.as_str()]), "{a:?}");
        assert!(a.iter().any(|x| x.ends_with(":/home/seagent:rw")), "{a:?}");
        let n = a.len();
        assert_eq!(&a[n - 3..], ["debian:bookworm-slim", "sleep", "infinity"], "{a:?}");
        let d = be.describe();
        assert!(d.contains("network none") && d.contains("caps dropped ALL") && d.contains("read-only rootfs"), "{d}");
        // The container is created through the client, once.
        be.ensure().unwrap();
        be.ensure().unwrap();
        let log = f.log();
        assert!(has_run(&log, "[-d][--rm][--name][seagent-s1]"), "{log}");
        assert_eq!(log.lines().filter(|l| l.contains("[run]")).count(), 1, "{log}");
    }

    #[cfg(unix)]
    #[test]
    fn workspace_access_none_ro_rw_and_path_mapping() {
        let f = Fake::new("ctr2");
        // none → private scratch workspace, the real one is not mounted at all.
        let (be, ctx) = build(&f, &f.cfg(), "none", true);
        let a = be.run_args().join("\n");
        assert!(a.contains("sandboxes/s1/workspace:/workspace:rw"), "{a}");
        assert!(!a.contains(&ctx.workspace.display().to_string()), "{a}");
        // Host-workspace paths still map into the sandbox (at its private copy).
        assert_eq!(be.map_path(&ctx.workspace.join("a/b.txt")), "/workspace/a/b.txt");
        // ro → read-only bind mount of the real workspace.
        let (be, ctx) = build(&f, &f.cfg(), "ro", true);
        let mount = format!("{}:/workspace:ro", ctx.workspace.display());
        assert!(has(&be.run_args(), &["-v", mount.as_str()]), "{:?}", be.run_args());
        assert_eq!(be.map_path(&ctx.workspace.join("src/a.rs")), "/workspace/src/a.rs");
        // rw → writable.
        let (be, ctx) = build(&f, &f.cfg(), "rw", true);
        let mount = format!("{}:/workspace:rw", ctx.workspace.display());
        assert!(has(&be.run_args(), &["-v", mount.as_str()]));
        // Not a sandboxed session (docker as the host backend): always read-write.
        let (be, ctx) = build(&f, &f.cfg(), "ro", false);
        let mount = format!("{}:/workspace:rw", ctx.workspace.display());
        assert!(has(&be.run_args(), &["-v", mount.as_str()]));
    }

    #[cfg(unix)]
    #[test]
    fn exec_runs_the_script_and_forwards_a_clean_env() {
        let f = Fake::new("ctr3");
        let (be, ctx) = build(&f, &f.cfg(), "rw", true);
        let mut r = ExecRequest { script: "echo out=$LANG; echo key=[$SEAGENT_TEST_TOKEN]; pwd".into(), ..Default::default() };
        r.cwd = Some(ctx.workspace.clone());
        r.env = vec![("LANG".into(), "C.UTF-8".into()), ("SEAGENT_TEST_TOKEN".into(), "sk-do-not-leak".into())];
        let (st, out) = drain(be.spawn(&r).unwrap(), Duration::from_secs(15)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(st.success(), "{s}");
        assert!(s.contains("out=C.UTF-8"), "sanitized env still arrives: {s}");
        assert!(s.contains("key=[]"), "credential names must not cross the sandbox: {s}");
        let log = f.log();
        // Values travel in the client env behind a name-only `-e` flag…
        assert!(log.contains("[-e][LANG]"), "{log}");
        assert!(log.contains("[-w][/workspace]"), "cwd mapped into the container: {log}");
        // …and credential names/values never reach the command line.
        assert!(!log.contains("[-e][SEAGENT_TEST_TOKEN]"), "credential name not forwarded: {log}");
        assert!(!log.contains("sk-do-not-leak"), "{log}");
        // A pty request becomes `exec -i -t`, and the command really gets a terminal.
        let mut p = ExecRequest { script: "test -t 1 && echo TTY".into(), pty: Some((24, 80)), ..Default::default() };
        p.env = vec![];
        f.clear_log();
        let (_, out) = drain(be.spawn(&p).unwrap(), Duration::from_secs(15)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("TTY"), "{s}");
        assert!(f.log().contains("[exec][-t][-i]"), "{}", f.log());
    }

    #[cfg(unix)]
    #[test]
    fn egress_proxy_env_follows_the_network_mode() {
        let f = Fake::new("ctr4");
        // network = none: no proxy variables may be forwarded, whatever the proxy config says.
        let mut cfg = f.cfg();
        cfg.proxy_port = 3128;
        cfg.egress_allow = vec!["api.example.com".into()];
        cfg.env.insert("HTTPS_PROXY".into(), "http://sneak:1".into());
        let (be, _) = build(&f, &cfg, "rw", true);
        let a = be.run_args().join("\n");
        assert!(!a.contains("PROXY"), "no proxy vars without networking: {a}");
        assert!(has(&be.run_args(), &["--network=none"]));
        assert_eq!(be.proxy(), None);
        // A joined network: proxy variables point at the host proxy, allowlist advertised.
        let mut cfg = f.cfg();
        cfg.network = "bridge".into();
        cfg.proxy_port = 3128;
        cfg.egress_allow = vec!["api.example.com".into()];
        let (be, _) = build(&f, &cfg, "rw", true);
        let a = be.run_args();
        assert!(has(&a, &["--network", "bridge"]), "{a:?}");
        assert!(has(&a, &["-e", "HTTPS_PROXY=http://host.docker.internal:3128"]), "{a:?}");
        assert!(has(&a, &["-e", "http_proxy=http://host.docker.internal:3128"]), "{a:?}");
        assert!(has(&a, &["-e", "NO_PROXY=127.0.0.1,localhost,::1"]), "{a:?}");
        assert!(has(&a, &["-e", "SEAGENT_EGRESS_ALLOW=api.example.com"]), "{a:?}");
        assert!(has(&a, &["--add-host", "host.docker.internal:host-gateway"]), "{a:?}");
        assert_eq!(be.proxy(), Some("http://host.docker.internal:3128"));
        assert!(be.describe().contains("allow api.example.com"), "{}", be.describe());
        // Overriding a proxy variable under enforcement is refused (Hermes check_docker_env_collisions).
        let mut cfg = f.cfg();
        cfg.network = "bridge".into();
        cfg.proxy_port = 3128;
        cfg.env.insert("HTTP_PROXY".into(), "http://sneak:1".into());
        let ctx = BackendCtx { workspace: tmpdir("ctr4b"), scope_key: "s1".into(), secrets: Arc::new(|s: &str| s.to_string()), home: tmpdir("ctr4h"), sandboxed: true };
        let e = ContainerBackend::new(&cfg, &SandboxConfig { workspace_access: "rw".into(), ..Default::default() }, &ExecConfig::default(), &ctx).err().expect("must refuse");
        assert!(e.contains("HTTP_PROXY") && e.contains("egress"), "{e}");
        // A bare `*` allowlist is refused.
        let mut cfg = f.cfg();
        cfg.egress_allow = vec!["*".into()];
        assert!(cfg.validate().is_err());
        let mut cfg = f.cfg();
        cfg.network = "container:other".into();
        assert!(cfg.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn proxy_sidecar_image_carries_the_allowlist() {
        let f = Fake::new("ctr5");
        let mut cfg = f.cfg();
        cfg.network = "bridge".into();
        cfg.proxy_port = 8080;
        cfg.proxy_image = "seagent/egress:1".into();
        cfg.egress_allow = vec!["api.example.com".into(), "*.openai.com".into()];
        let (be, _) = build(&f, &cfg, "rw", true);
        be.ensure().unwrap();
        let log = f.log();
        assert!(log.contains("[run][-d][--rm][--name][seagent-egress-s1]"), "{log}");
        assert!(log.contains("[--label][seagent.role=egress]"), "{log}");
        assert!(log.contains("[--cap-drop][ALL][--security-opt][no-new-privileges]"), "{log}");
        assert!(log.contains("[-e][SEAGENT_EGRESS_PORT=8080]"), "{log}");
        assert!(log.contains("[-e][SEAGENT_EGRESS_ALLOW=api.example.com,*.openai.com]"), "{log}");
        assert!(log.contains("[seagent/egress:1]"), "{log}");
        // The sandbox now points at the sidecar instead of the host gateway.
        let a = be.run_args();
        assert!(has(&a, &["-e", "HTTPS_PROXY=http://seagent-egress-s1:8080"]), "{a:?}");
        assert!(!a.iter().any(|x| x == "--add-host"), "{a:?}");
        // cleanup removes both containers.
        f.clear_log();
        be.cleanup();
        let log = f.log();
        assert!(log.contains("[rm][-f][seagent-s1]") && log.contains("[rm][-f][seagent-egress-s1]"), "{log}");
    }

    #[cfg(unix)]
    #[test]
    fn reattaches_a_running_container_and_starts_a_stopped_one() {
        let f = Fake::new("ctr6");
        let (be, _) = build(&f, &f.cfg(), "rw", true);
        f.touch("exists");
        be.ensure().unwrap();
        let log = f.log();
        assert!(log.contains("[inspect][--format][{{.State.Running}}][seagent-s1]"), "{log}");
        assert!(!log.contains("[run]"), "a running container is reused: {log}");
        // Stopped: `start` it instead of creating a new one.
        let f = Fake::new("ctr6b");
        let (be, _) = build(&f, &f.cfg(), "rw", true);
        f.touch("exists");
        f.touch("paused");
        be.ensure().unwrap();
        let log = f.log();
        assert!(log.contains("[start][seagent-s1]") && !log.contains("[run]"), "{log}");
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_and_prune_remove_by_label() {
        let f = Fake::new("ctr7");
        let (be, _) = build(&f, &f.cfg(), "rw", true);
        be.ensure().unwrap();
        f.clear_log();
        be.cleanup();
        assert!(f.log().contains("[rm][-f][seagent-s1]"), "{}", f.log());
        // prune: labelled containers idle past `prune_idle_hours` are removed.
        f.write("stale", "abc\ndef\n");
        f.clear_log();
        let ids = be.prune().unwrap();
        assert_eq!(ids, vec!["abc".to_string(), "def".to_string()]);
        let log = f.log();
        assert!(log.contains("[ps][-aq][--filter][label=seagent.sandbox][--filter][until=24h]"), "{log}");
        assert!(log.contains("[rm][-f][abc][def]"), "{log}");
    }

    #[cfg(unix)]
    #[test]
    fn missing_binary_bad_binds_and_reserved_targets() {
        let f = Fake::new("ctr8");
        let ctx = BackendCtx { workspace: tmpdir("ctr8w"), scope_key: "s1".into(), secrets: Arc::new(|s: &str| s.to_string()), home: tmpdir("ctr8h"), sandboxed: true };
        let sb = SandboxConfig { workspace_access: "rw".into(), ..Default::default() };
        let cfg = ContainerConfig { binary: "seagent-nope-docker".into(), ..ContainerConfig::docker() };
        let e = ContainerBackend::new(&cfg, &sb, &ExecConfig::default(), &ctx).err().expect("missing client must fail");
        assert!(e.contains("seagent-nope-docker") && e.contains("not found"), "{e}");
        if crate::exec::local::which("docker").is_none() {
            let cp = ContainerConfig::default();
            let e = ContainerBackend::new(&cp, &sb, &ExecConfig::default(), &ctx).err().expect("no docker here");
            assert!(e.starts_with("exec backend docker: `docker` not found"), "{e}");
        }
        // `[exec.sandbox] binds = ["/etc:/x"]` is refused when the container is built.
        let sb = SandboxConfig { workspace_access: "rw".into(), binds: vec!["/etc:/x".into()], ..Default::default() };
        let e = ContainerBackend::new(&f.cfg(), &sb, &ExecConfig::default(), &ctx).err().expect("must refuse /etc");
        assert!(e.contains("refusing to bind-mount"), "{e}");
        // A bind that would shadow the sandbox's own workspace is refused too.
        let sb = SandboxConfig { workspace_access: "rw".into(), binds: vec!["/tmp:/workspace".into()], ..Default::default() };
        let e = ContainerBackend::new(&f.cfg(), &sb, &ExecConfig::default(), &ctx).err().expect("must refuse /workspace");
        assert!(e.contains("used by the sandbox itself"), "{e}");
        // A legitimate bind is mounted with its mode.
        let sb = SandboxConfig { workspace_access: "rw".into(), binds: vec!["/tmp:/data:ro".into()], ..Default::default() };
        let (be, _) = build(&f, &f.cfg(), "rw", true);
        let _ = be;
        let be = ContainerBackend::new(&f.cfg(), &sb, &ExecConfig::default(), &ctx).unwrap();
        assert!(has(&be.run_args(), &["-v", "/tmp:/data:ro"]), "{:?}", be.run_args());
        assert_eq!(be.map_path(Path::new("/tmp/x/y")), "/data/x/y");
    }

    #[cfg(unix)]
    #[test]
    fn credential_files_are_mounted_read_only_and_dangerous_ones_are_not() {
        // `[exec] credential_files`: a real file under $HOME is mounted read-only at the same
        // path under the sandbox home; `/etc/passwd` and `~/.ssh/...` never reach the container.
        let f = Fake::new("ctr11");
        let ctx = BackendCtx { workspace: tmpdir("ctr11w"), scope_key: "s1".into(), secrets: Arc::new(|s: &str| s.to_string()), home: tmpdir("ctr11h"), sandboxed: true };
        let home = tmpdir("ctr11home");
        std::fs::create_dir_all(&home).unwrap();
        let name = format!(".seagent-cred-test-{}", std::process::id());
        let src = home.join(&name);
        std::fs::write(&src, "token=1").unwrap();
        let ecfg = ExecConfig { credential_files: vec![name.clone(), "/etc/passwd".into(), ".ssh/id_rsa".into()], ..ExecConfig::default() };
        let sb = SandboxConfig { workspace_access: "rw".into(), ..Default::default() };
        let be = {
            let _home = crate::testutil::test_home(&home);
            ContainerBackend::new(&f.cfg(), &sb, &ecfg, &ctx).unwrap_or_else(|e| panic!("{e}"))
        };
        let args = be.run_args();
        let real = std::fs::canonicalize(&src).unwrap();
        assert!(has(&args, &["-v", &format!("{}:{CONTAINER_HOME}/{name}:ro", real.display())]), "credential bind missing: {args:?}");
        assert!(!args.iter().any(|a| a.contains("/etc/passwd") || a.contains(".ssh")), "dangerous entries never reach the container: {args:?}");
        assert_eq!(be.map_path(&src), format!("{CONTAINER_HOME}/{name}"), "the sandbox sees it under its home");
        let _ = std::fs::remove_file(&src);
    }

    #[cfg(unix)]
    #[test]
    fn podman_defaults_use_keep_id_instead_of_user() {
        let f = Fake::new("ctr9");
        let p = ContainerConfig::podman();
        assert_eq!((p.binary.as_str(), p.userns.as_str()), ("podman", "keep-id"));
        let cfg = ContainerConfig { binary: f.bin.display().to_string(), ..ContainerConfig::podman() };
        let (be, _) = build(&f, &cfg, "rw", true);
        let a = be.run_args();
        assert!(has(&a, &["--userns", "keep-id"]), "{a:?}");
        assert!(!a.iter().any(|x| x == "--user"), "keep-id maps the host user: {a:?}");
        // Explicit `user = "none"` keeps the image's user, explicit uid wins otherwise.
        let cfg = ContainerConfig { user: "1000:1000".into(), ..f.cfg() };
        let (be, _) = build(&f, &cfg, "rw", true);
        assert!(has(&be.run_args(), &["--user", "1000:1000"]));
        let cfg = ContainerConfig { user: "none".into(), ..f.cfg() };
        let (be, _) = build(&f, &cfg, "rw", true);
        assert!(!be.run_args().iter().any(|x| x == "--user"));
    }
}
