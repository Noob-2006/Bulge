//! NVIDIA OpenShell backend (OpenClaw `extensions/openshell`).
//!
//! OpenShell is a **CLI + control plane**, not an HTTP API: the plugin drives
//! `openshell sandbox get|create|delete|ssh-config` (with `--gateway`,
//! `--gateway-endpoint`, `--workspace`) and then executes commands over SSH using
//! the config that `openshell sandbox ssh-config <sandbox>` returns (OpenClaw
//! `src/cli.ts::createOpenShellSshSession` → `src/backend.ts::runCli`). seagent does
//! the same: lifecycle through the CLI, exec through `ssh -F <generated config>`,
//! `-T -o RequestTTY=no` for pipes and `-tt -o RequestTTY=force` for a PTY
//! (`src/agents/sandbox/ssh.ts::commandSession`). The host workspace is mirrored
//! to `remote_workspace_dir` (`/sandbox`, upstream `mirror` mode) with
//! [`super::sync::WorkspaceSync`].
//!
//! Requires the OpenShell CLI and a reachable gateway on this host; without them
//! the backend fails with the CLI's own message plus what to check, never with a
//! bare "not implemented".

use super::local;
use super::sandbox::SandboxConfig;
use super::ssh::{self, SshConfig};
use super::sync::{self, SyncOptions, WorkspaceSync};
use super::{local::spawn_command, sh_quote, BackendCtx};
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest};
use serde::Deserialize;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// `[exec.openshell]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpenShellConfig {
    /// The OpenShell CLI (`openshell`, or an absolute path).
    pub command: String,
    /// `--gateway <name>` (optional).
    pub gateway: String,
    /// `--gateway-endpoint <url>` (optional).
    pub gateway_endpoint: String,
    /// `--workspace <name>`: the control-plane workspace (optional).
    pub workspace: String,
    /// Sandbox name; empty = `seagent-<scope>`.
    pub sandbox: String,
    /// `sandbox create --from <image>` (upstream default `openclaw`).
    pub from: String,
    /// `--policy <file>`: path to a policy YAML on this host.
    pub policy: String,
    /// `--provider <name>` to attach at creation.
    pub providers: Vec<String>,
    /// `--gpu`.
    pub gpu: bool,
    /// `--auto-providers`.
    pub auto_providers: bool,
    /// Delete the sandbox on cleanup. Off by default: the sandbox (and its
    /// workspace) is reused by the next turn, as OpenClaw keeps its runtime.
    pub delete_on_cleanup: bool,
    /// Writable workspace inside the sandbox (upstream `remoteWorkspaceDir`).
    pub remote_workspace_dir: String,
    /// Mirror the host workspace into the sandbox before each command.
    pub push: bool,
    /// Bring back what a command changed.
    pub pull: bool,
    /// Timeout for one CLI call (`create`, `ssh-config`, `delete`).
    pub timeout_seconds: u64,
    /// Host files copied into the sandbox `$HOME` once (mode 0600), in addition to
    /// `[exec] credential_files` — the backend constructor only receives this table.
    pub credential_files: Vec<String>,
}

impl Default for OpenShellConfig {
    fn default() -> Self {
        OpenShellConfig {
            command: "openshell".into(),
            gateway: String::new(),
            gateway_endpoint: String::new(),
            workspace: String::new(),
            sandbox: String::new(),
            from: "openclaw".into(),
            policy: String::new(),
            providers: vec![],
            gpu: false,
            auto_providers: false,
            delete_on_cleanup: false,
            remote_workspace_dir: "/sandbox".into(),
            push: true,
            pull: true,
            timeout_seconds: 300,
            credential_files: vec![],
        }
    }
}

pub struct OpenShellBackend {
    cfg: OpenShellConfig,
    /// `openshell [--gateway …]` prefix; the CLI name is argv[0] of every call.
    cli: Vec<String>,
    sandbox: String,
    /// Generated `ssh -F` config (contains host/user/port/proxy command).
    ssh_config: PathBuf,
    /// `Host` alias inside `ssh_config`.
    alias: String,
    /// `[exec.ssh]`-shaped settings, reused for argv building.
    ssh: SshConfig,
    remote_root: String,
    host_ws: PathBuf,
    sync: WorkspaceSync,
    creds: Vec<String>,
    creds_done: AtomicBool,
    passthrough: Vec<String>,
    gone: AtomicBool,
}

/// Output of one CLI call.
struct CliOut {
    code: i32,
    stdout: String,
    stderr: String,
}

impl OpenShellBackend {
    /// `sb` is the sandbox policy: a remote OpenShell sandbox cannot be bind-mounted
    /// into, so `workspace_access`/`binds` are OpenShell's policy file's job (see
    /// `[exec.openshell] policy`), not seagent's.
    pub fn new(cfg: &OpenShellConfig, _sb: &SandboxConfig, ctx: &BackendCtx) -> Result<OpenShellBackend, String> {
        if local::which(&cfg.command).is_none() {
            return Err(format!(
                "exec backend openshell: `{}` was not found in PATH — install the NVIDIA OpenShell CLI and configure a gateway (`openshell gateway list`), or set [exec.openshell] command",
                cfg.command
            ));
        }
        if !cfg.remote_workspace_dir.starts_with('/') {
            return Err(format!("exec.openshell.remote_workspace_dir `{}`: must be an absolute path inside the sandbox", cfg.remote_workspace_dir));
        }
        let mut cli = vec![cfg.command.clone()];
        if !cfg.gateway.is_empty() {
            cli.extend(["--gateway".into(), cfg.gateway.clone()]);
        }
        if !cfg.gateway_endpoint.is_empty() {
            cli.extend(["--gateway-endpoint".into(), cfg.gateway_endpoint.clone()]);
        }
        if !cfg.workspace.is_empty() {
            cli.extend(["--workspace".into(), cfg.workspace.clone()]);
        }
        let sandbox = if cfg.sandbox.trim().is_empty() { format!("seagent-{}", super::sanitize(&ctx.scope_key)) } else { cfg.sandbox.clone() };
        let mut me = OpenShellBackend {
            cli,
            sandbox,
            ssh_config: PathBuf::new(),
            alias: String::new(),
            ssh: SshConfig { host: String::new(), multiplex: false, connect_timeout: 15, host_key_checking: "accept-new".into(), ..Default::default() },
            remote_root: cfg.remote_workspace_dir.trim_end_matches('/').to_string(),
            host_ws: ctx.workspace.clone(),
            sync: WorkspaceSync::new(&ctx.workspace, &cfg.remote_workspace_dir, SyncOptions::default()),
            creds: cfg.credential_files.clone(),
            creds_done: AtomicBool::new(false),
            passthrough: vec![],
            gone: AtomicBool::new(false),
            cfg: cfg.clone(),
        };
        me.ensure_sandbox()?;
        me.load_ssh_config(ctx)?;
        Ok(me)
    }

    fn run_cli(&self, args: &[&str]) -> Result<CliOut, String> {
        let what = args.join(" ");
        let mut cmd = Command::new(&self.cli[0]);
        cmd.args(&self.cli[1..]).args(args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = super::retry_etxtbsy(|| cmd.spawn())
            .map_err(|e| format!("exec backend openshell: cannot run `{}`: {e}", self.cli[0]))?;
        // Drain both pipes while the CLI runs (a full pipe would block it) and stop waiting
        // after `timeout_seconds` (OpenClaw `runPluginCommandWithTimeout`).
        let mut out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let (otx, orx) = std::sync::mpsc::channel();
        let (etx, erx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = io::Read::read_to_end(&mut out, &mut b);
            let _ = otx.send(b);
        });
        std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = io::Read::read_to_end(&mut err, &mut b);
            let _ = etx.send(b);
        });
        let limit = self.cfg.timeout_seconds.max(1);
        let deadline = Instant::now() + Duration::from_secs(limit);
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) => {}
                Err(e) => return Err(format!("exec backend openshell: `{what}`: {e}")),
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("exec backend openshell: `{what}` timed out after {limit}s (raise [exec.openshell] timeout_seconds)"));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let read = |rx: std::sync::mpsc::Receiver<Vec<u8>>| String::from_utf8_lossy(&rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default()).into_owned();
        Ok(CliOut { code: status.code().unwrap_or(-1), stdout: read(orx), stderr: read(erx) })
    }

    fn fail(&self, what: &str, o: &CliOut) -> String {
        let detail = if o.stderr.trim().is_empty() { o.stdout.trim() } else { o.stderr.trim() };
        format!("exec backend openshell: `{what}` failed (exit {}): {detail}", o.code)
    }

    /// Reuse the scope's sandbox, creating it on first use (OpenClaw
    /// `ensureSandboxExistsInner`).
    fn ensure_sandbox(&mut self) -> Result<(), String> {
        let get = self.run_cli(&["sandbox", "get", &self.sandbox])?;
        if get.code == 0 {
            return Ok(());
        }
        let mut args: Vec<String> = vec!["sandbox".into(), "create".into(), self.sandbox.clone()];
        if !self.cfg.from.is_empty() {
            args.extend(["--from".into(), self.cfg.from.clone()]);
        }
        if !self.cfg.policy.is_empty() {
            let p = seagent_core::tool::expand_home(&self.cfg.policy);
            if !p.exists() {
                return Err(format!("exec.openshell.policy `{}` is not a readable file on this host", p.display()));
            }
            args.extend(["--policy".into(), p.display().to_string()]);
        }
        for p in &self.cfg.providers {
            args.extend(["--provider".into(), p.clone()]);
        }
        if self.cfg.gpu {
            args.push("--gpu".into());
        }
        if self.cfg.auto_providers {
            args.push("--auto-providers".into());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = self.run_cli(&refs)?;
        if out.code != 0 {
            return Err(format!(
                "{} — check `openshell sandbox list` / `openshell gateway list` (gateway reachable? sandbox quota?) and [exec.openshell] from/policy/providers",
                self.fail("openshell sandbox create", &out)
            ));
        }
        Ok(())
    }

    /// Ask the CLI for the sandbox's ssh config and keep it (0600) under the data dir.
    fn load_ssh_config(&mut self, ctx: &BackendCtx) -> Result<(), String> {
        let out = self.run_cli(&["sandbox", "ssh-config", &self.sandbox])?;
        if out.code != 0 || out.stdout.trim().is_empty() {
            return Err(self.fail("openshell sandbox ssh-config", &out));
        }
        let alias = out.stdout.lines().find_map(|l| l.trim().strip_prefix("Host ")).map(|h| h.trim().to_string());
        let Some(alias) = alias.filter(|a| !a.is_empty()) else {
            return Err("exec backend openshell: `openshell sandbox ssh-config` returned no `Host` block".into());
        };
        let dir = ctx.home.join("sandboxes").join("openshell").join(super::sanitize(&ctx.scope_key));
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let path = dir.join("ssh-config");
        crate::util::atomic_write(&path, out.stdout.as_bytes()).map_err(|e| format!("write {}: {e}", path.display()))?;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        self.alias = alias;
        self.ssh_config = path;
        Ok(())
    }

    /// `ssh -F <config> …` argv up to (not including) the target alias.
    fn ssh_args(&self, pty: bool) -> Vec<String> {
        let mut a: Vec<String> = vec!["-F".into(), self.ssh_config.display().to_string()];
        // OpenClaw: `-tt -o RequestTTY=force` with a terminal, `-T -o RequestTTY=no` without.
        if pty {
            a.extend(["-tt".into()]);
        } else {
            a.extend(["-T".into()]);
        }
        let opts = ssh::ssh_opts(&self.ssh, "");
        a.extend(opts);
        a.extend(["-o".into(), format!("RequestTTY={}", if pty { "force" } else { "no" })]);
        a
    }

    fn runner(&self) -> impl Fn(&str, Option<&[u8]>) -> Result<super::Capture, String> + '_ {
        move |script: &str, stdin: Option<&[u8]>| super::run_capture(self, script, stdin, Duration::from_secs(600))
    }

    fn sandbox_name(&self) -> &str {
        &self.sandbox
    }
}

impl ExecBackend for OpenShellBackend {
    fn id(&self) -> &str {
        "openshell"
    }
    fn describe(&self) -> String {
        format!(
            "openshell: sandbox `{}` (alias {}) over ssh; workspace mirrored to {}",
            self.sandbox, self.alias, self.remote_root
        )
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        let mut script = super::sync::common::env_prefix(&req.env, &self.passthrough);
        if let Some(c) = &req.cwd {
            script.push_str(&format!("mkdir -p {0} && cd {0} || exit 126\n", sh_quote(&self.map_path(c))));
        }
        script.push_str(&req.script);
        let mut cmd = Command::new("ssh");
        cmd.args(self.ssh_args(req.pty.is_some()));
        cmd.arg(&self.alias);
        // One quoted word: ssh re-parses the joined command line on the remote side.
        cmd.arg(ssh::remote_command(if req.login { "-lc" } else { "-c" }, &script));
        spawn_command(cmd, req, None)
    }
    fn map_path(&self, host: &Path) -> String {
        super::sync::common::map_under(&self.host_ws, &self.remote_root, host)
    }
    fn shares_host_fs(&self) -> bool {
        false
    }
    fn supports_pty(&self) -> bool {
        // `ssh -tt -o RequestTTY=force` (OpenClaw does the same for tty commands).
        true
    }
    fn temp_dir(&self) -> String {
        "/tmp".into()
    }
    fn before_exec(&self) -> Result<(), String> {
        let run = self.runner();
        if !self.creds.is_empty() && !self.creds_done.load(Ordering::SeqCst) {
            sync::upload_files(&run, &self.creds, false)?;
            self.creds_done.store(true, Ordering::SeqCst);
        }
        if self.cfg.push {
            self.sync.push(&run)?;
        }
        Ok(())
    }
    fn after_exec(&self) -> Result<(), String> {
        if !self.cfg.pull {
            return Ok(());
        }
        let run = self.runner();
        let r = self.sync.pull(&run)?;
        if r.skipped.is_empty() {
            Ok(())
        } else {
            Err(format!("workspace sync: {}", r.skipped.join("; ")))
        }
    }
    fn cleanup(&self) {
        if self.gone.swap(true, Ordering::SeqCst) {
            return;
        }
        if self.cfg.pull {
            let _ = self.after_exec();
        }
        if self.cfg.delete_on_cleanup {
            let _ = self.run_cli(&["sandbox", "delete", self.sandbox_name()]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::sync::common::fakecli;
    use crate::exec::{ExecConfig, ExecEnv};
    use crate::testutil::tmpdir;
    use serde_json::json;
    use std::sync::Arc;

    /// A stand-in `openshell` CLI: keeps "sandboxes" as files in a state dir and
    /// prints a plausible `ssh-config`.
    fn fake_cli(bin: &Path, log: &Path, state: &Path) -> PathBuf {
        let body = format!(
            r#"#!/bin/bash
printf '%s\n' "$*" >> {log}
state={state}
mkdir -p "$state"
args=()
while [ $# -gt 0 ]; do
    case "$1" in
        --gateway|--gateway-endpoint|--workspace) shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done
cmd="${{args[0]:-}}"
sub="${{args[1]:-}}"
name="${{args[2]:-}}"
case "$cmd $sub" in
    "sandbox get")
        [ -f "$state/$name" ] && exit 0
        echo "sandbox $name not found" >&2; exit 1 ;;
    "sandbox create")
        touch "$state/$name"; echo "created $name"; exit 0 ;;
    "sandbox ssh-config")
        [ -f "$state/$name" ] || {{ echo "no sandbox $name" >&2; exit 1; }}
        printf 'Host seagentsandbox\n  HostName 127.0.0.1\n  User seagent\n  Port 2222\n'
        exit 0 ;;
    "sandbox delete")
        rm -f "$state/$name"; exit 0 ;;
esac
echo "unexpected: $*" >&2; exit 2
"#,
            log = log.display(),
            state = state.display()
        );
        fakecli::script(bin, "openshell", &body)
    }

    #[test]
    fn cli_lifecycle_exec_pty_sync_and_cleanup() {
        let _lock = fakecli::lock_path();
        let base = tmpdir("oshell");
        let (ws, home, remote, bin, state) = (base.join("ws"), base.join("seagenthome"), base.join("remote"), base.join("bin"), base.join("state"));
        for d in [&ws, &home, &remote] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (log, sshlog) = (base.join("cli.log"), base.join("ssh.log"));
        let cli = fake_cli(&bin, &log, &state);
        fakecli::fake_ssh(&bin, &sshlog, &remote);
        let old = fakecli::prepend_path(&bin);
        std::fs::write(ws.join("in.txt"), "host file").unwrap();
        let hosthome = base.join("hosthome");
        std::fs::create_dir_all(&hosthome).unwrap();
        let (cred, cred_rel) = {
            let p = hosthome.join(format!(".seagent-oshell-{}", std::process::id()));
            std::fs::write(&p, "token=2\n").unwrap();
            let rel = format!("~/{}", p.file_name().unwrap().to_string_lossy());
            (p, rel)
        };
        let read = || std::fs::read_to_string(&log).unwrap_or_default();
        let ssh_read = || std::fs::read_to_string(&sshlog).unwrap_or_default();

        let cfg = ExecConfig {
            backend: "openshell".into(),
            openshell: OpenShellConfig {
                command: cli.display().to_string(),
                gateway: "gw1".into(),
                remote_workspace_dir: remote.display().to_string(),
                delete_on_cleanup: true,
                credential_files: vec![cred_rel],
                ..Default::default()
            },
            ..Default::default()
        };
        let env = ExecEnv::new(cfg);
        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.to_string());
        let b = env.backend("s1", &ws, &home, &secrets, false).unwrap();
        assert_eq!(b.id(), "openshell");
        assert!(!b.shares_host_fs() && b.supports_pty());
        assert!(read().contains("--gateway gw1 sandbox get seagent-host-s1"), "gateway flag + sandbox name: {}", read());
        assert!(read().contains("sandbox create seagent-host-s1 --from openclaw"), "created on first use: {}", read());
        assert!(read().contains("sandbox ssh-config seagent-host-s1"), "{}", read());
        assert!(b.describe().contains("seagent-host-s1") && b.describe().contains("seagentsandbox"), "{}", b.describe());
        let mapped = b.map_path(&ws.join("d/x"));
        assert_eq!(mapped, format!("{}/d/x", remote.display()));

        // mirror push: workspace files and credential files land remotely.
        {
            let _home = crate::testutil::test_home(&hosthome);
            b.before_exec().unwrap();
        }
        assert_eq!(std::fs::read_to_string(remote.join("in.txt")).unwrap(), "host file");
        let landed = remote.join(cred.file_name().unwrap());
        assert_eq!(std::fs::read_to_string(&landed).unwrap(), "token=2\n");
        assert_eq!(std::fs::metadata(&landed).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(ssh_read().contains("-F ") && ssh_read().contains("-o RequestTTY=no"), "exec over the ssh-config: {}", ssh_read());

        // exec (pipe) and exec (pty) both work; `-tt` only for the pty.
        let req = ExecRequest { script: "cat in.txt; echo made > out.txt; exit 2".into(), cwd: Some(ws.clone()), ..Default::default() };
        let (st, out) = crate::exec::drain(b.spawn(&req).unwrap(), Duration::from_secs(20)).unwrap();
        assert_eq!(st.code, Some(2), "{}", String::from_utf8_lossy(&out));
        assert!(String::from_utf8_lossy(&out).contains("host file"));
        let (st, out) = crate::exec::drain(b.spawn(&ExecRequest { script: "tty".into(), pty: Some((24, 80)), ..Default::default() }).unwrap(), Duration::from_secs(20)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("/dev/pts"), "pty through ssh -tt: {}", String::from_utf8_lossy(&out));
        assert!(ssh_read().contains("-tt"), "{}", ssh_read());
        b.after_exec().unwrap();
        assert_eq!(std::fs::read_to_string(ws.join("out.txt")).unwrap(), "made\n", "pulled back");

        // cleanup deletes the sandbox when configured.
        b.cleanup();
        assert!(read().contains("sandbox delete seagent-host-s1"), "{}", read());
        assert!(!state.join("seagent-host-s1").exists());
        let _ = std::fs::remove_file(&cred);
        fakecli::restore_path(old);
    }

    #[test]
    fn errors_name_the_cli_and_what_to_check() {
        let _lock = fakecli::lock_path();
        let base = tmpdir("oshellerr");
        let (ws, home) = (base.join("ws"), base.join("seagenthome"));
        for d in [&ws, &home] {
            std::fs::create_dir_all(d).unwrap();
        }
        let secrets: Arc<dyn Fn(&str) -> String + Send + Sync> = Arc::new(|s: &str| s.to_string());
        let build = |oc: OpenShellConfig| ExecEnv::new(ExecConfig { backend: "openshell".into(), openshell: oc, ..Default::default() }).backend("s1", &ws, &home, &secrets, false);

        // No CLI on this machine: names the CLI and the gateway check.
        let e = build(OpenShellConfig { command: "openshell-not-installed-xyz".into(), ..Default::default() }).err().unwrap();
        assert!(e.contains("OpenShell CLI") && e.contains("gateway list"), "{e}");
        // A CLI that rejects `create` surfaces its own message.
        let bin = base.join("bin");
        let failing = fakecli::script(&bin, "openshell-broken", "#!/bin/bash\necho 'gateway unreachable' >&2\nexit 1\n");
        let e = build(OpenShellConfig { command: failing.display().to_string(), ..Default::default() }).err().unwrap();
        assert!(e.contains("gateway unreachable") && e.contains("sandbox create"), "{e}");
        // Bad remote workspace path.
        let e = build(OpenShellConfig { command: failing.display().to_string(), remote_workspace_dir: "sandbox".into(), ..Default::default() }).err().unwrap();
        assert!(e.contains("remote_workspace_dir"), "{e}");
        assert!(serde_json::from_value::<OpenShellConfig>(json!({"command": "openshell", "gpu": true})).unwrap().from == "openclaw");
        assert!(serde_json::from_value::<OpenShellConfig>(json!({"typo": 1})).is_err());
    }
}
