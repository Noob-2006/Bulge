//! SSH backend: run commands on a remote machine through the system `ssh`
//! client (Hermes `tools/environments/ssh.py`, OpenClaw
//! `src/agents/sandbox/ssh.ts`). Spawn-per-call: every command is one
//! `ssh -o BatchMode=yes … <user>@<host> bash -c <script>` process, reusing a
//! ControlMaster connection when `multiplex` is on.
//!
//! The host workspace stays the source of truth: `push` mirrors it to
//! `workspace_remote_path` before every command and `after_exec`/`pull` brings
//! back what the command changed (tar over the same ssh channel, see
//! [`super::sync`]). `credential_files` are uploaded once, into the remote
//! `$HOME`, mode 0600. There is no pseudo-terminal: ssh runs with `-T`, so
//! `supports_pty()` is false and `spawn` refuses `pty` instead of silently
//! degrading.

use super::local::{self, spawn_command};
use super::sync::{self, SyncOptions, WorkspaceSync};
use super::{sh_quote, BackendCtx, ExecConfig};
use seagent_core::exec::{ExecBackend, ExecChild, ExecRequest, ExitInfo};
use serde::Deserialize;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// `[exec.ssh]`
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SshConfig {
    /// Remote host (no `user@`: `user` is its own key).
    pub host: String,
    /// Login user; empty = the local user name, as plain `ssh <host>` does.
    pub user: String,
    /// sshd port (`-p`, omitted for 22).
    pub port: u16,
    /// Private key (`-i`); empty = ssh-agent / `~/.ssh/config` defaults.
    pub identity_file: String,
    /// Extra `-o` options forwarded verbatim (`ProxyJump=bastion`, `RemoteCommand=none`, …).
    pub options: Vec<String>,
    /// Host key policy: `accept-new` (default), `yes`, or `no`.
    pub host_key_checking: String,
    /// `-o ConnectTimeout` seconds.
    pub connect_timeout: u16,
    /// Keep one connection open between commands (`ControlMaster=auto`, `ControlPersist=300`).
    pub multiplex: bool,
    /// Remote directory the host workspace is mirrored to; `~/x` is relative to the
    /// remote home. Empty = `<remote home>/.seagent/workspace/<workspace>-<scope>`.
    pub workspace_remote_path: String,
    /// Upload changed workspace files before every command.
    pub push: bool,
    /// Download the files a command created or changed afterwards.
    pub pull: bool,
}

impl Default for SshConfig {
    fn default() -> Self {
        SshConfig {
            host: String::new(),
            user: String::new(),
            port: 22,
            identity_file: String::new(),
            options: vec![],
            host_key_checking: "accept-new".into(),
            connect_timeout: 10,
            multiplex: true,
            workspace_remote_path: String::new(),
            push: true,
            pull: true,
        }
    }
}

/// `ssh <opts> <target>` flags, shared with the OpenShell backend (which runs
/// ssh against a generated `-F` config).
pub(crate) fn ssh_opts(cfg: &SshConfig, control: &str) -> Vec<String> {
    let mut a: Vec<String> = vec!["-T".into(), "-o".into(), "BatchMode=yes".into()];
    if cfg.multiplex && !control.is_empty() {
        a.extend(["-o".into(), "ControlMaster=auto".into(), "-o".into(), format!("ControlPath={control}")]);
        a.extend(["-o".into(), "ControlPersist=300".into()]);
    }
    a.extend(["-o".into(), format!("ConnectTimeout={}", cfg.connect_timeout.max(1))]);
    if cfg.host_key_checking == "no" {
        // OpenClaw `strictHostKeyChecking: false`: never touch the user's known_hosts.
        a.extend(["-o".into(), "StrictHostKeyChecking=no".into(), "-o".into(), "UserKnownHostsFile=/dev/null".into()]);
    } else {
        a.extend(["-o".into(), format!("StrictHostKeyChecking={}", cfg.host_key_checking)]);
    }
    if cfg.port != 0 && cfg.port != 22 {
        a.extend(["-p".into(), cfg.port.to_string()]);
    }
    if !cfg.identity_file.is_empty() {
        let id = seagent_core::tool::expand_home(&cfg.identity_file);
        a.extend(["-i".into(), id.display().to_string(), "-o".into(), "IdentitiesOnly=yes".into()]);
    }
    for o in &cfg.options {
        a.extend(["-o".into(), o.clone()]);
    }
    a
}

/// `user@host`, or plain `host` when no user is configured.
pub(crate) fn target(cfg: &SshConfig) -> String {
    if cfg.user.is_empty() {
        cfg.host.clone()
    } else {
        format!("{}@{}", cfg.user, cfg.host)
    }
}

/// Fail fast with the Hermes message when the client is missing or broken.
fn ensure_ssh_client() -> Result<(), String> {
    if local::which("ssh").is_none() {
        return Err("exec backend ssh: `ssh` is not installed or not in PATH (install the OpenSSH client: apt install openssh-client)".into());
    }
    let out = super::probe_output(Command::new("ssh").arg("-V"));
    match out {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!("exec backend ssh: `ssh -V` failed ({}): {}", o.status.code().map(|c| format!("exit {c}")).unwrap_or_else(|| "killed".into()), String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => Err(format!("exec backend ssh: cannot run `ssh -V`: {e}")),
    }
}

fn conn_error(cfg: &SshConfig, detail: &str) -> String {
    let t = target(cfg);
    let detail = detail.trim();
    let detail = if detail.is_empty() { "no output" } else { detail };
    format!(
        "exec backend ssh: cannot connect to {t} on port {port}: {detail} — check that {host} is up, sshd is running on port {port}, and the user can log in with the configured key; \
the connection is retried on the next command",
        port = cfg.port,
        host = cfg.host
    )
}

/// The remote command line. ssh joins its trailing arguments with spaces and hands the result
/// to the remote login shell, so `bash -c <script>` as separate argv words loses the quoting
/// (`printf 'X=%s\n' "$HOME"` arrived as `printf X=%s\n $HOME` → "printf: usage"): the script
/// must travel as one shell-quoted word (found by the real-sshd test, gen1-308).
pub(crate) fn remote_command(flag: &str, script: &str) -> String {
    format!("bash {flag} {}", super::sh_quote(script))
}

/// One probe command over a fresh/multiplexed connection (no sync, no env).
fn probe(cfg: &SshConfig, control: &str, script: &str, timeout: Duration) -> Result<(ExitInfo, Vec<u8>), String> {
    let mut cmd = Command::new("ssh");
    cmd.args(ssh_opts(cfg, control));
    cmd.arg(target(cfg));
    cmd.arg(remote_command("-c", script));
    let child = spawn_command(cmd, &ExecRequest::default(), None).map_err(|e| format!("cannot start `ssh`: {e}"))?;
    super::drain(child, timeout)
}

/// `~`-relative remote paths as absolute ones, or the per-scope default.
fn remote_root(cfg: &SshConfig, remote_home: &str, ctx: &BackendCtx) -> String {
    let home = remote_home.trim_end_matches('/');
    let p = cfg.workspace_remote_path.trim();
    if p.is_empty() {
        let name = ctx.workspace.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "workspace".into());
        return format!("{home}/.seagent/workspace/{}-{}", super::sanitize(&name), super::sanitize(&ctx.scope_key));
    }
    if p == "~" {
        return home.to_string();
    }
    match p.strip_prefix("~/") {
        Some(rest) => format!("{home}/{rest}"),
        None => p.to_string(),
    }
}

/// ControlMaster socket: short, deterministic, under the system temp dir
/// (not `<seagent data>`: unix socket paths must stay under `sun_path`'s ~104 bytes).
fn control_path(cfg: &SshConfig) -> String {
    let dir = std::env::temp_dir().join("seagent-ssh");
    let _ = std::fs::create_dir_all(&dir);
    let tag = super::sync::common::crc32(format!("{}:{}", target(cfg), cfg.port).as_bytes());
    dir.join(format!("{tag:08x}.sock")).display().to_string()
}

pub struct SshBackend {
    cfg: SshConfig,
    /// Remote `$HOME` (the anchor for `~` paths and credential files).
    remote_home: String,
    remote_root: String,
    host_ws: PathBuf,
    sync: WorkspaceSync,
    creds: Vec<String>,
    creds_done: AtomicBool,
    passthrough: Vec<String>,
    control: String,
    gone: AtomicBool,
}

impl SshBackend {
    pub fn new(cfg: &SshConfig, ecfg: &ExecConfig, ctx: &BackendCtx) -> Result<SshBackend, String> {
        if cfg.host.trim().is_empty() {
            return Err("exec backend ssh: set `[exec.ssh] host` (the machine to run commands on) and optionally `user`, `port`, `identity_file`".into());
        }
        if !["accept-new", "yes", "no"].contains(&cfg.host_key_checking.as_str()) {
            return Err(format!("exec.ssh.host_key_checking `{}`: use accept-new, yes or no", cfg.host_key_checking));
        }
        ensure_ssh_client()?;
        let control = if cfg.multiplex { control_path(cfg) } else { String::new() };
        // One round trip: proves the connection and finds the remote home (Hermes
        // `_establish_connection` + `_detect_remote_home`).
        let (ex, out) = probe(cfg, &control, "printf 'SEAGENT_HOME=%s\\n' \"$HOME\"", Duration::from_secs(15))
            .map_err(|e| conn_error(cfg, &format!("`ssh` failed: {e}")))?;
        if !ex.success() {
            return Err(conn_error(cfg, &String::from_utf8_lossy(&out)));
        }
        let text = String::from_utf8_lossy(&out);
        let detected = text.lines().find_map(|l| l.trim().strip_prefix("SEAGENT_HOME=")).unwrap_or("").trim().to_string();
        let remote_home = if detected.is_empty() {
            if cfg.user == "root" {
                "/root".to_string()
            } else if !cfg.user.is_empty() {
                format!("/home/{}", cfg.user)
            } else {
                return Err(conn_error(cfg, "the remote shell did not report $HOME"));
            }
        } else {
            detected
        };
        let root = remote_root(cfg, &remote_home, ctx);
        if !root.starts_with('/') {
            return Err(format!("exec.ssh.workspace_remote_path `{root}`: the remote workspace must be an absolute path (or `~/…`)"));
        }
        let (ex, out) = probe(cfg, &control, &format!("set -e\nmkdir -p {}\n", sh_quote(&root)), Duration::from_secs(30))
            .map_err(|e| conn_error(cfg, &format!("`ssh` failed: {e}")))?;
        if !ex.success() {
            return Err(format!("exec backend ssh: cannot create {root} on {}: {}", target(cfg), String::from_utf8_lossy(&out).trim()));
        }
        Ok(SshBackend {
            sync: WorkspaceSync::new(&ctx.workspace, &root, SyncOptions::default()),
            host_ws: ctx.workspace.clone(),
            creds: ecfg.credential_files.clone(),
            creds_done: AtomicBool::new(false),
            passthrough: ecfg.passthrough(),
            remote_home,
            remote_root: root,
            control,
            gone: AtomicBool::new(false),
            cfg: cfg.clone(),
        })
    }

    fn args(&self) -> Vec<String> {
        ssh_opts(&self.cfg, &self.control)
    }

    fn runner(&self) -> impl Fn(&str, Option<&[u8]>) -> Result<super::Capture, String> + '_ {
        move |script: &str, stdin: Option<&[u8]>| super::run_capture(self, script, stdin, Duration::from_secs(600))
    }
}

impl ExecBackend for SshBackend {
    fn id(&self) -> &str {
        "ssh"
    }
    fn describe(&self) -> String {
        let mode = match (self.cfg.push, self.cfg.pull) {
            (true, true) => "mirrored",
            (true, false) => "pushed only",
            (false, true) => "pulled only",
            (false, false) => "not synced",
        };
        format!(
            "ssh: {} port {}, workspace {mode} to {} (remote home {}){}",
            target(&self.cfg),
            self.cfg.port,
            self.remote_root,
            self.remote_home,
            if self.control.is_empty() { "" } else { " (multiplexed)" }
        )
    }
    fn spawn(&self, req: &ExecRequest) -> io::Result<Box<dyn ExecChild>> {
        if req.pty.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the ssh backend has no pseudo-terminal (ssh runs with -T, so stdin/stdout are pipes); run the command without `pty`",
            ));
        }
        let mut script = super::sync::common::env_prefix(&req.env, &self.passthrough);
        if let Some(c) = &req.cwd {
            script.push_str(&format!("mkdir -p {0} && cd {0} || exit 126\n", sh_quote(&self.map_path(c))));
        }
        script.push_str(&req.script);
        let mut cmd = Command::new("ssh");
        cmd.args(self.args());
        cmd.arg(target(&self.cfg));
        cmd.arg(remote_command(if req.login { "-lc" } else { "-c" }, &script));
        spawn_command(cmd, req, None)
    }
    fn map_path(&self, host: &Path) -> String {
        super::sync::common::map_under(&self.host_ws, &self.remote_root, host)
    }
    fn shares_host_fs(&self) -> bool {
        false
    }
    fn supports_pty(&self) -> bool {
        false
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
        if !self.control.is_empty() {
            let _ = Command::new("ssh")
                .args(["-o", &format!("ControlPath={}", self.control), "-O", "exit", &target(&self.cfg)])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            let _ = std::fs::remove_file(&self.control);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::sync::common::fakecli;
    use crate::exec::ExecEnv;
    use crate::testutil::tmpdir;
    use std::os::unix::fs::PermissionsExt;

    fn cred_file(tag: &str) -> (PathBuf, String) {
        let home = std::env::var("HOME").unwrap();
        let p = Path::new(&home).join(format!(".seagent-ssh-{tag}-{}", std::process::id()));
        std::fs::write(&p, "token=1\n").unwrap();
        let rel = format!("~/{}", p.file_name().unwrap().to_string_lossy());
        (p, rel)
    }

    #[test]
    fn ssh_argv_push_pull_credentials_and_pty_honesty() {
        // The ControlMaster socket directory lives at a fixed name in the temp dir.
        let _clean = seagent_core::tmp::scratch_path("seagent-ssh");
        let _lock = fakecli::lock_path();
        let base = tmpdir("sshbase");
        let (remote_home, ws, home) = (base.join("remotehome"), base.join("ws"), base.join("seagenthome"));
        let bin = base.join("bin");
        for d in [&remote_home, &ws, &home] {
            std::fs::create_dir_all(d).unwrap();
        }
        let log = base.join("ssh.log");
        fakecli::fake_ssh(&bin, &log, &remote_home);
        let old = fakecli::prepend_path(&bin);
        std::fs::write(ws.join("in.txt"), "from host").unwrap();
        let (cred, cred_rel) = cred_file("cred");

        let cfg = ExecConfig {
            backend: "ssh".into(),
            credential_files: vec![cred_rel],
            ssh: SshConfig { host: "remote.test".into(), user: "seagent".into(), port: 2222, ..Default::default() },
            ..Default::default()
        };
        let env = ExecEnv::new(cfg);
        let secrets: std::sync::Arc<dyn Fn(&str) -> String + Send + Sync> = std::sync::Arc::new(|s: &str| s.to_string());
        let b = env.backend("s1", &ws, &home, &secrets, false).unwrap();
        let read = || std::fs::read_to_string(&log).unwrap_or_default();

        assert_eq!(b.id(), "ssh");
        assert!(!b.shares_host_fs() && !b.supports_pty(), "ssh shares no fs and has no pty");
        assert!(read().contains("BatchMode=yes"), "{}", read());
        assert!(read().contains("seagent@remote.test"), "target user@host: {}", read());
        assert!(read().contains("-p 2222"), "port: {}", read());
        assert!(read().contains("ControlMaster=auto"), "multiplexing: {}", read());
        let mapped = b.map_path(&ws.join("a/b.txt"));
        assert!(mapped.ends_with("/a/b.txt") && mapped.starts_with('/'), "{mapped}");
        assert!(b.describe().contains("seagent@remote.test") && b.describe().contains(&mapped[..mapped.len() - "/a/b.txt".len()]));

        // push: the host workspace lands in the remote mirror, credentials in $HOME.
        b.before_exec().unwrap();
        let root = b.map_path(&ws);
        assert_eq!(std::fs::read_to_string(format!("{root}/in.txt")).unwrap(), "from host");
        assert!(read().contains("tar -xf -"), "tar push over ssh: {}", read());
        let landed = remote_home.join(cred.file_name().unwrap());
        assert_eq!(std::fs::read_to_string(&landed).unwrap(), "token=1\n");
        assert_eq!(std::fs::metadata(&landed).unwrap().permissions().mode() & 0o777, 0o600, "credentials are 0600 in the remote home");

        // exec: argv carries `bash -c <script>`, output and exit status come back.
        let req = ExecRequest { script: "cat in.txt; echo oops >&2; echo made > out.txt; exit 4".into(), cwd: Some(ws.clone()), ..Default::default() };
        let (st, out) = crate::exec::drain(b.spawn(&req).unwrap(), Duration::from_secs(20)).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert_eq!(st.code, Some(4), "{s}");
        assert!(s.contains("from host") && s.contains("oops"), "{s}");
        assert!(read().contains("bash -c 'mkdir -p"), "cwd mapped and cd'd, script sent as one quoted word: {}", read());

        // pull: what the command wrote comes back to the host workspace.
        b.after_exec().unwrap();
        assert_eq!(std::fs::read_to_string(ws.join("out.txt")).unwrap(), "made\n");

        // stdin round-trips through the pipe.
        let (st, out) = super::super::run_capture(b.as_ref(), "tr a-z A-Z", Some(b"quiet"), Duration::from_secs(20)).unwrap();
        assert!(st.success() && String::from_utf8_lossy(&out).contains("QUIET"), "{}", String::from_utf8_lossy(&out));

        // pty: refused with an actionable message, not silently ignored.
        let e = b.spawn(&ExecRequest { pty: Some((24, 80)), ..Default::default() }).err().unwrap();
        assert!(e.to_string().contains("no pseudo-terminal"), "{e}");

        b.cleanup();
        assert!(read().contains("-O exit"), "the control master is closed: {}", read());
        let _ = std::fs::remove_file(&cred);
        fakecli::restore_path(old);
    }

    #[test]
    fn ssh_config_errors_and_remote_only_mode() {
        let _lock = fakecli::lock_path();
        let base = tmpdir("sshcfg");
        let (remote_home, ws, home) = (base.join("remotehome"), base.join("ws"), base.join("seagenthome"));
        let bin = base.join("bin");
        for d in [&remote_home, &ws, &home] {
            std::fs::create_dir_all(d).unwrap();
        }
        let log = base.join("ssh.log");
        fakecli::fake_ssh(&bin, &log, &remote_home);
        let old = fakecli::prepend_path(&bin);
        let secrets: std::sync::Arc<dyn Fn(&str) -> String + Send + Sync> = std::sync::Arc::new(|s: &str| s.to_string());

        let build = |ssh: SshConfig| {
            ExecEnv::new(ExecConfig { backend: "ssh".into(), ssh, ..Default::default() }).backend("s1", &ws, &home, &secrets, false)
        };
        // No host: actionable at construction.
        let e = build(SshConfig::default()).err().unwrap();
        assert!(e.contains("[exec.ssh] host"), "{e}");
        // Bad host-key policy.
        let e = build(SshConfig { host: "h".into(), host_key_checking: "maybe".into(), ..Default::default() }).err().unwrap();
        assert!(e.contains("host_key_checking"), "{e}");
        // Unreachable host: the Hermes connection error, with the retry hint.
        let e = build(SshConfig { host: "unreachable".into(), ..Default::default() }).err().unwrap();
        assert!(e.contains("cannot connect to unreachable on port 22") && e.contains("sshd"), "{e}");
        // Remote-only mode (no push/pull): an explicit `~/work` path, nothing mirrored.
        std::fs::write(ws.join("local.txt"), "x").unwrap();
        let ssh = SshConfig { host: "remote.test".into(), user: "".into(), workspace_remote_path: "~/work".into(), push: false, pull: false, ..Default::default() };
        let b = build(ssh).unwrap();
        assert_eq!(b.map_path(&ws), format!("{}/work", remote_home.display()), "`~/work` is anchored at the remote home");
        assert!(b.describe().contains("not synced"), "{}", b.describe());
        b.before_exec().unwrap();
        assert!(read_log(&log).contains("remote.test bash -c"), "no user prefix when `user` is empty");
        assert!(!remote_home.join("work/local.txt").exists(), "push=false uploads nothing");
        let _ = remote_home;
        fakecli::restore_path(old);

        // Every `[exec.ssh]` key round-trips through config parsing (and typos are refused).
        let cfg = super::super::ExecConfig::parse(&serde_json::json!({
            "backend": "ssh",
            "ssh": {"host": "h", "user": "u", "port": 2200, "identity_file": "~/.ssh/id_ed25519",
                    "options": ["ProxyJump=bastion"], "host_key_checking": "yes", "connect_timeout": 5,
                    "multiplex": false, "workspace_remote_path": "~/w", "push": false, "pull": true}
        }))
        .unwrap();
        assert_eq!((cfg.ssh.port, cfg.ssh.connect_timeout), (2200, 5));
        assert!(!cfg.ssh.multiplex && !cfg.ssh.push && cfg.ssh.pull);
        assert_eq!(cfg.ssh.options, vec!["ProxyJump=bastion".to_string()]);
        assert!(serde_json::from_value::<SshConfig>(serde_json::json!({"host": "h", "typo": 1})).is_err());
    }

    fn read_log(p: &Path) -> String {
        std::fs::read_to_string(p).unwrap_or_default()
    }
}
