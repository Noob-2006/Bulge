//! Real sandbox backends (gen1-308): podman / docker / bwrap / ssh, actually run.
//!
//! The rest of the suite drives these backends through fake clients; these cases start real
//! containers, a real bubblewrap sandbox and a real sshd. All `#[ignore]` and gated on
//! `SEAGENT_REAL_TESTS=1` (`tests/real/realtest.sh` runs them):
//!
//! ```sh
//! SEAGENT_REAL_TESTS=1 cargo test -p seagent-tools real_backend -- --ignored --test-threads=1
//! # ssh: the script starts an `seagent-test-realtest-sshd-*` container and exports
//! #   SEAGENT_REAL_SSH_PORT / SEAGENT_REAL_SSH_KEY / SEAGENT_REAL_SSH_USER
//! ```
//!
//! Every container is named `seagent-test-realtest-*` and removed by a drop guard (also on a
//! failed assertion); docker is skipped (and says so) when there is no `docker` client.

use super::container::{ContainerBackend, ContainerConfig};
use super::local::{BwrapBackend, BwrapConfig};
use super::sandbox::SandboxConfig;
use super::ssh::{SshBackend, SshConfig};
use super::*;
use crate::testutil::tmpdir;
use std::sync::Arc;

const IMAGE: &str = "docker.io/library/debian:trixie-slim";

fn real() -> bool {
    let on = std::env::var("SEAGENT_REAL_TESTS").ok().as_deref() == Some("1");
    if !on {
        eprintln!("skipping: set SEAGENT_REAL_TESTS=1 to run real backend cases");
    }
    on
}

fn ctx(tag: &str, sandboxed: bool) -> BackendCtx {
    BackendCtx {
        workspace: tmpdir(&format!("real-{tag}-ws")),
        scope_key: format!("test-realtest-{tag}-{}", std::process::id()),
        secrets: Arc::new(|s: &str| s.to_string()),
        home: tmpdir(&format!("real-{tag}-home")),
        sandboxed,
    }
}

fn run(b: &dyn ExecBackend, script: &str) -> (i32, String) {
    let (st, out) = run_capture(b, script, None, Duration::from_secs(120)).unwrap_or_else(|e| panic!("{script}: {e}"));
    (st.code.unwrap_or(-1), String::from_utf8_lossy(&out).to_string())
}

/// `rm -f` of exactly the container(s) this case created, on drop.
struct Containers(String, Vec<String>);

impl Drop for Containers {
    fn drop(&mut self) {
        for n in &self.1 {
            let _ = std::process::Command::new(&self.0).args(["rm", "-f", "-t", "1", n]).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
        }
    }
}

fn exists(bin: &str, name: &str) -> bool {
    std::process::Command::new(bin).args(["container", "exists", name]).status().map(|s| s.success()).unwrap_or(false)
        || std::process::Command::new(bin).args(["ps", "-aq", "--filter", &format!("name=^{name}$")]).output().map(|o| !o.stdout.is_empty()).unwrap_or(false)
}

fn container_case(bin: &str) {
    let c = ctx(bin, true);
    std::fs::write(c.workspace.join("in.txt"), "from host\n").unwrap();
    // No stale-sandbox sweep: it would look at other `seagent-*` sandboxes on this machine.
    let cfg = ContainerConfig { binary: bin.into(), image: IMAGE.into(), prune_idle_hours: 0, prune_max_age_days: 0, userns: if bin == "podman" { "keep-id".into() } else { String::new() }, ..ContainerConfig::default() };
    let sb = SandboxConfig { workspace_access: "rw".into(), ..Default::default() };
    let be = ContainerBackend::new(&cfg, &sb, &ExecConfig::default(), &c).unwrap_or_else(|e| panic!("{e}"));
    assert!(be.name().starts_with("seagent-test-realtest-"), "{}", be.name());
    let _g = Containers(bin.into(), vec![be.name().to_string(), format!("seagent-egress-{}", c.scope_key)]);
    // Workspace round trip: the host file is visible, a file written inside lands on the host.
    let (code, out) = run(&be, "cat in.txt; pwd; echo made > out.txt; id -u");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("from host") && out.contains("/workspace"), "{out}");
    assert_eq!(std::fs::read_to_string(c.workspace.join("out.txt")).unwrap(), "made\n");
    let uid = unsafe { libc::getuid() }.to_string();
    assert!(out.lines().any(|l| l.trim() == uid), "runs as the host user {uid}: {out}");
    // Hardening is real: read-only rootfs, no network, no capabilities.
    let (code, out) = run(&be, "touch /etc/x 2>&1; echo rc=$?; cat /proc/net/route | wc -l; grep CapEff /proc/self/status");
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("Read-only file system") || out.contains("rc=1"), "read-only rootfs: {out}");
    assert!(out.lines().any(|l| l.trim() == "1"), "network none = only the route header: {out}");
    assert!(out.contains("CapEff:\t0000000000000000"), "all capabilities dropped: {out}");
    // Exit codes and a killed long-running command.
    assert_eq!(run(&be, "exit 7").0, 7);
    let mut ch = be.spawn(&ExecRequest { script: "sleep 300".into(), ..Default::default() }).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    ch.kill(true);
    let until = std::time::Instant::now() + Duration::from_secs(20);
    while ch.try_wait().unwrap().is_none() {
        assert!(std::time::Instant::now() < until, "killed command did not exit");
        std::thread::sleep(Duration::from_millis(100));
    }
    // cleanup() removes the container.
    assert!(exists(bin, be.name()), "the sandbox container is running");
    be.cleanup();
    assert!(seagent_core::proc::wait_until(Duration::from_secs(15), || !exists(bin, be.name())), "cleanup left {} behind", be.name());
}

#[test]
#[ignore]
fn real_backend_podman() {
    if !real() {
        return;
    }
    assert!(util_which("podman"), "SEAGENT_REAL_TESTS=1 but podman is missing");
    container_case("podman");
}

#[test]
#[ignore]
fn real_backend_docker() {
    if !real() {
        return;
    }
    if !util_which("docker") {
        eprintln!("SKIPPED real_backend_docker: no `docker` client on this host (podman covers the container backend)");
        return;
    }
    container_case("docker");
}

#[test]
#[ignore]
fn real_backend_bwrap() {
    if !real() {
        return;
    }
    assert!(util_which("bwrap"), "SEAGENT_REAL_TESTS=1 but bwrap is missing");
    let c = ctx("bwrap", true);
    std::fs::write(c.workspace.join("f.txt"), "inside\n").unwrap();
    let sb = SandboxConfig { workspace_access: "rw".into(), ..Default::default() };
    let b = BwrapBackend::new(&BwrapConfig::default(), &sb, &c).unwrap_or_else(|e| panic!("{e}"));
    let real_home = super::sandbox::host_home();
    let (code, out) = run(&b, &format!("cat f.txt; echo w > new.txt; ls {} 2>&1 | head -1; echo ROUTES=$(tail -n +2 /proc/net/route | wc -l); grep CapEff /proc/self/status", real_home.display()));
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("inside"), "{out}");
    assert_eq!(std::fs::read_to_string(c.workspace.join("new.txt")).unwrap(), "w\n");
    assert!(out.contains("ROUTES=0"), "no network inside bwrap: {out}");
    assert!(out.contains("CapEff:\t0000000000000000"), "{out}");
    // The real home is hidden: either missing or an empty tmpfs.
    let line = out.lines().nth(1).unwrap_or("");
    assert!(line.contains("No such file") || line.trim().is_empty() || !line.contains(".bashrc"), "real $HOME visible: {out}");
    assert_eq!(run(&b, "exit 5").0, 5);
}

#[test]
#[ignore]
fn real_backend_ssh() {
    if !real() {
        return;
    }
    let (Ok(port), Ok(key)) = (std::env::var("SEAGENT_REAL_SSH_PORT"), std::env::var("SEAGENT_REAL_SSH_KEY")) else {
        eprintln!("SKIPPED real_backend_ssh: SEAGENT_REAL_SSH_PORT / SEAGENT_REAL_SSH_KEY not set (tests/real/realtest.sh starts an sshd container)");
        return;
    };
    let c = ctx("ssh", false);
    std::fs::write(c.workspace.join("pushed.txt"), "pushed body\n").unwrap();
    let cfg = SshConfig {
        host: "127.0.0.1".into(),
        user: std::env::var("SEAGENT_REAL_SSH_USER").unwrap_or_else(|_| "root".into()),
        port: port.parse().unwrap(),
        identity_file: key,
        multiplex: false,
        push: true,
        pull: true,
        ..SshConfig::default()
    };
    let b = SshBackend::new(&cfg, &ExecConfig::default(), &c).unwrap_or_else(|e| panic!("{e}"));
    // The probe's quoting is the regression this case caught: `printf '…%s\n' "$HOME"` must
    // reach the remote shell intact (it used to arrive as separate words).
    let (code, out) = run(&b, "printf 'Q=%s|%s\\n' \"a b\" 'c'\"'\"'d'");
    assert_eq!((code, out.trim()), (0, "Q=a b|c'd"), "quoting survives the remote shell");
    // What the shell tool does around a command: push, run in the mirror, pull.
    b.before_exec().unwrap();
    let dir = b.map_path(&c.workspace);
    let (code, out) = run(&b, &format!("cd {} && cat pushed.txt && echo remote > pulled.txt && head -1 /etc/os-release", sh_quote(&dir)));
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("pushed body"), "workspace pushed to the remote: {out}");
    assert!(out.contains("Ubuntu"), "ran on the sshd container: {out}");
    b.after_exec().unwrap();
    assert_eq!(std::fs::read_to_string(c.workspace.join("pulled.txt")).unwrap(), "remote\n", "created file pulled back");
    assert_eq!(run(&b, "exit 3").0, 3);
    b.cleanup();
}

fn util_which(b: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(b).is_file()))
}
