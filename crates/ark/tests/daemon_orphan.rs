//! new-002: an `arkd` started by a harness cannot outlive it.
//!
//! The e2e suite once left a daemon running for two days after being interrupted. Two
//! production-side exits make that impossible, and both are proven here with the real binary:
//! `ARK_DAEMON_WATCH_PID` (the daemon stops when the process that started it is gone) and the
//! orphan check (the daemon stops when its control socket / ARK_HOME is deleted). Every process
//! is held by a guard from `ark_core::proc`, so even a failing assertion leaves nothing behind.

use ark_core::proc::{group_alive, ChildGuard, PidGuard};
use ark_core::tmp::TempDir;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

fn home(tag: &str) -> TempDir {
    let root = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    // Short on purpose: `<home>/run` must stay under the 80-byte runtime limit, or the socket
    // would move to /tmp/ark-<uid> (outside the throwaway home).
    let d = TempDir::new_in(root, &format!("ad{tag}"));
    assert!(d.path().join("run").as_os_str().len() <= 80, "TMPDIR too long for this test: {}", d.path().display());
    std::fs::create_dir_all(d.path().join("config")).unwrap();
    std::fs::write(d.path().join("config/config.toml"), "[exec]\nbackend = \"local\"\n").unwrap();
    d
}

fn ark(h: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ark"));
    c.env("ARK_HOME", h).env("ARK_OFFLINE", "1").env("XDG_RUNTIME_DIR", "").env_remove("OPENAI_API_KEY").env_remove("ANTHROPIC_API_KEY").stdin(Stdio::null());
    c
}

fn daemon_pid(h: &Path) -> Option<i32> {
    std::fs::read_to_string(h.join("run/arkd.pid")).ok()?.trim().parse().ok()
}

/// `ark daemon start` detaches the daemon on purpose; with `ARK_DAEMON_WATCH_PID` set to the
/// harness, the daemon follows the harness down.
#[test]
fn detached_daemon_exits_when_the_watched_harness_dies() {
    let h = home("w");
    // Stand-in for the harness process (python run.py): a sleep we own.
    let mut harness = ChildGuard::single(Command::new("sleep").arg("120").spawn().unwrap());
    let out = ark(h.path()).args(["daemon", "start"]).env("ARK_DAEMON_WATCH_PID", harness.id().to_string()).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let pid = daemon_pid(h.path()).expect("arkd.pid");
    let _g = PidGuard(pid); // started by us: never leak it, even if the assertions fail
    assert!(group_alive(pid), "daemon {pid} is up");
    let _ = harness.child().kill();
    let _ = harness.child().wait();
    let gone = ark_core::proc::wait_until(Duration::from_secs(15), || !group_alive(pid));
    let log = std::fs::read_to_string(h.path().join("data/arkd.log")).unwrap_or_default();
    assert!(gone, "arkd {pid} outlived the process it watched: {log}");
    assert!(log.contains("watched process"), "{log}");
}

/// A daemon whose ARK_HOME was deleted under it (the harness's `rmtree`) shuts itself down.
#[test]
fn daemon_exits_when_its_home_is_removed() {
    let h = home("r");
    let log = std::fs::File::create(h.path().join("arkd.log")).unwrap();
    let mut d = ChildGuard::group({
        let mut c = ark(h.path());
        c.args(["daemon", "run"]).stdout(log.try_clone().unwrap()).stderr(log);
        ark_core::proc::spawn_tied(c, true).unwrap()
    });
    assert!(ark_core::proc::wait_until(Duration::from_secs(25), || h.path().join("run/arkd.sock").exists()), "daemon never came up");
    std::thread::sleep(Duration::from_millis(500));
    std::fs::remove_dir_all(h.path().join("run")).unwrap();
    let exited = ark_core::proc::wait_until(Duration::from_secs(15), || matches!(d.child().try_wait(), Ok(Some(_))));
    let text = std::fs::read_to_string(h.path().join("arkd.log")).unwrap_or_default();
    assert!(exited, "arkd kept running with its control socket gone: {text}");
    assert!(text.contains("control socket"), "{text}");
}
