//! The web setup wizard's "finish" restarts the daemon with the new configuration, and the
//! daemon really comes back — proven with the real binary on every OS:
//!
//! `seagent setup bootstrap` → `seagent daemon start` (detached, as the desktop app runs it) →
//! `setup.apply` over `POST /setup/rpc` → the daemon stops, its restart helper (`sh` on Unix;
//! `seagent daemon start --after-pid` on Windows) starts a new one → the console answers again
//! with the saved config.
//!
//! On Windows the helper used to be a PowerShell one-liner started with `DETACHED_PROCESS`;
//! Windows PowerShell exits at once without a console, so the daemon never came back and the
//! desktop app showed "127.0.0.1 refused the connection". This test failed that way.

use seagent_core::proc::{group_alive, PidGuard};
use seagent_core::tmp::TempDir;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

fn home() -> TempDir {
    let root = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let d = TempDir::new_in(root, "seagent-run-setup-restart");
    std::fs::create_dir_all(d.path().join("h/config")).unwrap();
    std::fs::write(d.path().join("h/config/config.toml"), "[exec]\nbackend = \"local\"\n").unwrap();
    d
}

/// Relative `SEAGENT_HOME=h` keeps the socket path short (see daemon_orphan.rs).
fn seagent(d: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_seagent"));
    c.current_dir(d)
        .env("SEAGENT_HOME", "h")
        .env("SEAGENT_OFFLINE", "1")
        .env("XDG_RUNTIME_DIR", "")
        .env("NO_COLOR", "1")
        // A test runner under systemd would make this look like a service.
        .env_remove("NOTIFY_SOCKET")
        .env_remove("INVOCATION_ID")
        .env_remove("SEAGENT_DAEMON_DETACHED")
        .stdin(Stdio::null());
    c
}

fn daemon_pid(h: &Path) -> Option<i32> {
    std::fs::read_to_string(h.join("h/run/seagentd.pid")).ok()?.trim().parse().ok()
}

fn http(addr: &str, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Option<(u16, String)> {
    let mut s = std::net::TcpStream::connect_timeout(&addr.parse().ok()?, Duration::from_secs(2)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).ok()?;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    let text = String::from_utf8_lossy(&out).into_owned();
    let code = text.split_whitespace().nth(1)?.parse().ok()?;
    Some((code, text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default()))
}

fn healthy(addr: &str) -> bool {
    http(addr, "GET", "/health", &[], "").is_some_and(|(c, _)| c == 200)
}

#[test]
fn finishing_the_web_wizard_restarts_the_detached_daemon() {
    let h = home();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let addr = format!("127.0.0.1:{port}");
    let log = || std::fs::read_to_string(h.path().join("h/data/seagentd.log")).unwrap_or_default();
    let out = seagent(h.path()).args(["setup", "bootstrap", "--listen", &addr]).output().unwrap();
    assert!(out.status.success(), "bootstrap: {}", String::from_utf8_lossy(&out.stderr));
    let out = seagent(h.path()).args(["daemon", "start"]).output().unwrap();
    assert!(out.status.success(), "daemon start: {}{}", String::from_utf8_lossy(&out.stderr), log());
    assert!(seagent_core::proc::wait_until(Duration::from_secs(15), || daemon_pid(h.path()).is_some()), "no pid file: {}", log());
    let first = daemon_pid(h.path()).unwrap();
    let _g1 = PidGuard(first);
    assert!(seagent_core::proc::wait_until(Duration::from_secs(30), || healthy(&addr)), "console never answered: {}", log());

    let link = seagent(h.path()).args(["setup", "link", "--json"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&link.stdout).unwrap_or_else(|e| panic!("setup link --json: {e}: {}", String::from_utf8_lossy(&link.stdout)));
    let token = v["url"].as_str().unwrap().split_once("#token=").unwrap().1.to_string();
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "setup.apply", "params": {
        "provider": "fake", "base_url": "http://127.0.0.1:9/v1", "api_key": "sk-fake-0123456789", "model": "m1", "autostart": false}})
    .to_string();
    let (code, reply) = http(&addr, "POST", "/setup/rpc", &[("content-type", "application/json"), ("x-seagent-setup-token", &token)], &body).expect("setup.apply answered");
    assert_eq!(code, 200, "{reply}");
    assert!(reply.contains("\"ok\":true"), "{reply}");

    // The first daemon goes away and a new one, started by the helper, answers.
    let gone = seagent_core::proc::wait_until(Duration::from_secs(30), || !group_alive(first));
    assert!(gone, "the first daemon {first} did not stop: {}", log());
    let back = seagent_core::proc::wait_until(Duration::from_secs(60), || daemon_pid(h.path()).is_some_and(|p| p != first && group_alive(p)) && healthy(&addr));
    let second = daemon_pid(h.path());
    let _g2 = second.map(PidGuard);
    let text = log();
    assert!(back, "the daemon did not come back after the wizard: {text}");
    assert!(text.contains("restarting (helper pid"), "{text}");
    let cfg = std::fs::read_to_string(h.path().join("h/config/config.toml")).unwrap();
    assert!(cfg.contains("default = \"fake/m1\""), "the wizard's config is saved where the daemon reads it:\n{cfg}");
    let st = seagent(h.path()).args(["daemon", "status"]).output().unwrap();
    assert!(st.status.success(), "{}", String::from_utf8_lossy(&st.stdout));
    let _ = seagent(h.path()).args(["daemon", "stop"]).output();
}
