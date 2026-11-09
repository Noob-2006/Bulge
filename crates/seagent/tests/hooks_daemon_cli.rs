//! G14: `gateway_start` / `gateway_stop` (`HookEvent::DaemonStart` / `DaemonStop`) really fire.
//!
//! The implementation and the wiring were already there, but nothing proved the events reach a
//! hook: this starts the real `seagent daemon run` with two shell hooks that record their stdin, then
//! shuts it down the way a user does (`seagent daemon stop`) and checks both markers. Only the child
//! this test started is ever signalled, and every path lives under the throwaway SEAGENT_HOME.

use seagent_core::tmp::TempDir;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A throwaway `SEAGENT_HOME`; the guard removes the whole tree when the test ends, also on panic.
fn home(tag: &str) -> TempDir {
    let root = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let d = TempDir::new_in(root, &format!("seagent-hooks-daemon-{tag}"));
    std::fs::create_dir_all(d.path().join("config")).unwrap();
    d
}

/// Run the real binary against the throwaway home (never a provider key, never the real home).
fn seagent(h: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_seagent"))
        .args(args)
        .env("SEAGENT_HOME", h)
        // Offline by default: no models.dev price download from a fresh SEAGENT_HOME.
        .env("SEAGENT_OFFLINE", "1")
        .env_remove("OPENAI_API_KEY")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("XAI_API_KEY")
        .env_remove("GOOGLE_API_KEY")
        .output()
        .expect("run seagent");
    let code = out.status.code().unwrap_or(-1);
    (code, format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr)))
}

fn wait_until(deadline: Duration, mut f: impl FnMut() -> bool) -> bool {
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// A daemon hook receives the event as JSON on stdin (`hook_event_name` is the Claude-style
/// name). Both hook markers must appear: one when the daemon comes up, one when it shuts down.
#[test]
fn gateway_start_and_stop_hooks_fire_around_the_daemon() {
    let seagenth = home("gateway");
    let h = seagenth.path().to_path_buf();
    let marks = h.join("marks");
    std::fs::create_dir_all(&marks).unwrap();
    let (start, stop) = (marks.join("start.json"), marks.join("stop.json"));
    std::fs::write(
        h.join("config/config.toml"),
        format!(
            "# consent for the two shell hooks below (a new [[hooks]] entry needs it once)\n\
             [hooks_extra]\n\
             auto_accept = true\n\
             \n\
             [[hooks]]\n\
             event = \"gateway_start\"\n\
             timeout_secs = 5\n\
             command = \"cat > {}\"\n\
             \n\
             [[hooks]]\n\
             event = \"gateway_stop\"\n\
             timeout_secs = 5\n\
             command = \"cat > {}\"\n",
            // The hook command is a shell line: Windows' Git Bash wants `C:/…` (and the TOML
            // string then needs no escaping); Unix: the path as is.
            seagent_core::platform::shell::path_str(&start),
            seagent_core::platform::shell::path_str(&stop)
        ),
    )
    .unwrap();
    let ws = h.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let log = std::fs::File::create(h.join("daemon.log")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_seagent"));
    cmd.args(["daemon", "run", "-w", ws.to_str().unwrap()])
        .env("SEAGENT_HOME", &h)
        .env("SEAGENT_OFFLINE", "1")
        .env_remove("OPENAI_API_KEY")
        .env_remove("ANTHROPIC_API_KEY")
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    // Tied to this test process and guarded: a failed assertion or an interrupted run stops the
    // daemon and its whole process group (new-002).
    let mut guard = seagent_core::proc::ChildGuard::group(seagent_core::proc::spawn_tied(cmd, true).expect("spawn seagentd"));
    let child = guard.child();

    // The daemon answered: the start hook must have run (it is emitted before the socket serves).
    let up = wait_until(Duration::from_secs(25), || seagent(&h, &["daemon", "status"]).0 == 0);
    if !up {
        let _ = child.kill();
        let _ = child.wait();
        let text = std::fs::read_to_string(h.join("daemon.log")).unwrap_or_default();
        panic!("seagentd did not come up; log:\n{text}");
    }
    let started = wait_until(Duration::from_secs(5), || start.exists());
    let start_json = std::fs::read_to_string(&start).unwrap_or_default();
    assert!(started, "a gateway_start hook did not run when the daemon came up: {start_json:?}");

    assert_eq!(seagent(&h, &["daemon", "stop"]).0, 0, "`seagent daemon stop` is how a user stops seagentd");
    let exited = wait_until(Duration::from_secs(20), || matches!(child.try_wait(), Ok(Some(_))));
    if !exited {
        let _ = child.kill();
    }
    let _ = child.wait();
    assert!(exited, "the daemon did not exit within 20s of `seagent daemon stop`");
    assert!(wait_until(Duration::from_secs(5), || stop.exists()), "a gateway_stop hook did not run when the daemon shut down");

    let start_json: serde_json::Value = serde_json::from_str(start_json.trim()).expect("the hook received JSON on stdin");
    assert_eq!(start_json["hook_event_name"], "DaemonStart", "{start_json}");
    assert!(start_json["pid"].as_u64().unwrap_or(0) > 0, "the daemon's own pid: {start_json}");
    assert_eq!(start_json["cwd"].as_str(), ws.to_str(), "{start_json}");
    let stop_json: serde_json::Value = serde_json::from_str(std::fs::read_to_string(&stop).unwrap_or_default().trim()).expect("stop hook JSON");
    assert_eq!(stop_json["hook_event_name"], "DaemonStop", "{stop_json}");
    assert_eq!(stop_json["reason"], "shutdown", "an orderly stop says why: {stop_json}");

}
