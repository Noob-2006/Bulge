//! `ark status sessions` and `ark status health` through the real binary: a throwaway
//! `ARK_HOME` with a small session store and no daemon (the two sub-forms nothing else
//! exercised end to end).

use std::path::{Path, PathBuf};
use std::process::Command;

/// Temp `ARK_HOME`, removed when the test ends (even on panic).
struct Home(PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn home(tag: &str) -> Home {
    let root = std::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let d = root.join(format!("ark-status-cli-{tag}-{}-{}", std::process::id(), line!()));
    std::fs::create_dir_all(&d).unwrap();
    Home(d)
}

fn ark(h: &Path, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_ark"))
        .args(args)
        .env("ARK_HOME", h)
        // Offline by default: no models.dev price download from a fresh ARK_HOME.
        .env("ARK_OFFLINE", "1")
        // No credential of the real user may leak into the report.
        .env_remove("OPENAI_API_KEY")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("XAI_API_KEY")
        .env_remove("GOOGLE_API_KEY")
        .output()
        .expect("run ark");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// Two stored sessions (`<data>/sessions/<id>/events.jsonl`), the second one newest.
fn session_store(h: &Path) -> String {
    let sessions = h.join("data").join("sessions");
    for id in ["s-older", "s-newest"] {
        let d = sessions.join(id);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("events.jsonl"), "{\"type\":\"message\",\"role\":\"user\",\"text\":\"hi\"}\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20)); // distinct mtimes decide "newest"
    }
    "s-newest".to_string()
}

#[test]
fn status_sessions_reports_the_stored_and_running_counts() {
    let h = home("sessions");
    let ws = h.0.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let newest = session_store(&h.0);
    let ws = ws.display().to_string();

    let (code, out, err) = ark(&h.0, &["status", "sessions", "--workspace", &ws]);
    assert_eq!(code, 0, "`status sessions` always exits 0: {out}{err}");
    assert!(out.contains("Sessions"), "{out}");
    assert!(out.contains("  Stored:       2"), "both stored sessions are counted: {out}");
    assert!(out.contains("unknown (arkd stopped)"), "no daemon → running is unknown, not a guess: {out}");
    assert!(out.contains("  Newest:"), "{out}");
    assert!(out.contains(&newest), "the newest session is named: {out}");

    // `--json` is the same data in one object (the shape the UI reads).
    let (code, out, err) = ark(&h.0, &["status", "sessions", "--json", "--workspace", &ws]);
    assert_eq!(code, 0, "{out}{err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("not JSON ({e}): {out}"));
    assert_eq!(v["sessions"]["count"], 2, "{v}");
    assert_eq!(v["sessions"]["running"], serde_json::Value::Null, "no arkd answered: {v}");
    assert_eq!(v["sessions"]["newest"], newest, "{v}");
    assert!(v["sessions"]["newestMs"].is_u64(), "{v}");
}

#[test]
fn status_health_reports_a_stopped_daemon_and_exits_1() {
    let h = home("health");
    std::fs::create_dir_all(h.0.join("data")).unwrap();

    let (code, out, err) = ark(&h.0, &["status", "health"]);
    assert_eq!(code, 1, "no arkd at this ARK_HOME → exit 1: {out}{err}");
    assert!(out.contains("✗ arkd: not running"), "{out}");
    assert!(out.contains("start it with `ark daemon start`"), "{out}");

    let (code, out, err) = ark(&h.0, &["status", "health", "--json"]);
    assert_eq!(code, 1, "{out}{err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap_or_else(|e| panic!("not JSON ({e}): {out}"));
    assert_eq!(v["ok"], false, "{v}");
    assert_eq!(v["socketExists"], false, "{v}");
    assert_eq!(v["pid"], serde_json::Value::Null, "{v}");
    assert_eq!(v["runningSessions"], 0, "{v}");
    assert!(v["socket"].as_str().is_some_and(|s| s.ends_with("arkd.sock")), "{v}");
    assert!(v["error"].as_str().is_some_and(|e| e.contains("no socket")), "{v}");
}
