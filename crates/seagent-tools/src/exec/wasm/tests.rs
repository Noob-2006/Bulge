//! Backend-level tests that need no WASI fixture (the real-module tests are in
//! `tests/wasm_backend.rs`): builtins-only scripts, kill of a builtin `sleep`, path mapping, and
//! how the `auto` / explicit plans report the wasm sandbox.

use super::*;
use seagent_core::tmp::TempDir;

fn fixture(tag: &str) -> (TempDir, WasmBackend, PathBuf) {
    let t = TempDir::new(&format!("seagent-wasm-{tag}"));
    let root = t.path().canonicalize().unwrap();
    let ws = root.join("ws");
    std::fs::create_dir_all(&ws).unwrap();
    let cfg = WasmConfig { tools_dir: root.join("no-tools").display().to_string(), ..Default::default() };
    let b = WasmBackend::with_layout(cfg, &ws, true, &root.join("tmp"), &[], &root.join("home")).unwrap();
    (t, b, ws)
}

#[test]
fn builtins_run_without_any_tool_and_tools_are_reported_missing() {
    let (_t, b, ws) = fixture("builtins");
    let (st, out) = crate::exec::run_capture(&b, "echo hi; pwd; x=$((6*7)); echo $x; ls", None, Duration::from_secs(10)).unwrap();
    let out = String::from_utf8_lossy(&out).into_owned();
    assert_eq!(st, ExitInfo::code(127), "{out}");
    assert_eq!(out, format!("hi\n{}\n42\nsh: ls: command not found\n", ws.display()));
    assert_eq!(b.map_path(&ws.join("a/b")), format!("{}/a/b", ws.display()));
    assert!(!b.supports_pty() && b.shares_host_fs() && b.temp_dir() == "/tmp");
}

#[test]
fn a_builtin_sleep_is_killed() {
    let (_t, b, _) = fixture("sleep");
    let mut c = b.spawn(&ExecRequest { script: "sleep 30".into(), ..Default::default() }).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    c.kill(false);
    let t = std::time::Instant::now();
    while c.try_wait().unwrap().is_none() {
        assert!(t.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(c.try_wait().unwrap(), Some(ExitInfo { code: None, signal: Some(9) }));
}

#[test]
fn plans_report_the_interpreter_sandbox_honestly() {
    use seagent_vm::policy::{Origin, Plan};
    use seagent_vm::IsolationLevel;
    let explicit = crate::exec::os_plan(seagent_vm::policy::resolve(&seagent_vm::policy::Query { requested: "wasm", cfg: &Default::default(), data: Path::new("/nonexistent"), sandboxed: false }), false);
    assert_eq!((explicit.backend.as_str(), explicit.level, explicit.origin), ("wasm", IsolationLevel::OsSandbox, Origin::Configured));
    assert!(explicit.warning.as_deref().is_some_and(|w| w.contains("interpreter") && w.contains("weaker than a microVM")), "{explicit:?}");
    // On iOS, `auto` lands on it instead of the host.
    let host = Plan { backend: "local".into(), provider: None, level: IsolationLevel::Host, origin: Origin::AutoHost, warning: None, reason: String::new() };
    let p = crate::exec::os_plan(host, false);
    if cfg!(target_os = "ios") {
        assert_eq!((p.backend.as_str(), p.level), ("wasm", IsolationLevel::OsSandbox));
    } else {
        assert_ne!(p.backend, "wasm", "only iOS picks the interpreter by itself");
    }
}
