//! Real-Chromium cases (gen1-303), split out of the old single `real_chromium_end_to_end`.
//!
//! All `#[ignore]`: run with `SEAGENT_REAL_TESTS=1 cargo test -p seagent-browser real_ -- --ignored
//! --test-threads=1` (or `tests/real/realtest.sh`). Without `SEAGENT_REAL_TESTS=1` an `--ignored`
//! run skips them, so a blanket `--ignored` never starts a browser by surprise.
//!
//! Every case holds a [`Browsers`] guard: the managed browser is stopped (and its process group
//! killed) when the case ends, including on a failed assertion — the launcher additionally ties
//! Chrome to this process with `PR_SET_PDEATHSIG`, so even an interrupted run leaves nothing.

use crate::config::BrowserConfig;
use crate::tests::{call, ctx, serve, tool, PAGE, SERIAL};
use seagent_core::ToolCtx;
use serde_json::{json, Value};
use std::time::Duration;

/// `SEAGENT_REAL_TESTS=1` and a Chromium-family browser, else `None` (the case is skipped).
pub(crate) fn real_gate() -> Option<std::path::PathBuf> {
    if std::env::var("SEAGENT_REAL_TESTS").ok().as_deref() != Some("1") {
        eprintln!("skipping: set SEAGENT_REAL_TESTS=1 to run real-browser cases");
        return None;
    }
    match crate::launch::find_executable("") {
        Ok(p) => Some(p),
        Err(e) => panic!("SEAGENT_REAL_TESTS=1 but no browser: {e}"),
    }
}

/// Stops every browser this process manages, and kills the process groups it saw, on drop.
pub(crate) struct Browsers(pub std::sync::Mutex<Vec<i32>>);

impl Browsers {
    pub fn new() -> Self {
        Browsers(Default::default())
    }
    fn note(&self) {
        for b in crate::manager::global().status().as_array().cloned().unwrap_or_default() {
            if let Some(p) = b["pid"].as_i64() {
                self.0.lock().unwrap().push(p as i32);
            }
        }
    }
}

impl Drop for Browsers {
    fn drop(&mut self) {
        self.note();
        crate::manager::global().stop_all();
        for p in self.0.lock().unwrap().drain(..) {
            seagent_core::proc::kill_group(p, Duration::from_secs(2));
        }
    }
}

struct Case {
    cfg: BrowserConfig,
    c: ToolCtx,
    base: String,
    snap: String,
}

fn open(tag: &str) -> Case {
    let base = serve(PAGE);
    let cfg = BrowserConfig { backend: "local".into(), enabled: toml::Value::Boolean(true), default_profile: format!("real{tag}{}", std::process::id()), ..Default::default() };
    let c = ctx(&format!("real-{tag}"), &format!("sess-real-{tag}"));
    let (ok, v, raw) = call(&cfg, &c, "browser_navigate", json!({"url": format!("{base}/")}));
    assert!(ok, "{raw}");
    assert_eq!(v["title"], "Real Test");
    let snap = v["snapshot"].as_str().unwrap().to_string();
    Case { cfg, c, base, snap }
}

fn r(snap: &str, name: &str) -> String {
    snap.lines().find(|l| l.contains(name)).and_then(|l| l.split("[ref=").nth(1)).map(|r| r.split(']').next().unwrap().to_string()).unwrap_or_else(|| panic!("no ref for {name} in {snap}"))
}

fn js(k: &Case, e: &str) -> Value {
    call(&k.cfg, &k.c, "browser_console", json!({"expression": e})).1["result"].clone()
}

#[test]
#[ignore]
fn real_click_type_and_select() {
    let Some(_) = real_gate() else { return };
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _b = Browsers::new();
    let k = open("input");
    let (ok, _, raw) = call(&k.cfg, &k.c, "browser_click", json!({"ref": r(&k.snap, "Press me")}));
    assert!(ok, "{raw}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(js(&k, "document.getElementById('out').textContent"), "clicked");
    let (ok, _, raw) = call(&k.cfg, &k.c, "browser_type", json!({"ref": r(&k.snap, "\"Name\""), "text": "héllo wörld"}));
    assert!(ok, "{raw}");
    assert_eq!(js(&k, "document.getElementById('name').value"), "héllo wörld");
    let o = tool(&k.cfg, "browser").call(&k.c, json!({"action": "act", "kind": "select", "ref": r(&k.snap, "Color"), "values": ["Green"]}));
    assert!(!o.is_error, "{}", o.content);
    assert_eq!(js(&k, "document.getElementById('s').value"), "g");
}

#[test]
#[ignore]
fn real_console_errors_and_evaluate() {
    let Some(_) = real_gate() else { return };
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _b = Browsers::new();
    let k = open("console");
    let _ = call(&k.cfg, &k.c, "browser_click", json!({"ref": r(&k.snap, "Press me")}));
    std::thread::sleep(Duration::from_millis(300));
    let (_, v, _) = call(&k.cfg, &k.c, "browser_console", json!({}));
    assert!(v["console_messages"].to_string().contains("btn clicked") && v["js_errors"].to_string().contains("boom"), "{v}");
    let o = tool(&k.cfg, "browser").call(&k.c, json!({"action": "act", "kind": "evaluate", "fn": "() => document.querySelectorAll('button').length"}));
    assert!(o.content.contains("\"result\": 2"), "{}", o.content);
    let o = tool(&k.cfg, "browser").call(&k.c, json!({"action": "text", "selector": "h1"}));
    assert!(o.content.contains("Hello seagent"), "{}", o.content);
}

#[test]
#[ignore]
fn real_dialog_accept() {
    let Some(_) = real_gate() else { return };
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _b = Browsers::new();
    let k = open("dialog");
    let _ = call(&k.cfg, &k.c, "browser_click", json!({"ref": r(&k.snap, "\"Confirm\"")}));
    std::thread::sleep(Duration::from_millis(300));
    let (_, v, raw) = call(&k.cfg, &k.c, "browser_snapshot", json!({}));
    assert!(raw.contains("pending_dialogs") || v["pending_dialogs"].is_array(), "{raw}");
    let (ok, _, raw) = call(&k.cfg, &k.c, "browser_dialog", json!({"action": "accept"}));
    assert!(ok, "{raw}");
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(js(&k, "document.getElementById('out').textContent"), "yes");
}

#[test]
#[ignore]
fn real_upload_and_download() {
    let Some(_) = real_gate() else { return };
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _b = Browsers::new();
    let k = open("files");
    let t = tool(&k.cfg, "browser");
    std::fs::write(k.c.workspace.join("u.txt"), "upload body").unwrap();
    let o = t.call(&k.c, json!({"action": "upload", "paths": ["u.txt"], "inputRef": r(&k.snap, "Upload")}));
    assert!(!o.is_error, "{}", o.content);
    assert_eq!(js(&k, "document.getElementById('f').files[0].name"), "u.txt");
    let o = t.call(&k.c, json!({"action": "download", "ref": r(&k.snap, "Download file"), "path": "dl.txt"}));
    assert!(!o.is_error, "{}", o.content);
    assert_eq!(std::fs::read_to_string(k.c.workspace.join("dl.txt")).unwrap(), "download me");
}

#[test]
#[ignore]
fn real_screenshot_pdf_and_vision() {
    let Some(_) = real_gate() else { return };
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _b = Browsers::new();
    let k = open("render");
    let t = tool(&k.cfg, "browser");
    let (ok, v, raw) = call(&k.cfg, &k.c, "browser_vision", json!({"question": "what?", "annotate": true}));
    assert!(ok, "{raw}");
    assert!(std::fs::read(v["screenshot_path"].as_str().unwrap()).unwrap().starts_with(b"\x89PNG"));
    let o = t.call(&k.c, json!({"action": "screenshot", "labels": true, "path": "shot.png"}));
    assert!(!o.is_error && std::fs::read(k.c.workspace.join("shot.png")).unwrap().starts_with(b"\x89PNG"), "{}", o.content);
    let o = t.call(&k.c, json!({"action": "pdf", "path": "p.pdf"}));
    assert!(std::fs::read(k.c.workspace.join("p.pdf")).unwrap().starts_with(b"%PDF"), "{}", o.content);
    let o = t.call(&k.c, json!({"action": "emulate", "timezoneId": "Asia/Taipei", "locale": "zh-TW"}));
    assert!(!o.is_error, "{}", o.content);
    assert_eq!(js(&k, "Intl.DateTimeFormat().resolvedOptions().timeZone"), "Asia/Taipei");
}

#[test]
#[ignore]
fn real_vault_fill_is_model_blind() {
    let Some(_) = real_gate() else { return };
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _b = Browsers::new();
    let k = open("vault");
    let origin = crate::vault::normalize_origin(&k.base).unwrap();
    let it = crate::vault::add(&k.c.home, "login", "local", &origin, std::collections::BTreeMap::from([("identifier".into(), "me@x.example".into()), ("password".into(), "Very-Secret-Pw-42".into())])).unwrap();
    let (ok, v, raw) = call(&k.cfg, &k.c, "browser_vault", json!({"action": "fill", "handle": it.id}));
    assert!(ok && v["filled_fields"] == 1, "{raw}");
    assert!(!raw.contains("Very-Secret-Pw-42"));
    assert_eq!(js(&k, "document.querySelector('input[type=password]').value"), "[REDACTED]");
}

#[test]
#[ignore]
fn real_tabs_cdp_and_stop_kills_the_group() {
    let Some(_) = real_gate() else { return };
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _b = Browsers::new();
    let k = open("life");
    let t = tool(&k.cfg, "browser");
    let o = t.call(&k.c, json!({"action": "open", "url": format!("{}/second", k.base)}));
    assert!(!o.is_error, "{}", o.content);
    let o = t.call(&k.c, json!({"action": "tabs"}));
    assert!(o.content.contains("/second"), "{}", o.content);
    let (ok, v, _) = call(&k.cfg, &k.c, "browser_cdp", json!({"method": "Browser.getVersion"}));
    assert!(ok && v["result"]["product"].as_str().unwrap().contains('/'));
    let st = crate::manager::global().status();
    let pid = st.as_array().and_then(|a| a.iter().find_map(|b| b["pid"].as_i64())).expect("managed browser pid") as i32;
    assert!(seagent_core::proc::group_alive(pid));
    let o = t.call(&k.c, json!({"action": "stop"}));
    assert!(o.content.contains("\"stopped\":true"), "{}", o.content);
    assert!(seagent_core::proc::wait_until(Duration::from_secs(10), || !seagent_core::proc::group_alive(pid)), "browser group {pid} survived stop");
}

/// Child half of [`real_browser_dies_with_a_panicking_test`]: launches a real Chrome through
/// the tools, records its pid, then panics without any guard.
#[test]
#[ignore]
fn real_panic_helper() {
    let Ok(out) = std::env::var("SEAGENT_BT_PANIC_PIDFILE") else { return };
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let k = open("panic");
    let st = crate::manager::global().status();
    let pid = st.as_array().and_then(|a| a.iter().find_map(|b| b["pid"].as_i64())).expect("pid");
    std::fs::write(out, pid.to_string()).unwrap();
    std::mem::forget(k);
    panic!("deliberate panic with a real browser running");
}

/// new-001 with a real browser: the test process panics, Chrome (and its whole group) goes.
#[test]
#[ignore]
fn real_browser_dies_with_a_panicking_test() {
    let Some(_) = real_gate() else { return };
    let dir = seagent_core::tmp::TempDir::new("seagent-bt-panic");
    let pidfile = dir.path().join("pid");
    let st = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests_real::real_panic_helper", "--ignored", "--test-threads=1"])
        .env("SEAGENT_BT_PANIC_PIDFILE", &pidfile)
        // The helper cannot clean up after a panic: its scratch trees land in ours.
        .env("TMPDIR", dir.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!st.success());
    let pid: i32 = std::fs::read_to_string(&pidfile).expect("helper wrote the pid").trim().parse().unwrap();
    let gone = seagent_core::proc::wait_until(Duration::from_secs(10), || !seagent_core::proc::group_alive(pid));
    if !gone {
        seagent_core::proc::kill_group(pid, Duration::from_secs(2));
    }
    assert!(gone, "Chrome group {pid} outlived the panicking test process");
}

/// A stand-in "browser": writes `DevToolsActivePort` into its `--user-data-dir` (what the
/// launcher waits for), then becomes a long `sleep`. Lets the launcher's process tying be
/// tested on every run, without Chrome.
fn fake_browser(dir: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let exe = dir.join("fake-chrome");
    std::fs::write(&exe, "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --user-data-dir=*) d=\"${a#*=}\";; esac; done\nprintf '9\\n/devtools/browser/fake\\n' > \"$d/DevToolsActivePort\"\nexec sleep 300\n").unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    exe
}

/// Child half of [`launcher_ties_the_browser_to_a_panicking_process`].
#[test]
fn launcher_panic_helper() {
    let Ok(out) = std::env::var("SEAGENT_LAUNCH_PANIC_PIDFILE") else { return };
    let dir = seagent_core::tmp::TempDir::new("seagent-bt-launch-panic");
    let exe = fake_browser(dir.path());
    let udd = dir.path().join("profile");
    let o = crate::launch::LaunchOpts { exe: &exe, user_data_dir: &udd, headless: true, no_sandbox: false, extra_args: &[], port: 0, managed: true, env: vec![] };
    let l = crate::launch::launch(&o, Duration::from_secs(10)).unwrap();
    std::fs::write(out, l.pid.to_string()).unwrap();
    std::mem::forget(dir);
    panic!("deliberate panic with a launched browser running");
}

/// new-001 (production layer): `launch::launch` ties the browser to seagent with PDEATHSIG, so a
/// test process that panics (or any seagent that dies) takes its browser with it.
#[test]
fn launcher_ties_the_browser_to_a_panicking_process() {
    let dir = seagent_core::tmp::TempDir::new("seagent-bt-launch-tie");
    let pidfile = dir.path().join("pid");
    let st = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "tests_real::launcher_panic_helper", "--test-threads=1"])
        .env("SEAGENT_LAUNCH_PANIC_PIDFILE", &pidfile)
        .env("TMPDIR", dir.path())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!st.success(), "the helper was supposed to panic");
    let pid: i32 = std::fs::read_to_string(&pidfile).expect("helper wrote the pid").trim().parse().unwrap();
    let gone = seagent_core::proc::wait_until(Duration::from_secs(5), || !seagent_core::proc::group_alive(pid));
    if !gone {
        seagent_core::proc::kill_group(pid, Duration::from_secs(1));
    }
    assert!(gone, "the launched browser {pid} outlived its panicking parent");
}
