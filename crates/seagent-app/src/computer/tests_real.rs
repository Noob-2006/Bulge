//! computer_use on a real Bot Desktop (gen1-304): TigerVNC Xvnc + Xfce started by seagent's own
//! launcher (`seagent screen start`), driven through the `computer_use` / `computer` tools with
//! real xdotool input, ImageMagick captures and AT-SPI (gdbus) accessibility.
//!
//! Needs the desktop stack, so `tests/real/realtest.sh` runs it inside the
//! `seagent-test-realtest-desktop-*` container (image `tests/real/realtest/Containerfile`):
//!
//! ```sh
//! SEAGENT_REAL_TESTS=1 SEAGENT_REAL_DESKTOP=1 <seagent-app test binary> --ignored --exact \
//!     computer::tests_real::real_bot_desktop_computer_use
//! ```
//!
//! `SEAGENT_REAL_DESKTOP=1` is the "this machine may grow an Xvnc screen" opt-in on top of
//! `SEAGENT_REAL_TESTS=1`; the desktop and the target app are stopped by guards on any exit.

use super::fake_driver::{ctx, find_json, run};
use seagent_browser::control::screen::Desktop;
use seagent_core::proc::{spawn_tied, wait_until, ChildGuard};
use serde_json::{json, Value};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

fn gate() -> bool {
    let on = std::env::var("SEAGENT_REAL_TESTS").ok().as_deref() == Some("1") && std::env::var("SEAGENT_REAL_DESKTOP").ok().as_deref() == Some("1");
    if !on {
        eprintln!("skipping: needs SEAGENT_REAL_TESTS=1 and SEAGENT_REAL_DESKTOP=1 (run tests/real/realtest.sh)");
    }
    on
}

/// Stops the Bot Desktop (Xvnc + Xfce) on drop.
struct Screen(Desktop);

impl Drop for Screen {
    fn drop(&mut self) {
        self.0.stop();
    }
}

fn sh(env: &[(String, String)], args: &[&str]) -> String {
    let o = Command::new(args[0]).args(&args[1..]).envs(env.iter().cloned()).output().unwrap_or_else(|e| panic!("{}: {e}", args[0]));
    String::from_utf8_lossy(&o.stdout).to_string()
}

#[test]
#[ignore]
fn real_bot_desktop_computer_use() {
    if !gate() {
        return;
    }
    let home = seagent_core::tmp::TempDir::new("seagent-cu-real");
    let d = Desktop::new(home.path());
    let st = d.start().unwrap_or_else(|e| panic!("Bot Desktop did not start: {e}"));
    let screen = Screen(d);
    eprintln!("bot desktop: {st:?}");
    let env = screen.0.published_env();
    assert!(env.iter().any(|(k, _)| k == "DISPLAY"), "the launcher publishes DISPLAY: {env:?}");

    // The app the agent will operate: a zenity entry dialog that prints what was typed.
    let mut z = Command::new("zenity");
    z.args(["--entry", "--title=seagent-target", "--text=Name"]).envs(env.iter().cloned()).env("GTK_MODULES", "gail:atk-bridge").env("NO_AT_BRIDGE", "0").stdout(Stdio::piped()).stderr(Stdio::null());
    let mut app = ChildGuard::group(spawn_tied(z, false).unwrap());
    assert!(wait_until(Duration::from_secs(20), || !sh(&env, &["xdotool", "search", "--name", "seagent-target"]).trim().is_empty()), "zenity window never mapped");

    let t = toml::from_str::<toml::Table>("enabled = true\nbackend = \"xdotool\"\nvision = false\ntools = [\"computer_use\", \"computer\"]\n").unwrap();
    let tools = super::tools(&t).unwrap();
    let cu = tools.iter().find(|x| x.spec().name == "computer_use").expect("computer_use registered");
    let oc = tools.iter().find(|x| x.spec().name == "computer").expect("computer registered");
    let c = ctx(home.path(), "real-cu");

    // capture: a real PNG of the Bot Desktop at its configured geometry.
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "capture", "mode": "vision"}));
    assert!(!o.is_error, "{}", o.content);
    eprintln!("capture: {}", o.content.chars().take(400).collect::<String>());
    assert!(o.content.contains("png") || o.content.contains("PNG") || o.content.contains("image"), "{}", o.content);

    // AT-SPI: the app is visible in the accessibility tree.
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "list_apps"}));
    assert!(!o.is_error, "{}", o.content);
    assert!(o.content.to_lowercase().contains("zenity"), "AT-SPI lists zenity: {}", o.content);

    // Input: focus the dialog, type into its entry, press Return → zenity prints the text.
    // focus_app goes through AT-SPI actions; GTK dialogs may not implement them (zenity
    // answers NotSupported), so its verdict is logged, not asserted — the window is raised
    // with xdotool and the rest of the input path is asserted end to end.
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "focus_app", "app": "zenity", "raise_window": true}));
    eprintln!("focus_app: {}", o.content.chars().take(200).collect::<String>());
    let win = sh(&env, &["xdotool", "search", "--name", "seagent-target"]).lines().next().unwrap_or("").to_string();
    let _ = sh(&env, &["xdotool", "windowactivate", "--sync", &win]);
    // XTest input goes to the focused window: wait until the window manager has given it focus.
    assert!(wait_until(Duration::from_secs(10), || sh(&env, &["xdotool", "getwindowfocus"]).trim() == win), "zenity never got focus");
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "type", "text": "hello seagent"}));
    eprintln!("type: {}", o.content.chars().take(300).collect::<String>());
    assert!(!o.is_error, "{}", o.content);
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "key", "keys": "Return"}));
    eprintln!("key: {}", o.content.chars().take(300).collect::<String>());
    assert!(!o.is_error, "{}", o.content);
    assert!(wait_until(Duration::from_secs(10), || matches!(app.child().try_wait(), Ok(Some(_)))), "zenity did not close on Return");
    let mut typed = String::new();
    app.child().stdout.take().unwrap().read_to_string(&mut typed).unwrap();
    assert_eq!(typed.trim(), "hello seagent", "the text computer_use typed reached the app");

    // Pointer: a click lands where it was asked to.
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "click", "coordinate": [123, 77]}));
    assert!(!o.is_error, "{}", o.content);
    let loc = sh(&env, &["xdotool", "getmouselocation"]);
    assert!(loc.contains("x:123") && loc.contains("y:77"), "pointer at {loc}");

    // The OpenClaw-shaped `computer` tool on the same screen.
    let (o, v) = run(oc.as_ref(), &c, json!({"action": "screenshot"}));
    assert!(!o.is_error, "{}", o.content);
    let shot: Value = if v.is_null() { find_json(&o.content, "width") } else { v };
    eprintln!("computer screenshot: {}", shot.to_string().chars().take(300).collect::<String>());
    drop(screen);
}

/// The Windows substitute of the case above, on this host's own desktop (no Xvnc there): a
/// WinForms window seagent starts (`seagent-target`: a Name box and a Submit button) is found
/// through `list_windows` / `list_apps` (EnumWindows), captured with its UI Automation elements
/// (`capture mode=som app=…`, `get_window_state`), filled through UIA `set_value`, typed into
/// with SendInput once `focus_app` really gave it the foreground (never typed otherwise: the
/// keys would land in the user's window), and submitted through the button's UIA Invoke. The
/// window's own output proves every step landed.
///
/// ```text
/// SEAGENT_REAL_TESTS=1 SEAGENT_REAL_DESKTOP=1 cargo test -p seagent-app real_windows_host_computer_use -- --ignored
/// ```
#[cfg(windows)]
#[test]
#[ignore]
fn real_windows_host_computer_use() {
    if !gate() {
        return;
    }
    let home = seagent_core::tmp::TempDir::new("seagent-cu-real-win");
    let out = home.path().join("submitted.txt");
    const FORM: &str = "Add-Type -AssemblyName System.Windows.Forms; $f = New-Object Windows.Forms.Form; $f.Text = 'seagent-target'; $f.Width = 420; $f.Height = 200; $f.StartPosition = 'CenterScreen'; $f.TopMost = $true; $t = New-Object Windows.Forms.TextBox; $t.AccessibleName = 'Name'; $t.Left = 20; $t.Top = 20; $t.Width = 360; $b = New-Object Windows.Forms.Button; $b.Text = 'Submit'; $b.Left = 20; $b.Top = 60; $b.Width = 120; $b.Add_Click({ [IO.File]::WriteAllText($env:SEAGENT_TARGET_OUT, $t.Text); $f.Close() }); $f.Controls.Add($t); $f.Controls.Add($b); [void]$f.ShowDialog()";
    let mut ps = Command::new("powershell");
    ps.args(["-NoProfile", "-NonInteractive", "-STA", "-Command", FORM]).env("SEAGENT_TARGET_OUT", &out).stdout(Stdio::null()).stderr(Stdio::null());
    let mut app = ChildGuard::group(spawn_tied(ps, false).unwrap());

    let t = toml::from_str::<toml::Table>("enabled = true\nbackend = \"native\"\ntools = [\"computer_use\", \"computer\"]\n").unwrap();
    let tools = super::tools(&t).unwrap();
    let cu = tools.iter().find(|x| x.spec().name == "computer_use").expect("computer_use registered");
    let oc = tools.iter().find(|x| x.spec().name == "computer").expect("computer registered");
    let c = ctx(home.path(), "real-cu-win");

    // list_windows (both tools) and list_apps: the target window, its app, no AT-SPI anywhere.
    let mut listed = Value::Null;
    assert!(
        wait_until(Duration::from_secs(30), || {
            let (o, v) = run(cu.as_ref(), &c, json!({"action": "list_windows", "target": "host"}));
            assert!(!o.content.contains("AT-SPI"), "{}", o.content);
            listed = v;
            o.content.contains("seagent-target")
        }),
        "the target window never showed up in list_windows: {listed}"
    );
    let win = listed["windows"].as_array().unwrap().iter().find(|w| w["title"] == "seagent-target").cloned().unwrap();
    assert!(win["windowRef"].as_str().unwrap().starts_with("hwnd:"), "{win}");
    assert_eq!(win["app"], "powershell", "{win}");
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "list_apps", "target": "host"}));
    assert!(!o.is_error && o.content.contains("powershell"), "{}", o.content);
    let (o, _) = run(oc.as_ref(), &c, json!({"action": "list_windows"}));
    assert!(!o.is_error && o.content.contains("seagent-target"), "{}", o.content);

    // capture: a screenshot plus the window's UIA elements (som), and ax alone.
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "capture", "mode": "som", "app": "seagent-target", "target": "host"}));
    assert!(!o.is_error, "{}", o.content);
    eprintln!("capture som: {}", o.content.chars().take(600).collect::<String>());
    let (o, ax) = run(cu.as_ref(), &c, json!({"action": "capture", "mode": "ax", "app": "seagent-target", "target": "host"}));
    assert!(!o.is_error && !o.content.contains("accessibility tree unavailable"), "{}", o.content);
    let elements = if ax["elements"].is_array() { ax["elements"].clone() } else { find_json(&o.content, "elements")["elements"].clone() };
    let index_of = |role: &str, label: &str| elements.as_array().and_then(|es| es.iter().find(|e| e["role"] == role && e["label"] == label)).and_then(|e| e["index"].as_u64()).unwrap_or_else(|| panic!("no {role} {label:?} in {elements}"));
    let entry = index_of("entry", "Name");
    let _ = index_of("push button", "Submit");

    // set_value through UIA ValuePattern.
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "set_value", "element": entry, "value": "hello seagent", "target": "host"}));
    assert!(!o.is_error && o.content.contains("\"verified\":true"), "{}", o.content);

    // Real keyboard input only once the window is really in front. SendInput reaches whatever
    // window is in front, and raising takes the foreground from the user: both are opt-in with
    // SEAGENT_REAL_INPUT=1, on a desktop nobody is using at the time.
    let mut expect = "hello seagent".to_string();
    let input = std::env::var("SEAGENT_REAL_INPUT").ok().as_deref() == Some("1");
    if input {
        let (o, _) = run(cu.as_ref(), &c, json!({"action": "focus_app", "app": "seagent-target", "raise_window": true, "target": "host"}));
        eprintln!("focus_app: {}", o.content.chars().take(300).collect::<String>());
    }
    let front = input && wait_until(Duration::from_secs(5), || {
        let (_, v) = run(cu.as_ref(), &c, json!({"action": "list_windows", "target": "host"}));
        v["windows"].as_array().into_iter().flatten().any(|w| w["title"] == "seagent-target" && w["focused"] == true)
    });
    if front {
        // The Name box has the focus inside the form (its first control): end of line, then type.
        let (o, _) = run(cu.as_ref(), &c, json!({"action": "key", "keys": "end", "target": "host"}));
        assert!(!o.is_error, "{}", o.content);
        let (o, _) = run(cu.as_ref(), &c, json!({"action": "type", "text": " typed", "target": "host"}));
        assert!(!o.is_error, "{}", o.content);
        expect.push_str(" typed");
    } else {
        eprintln!("SendInput typing skipped (SEAGENT_REAL_INPUT=1 not set, or another window kept the foreground)");
    }

    // Submit through the button's UIA Invoke (computer: get_window_state → left_click elementRef).
    let (o, st) = run(oc.as_ref(), &c, json!({"action": "get_window_state", "windowRef": win["windowRef"]}));
    assert!(!o.is_error, "{}", o.content);
    let st: Value = if st.is_null() { o.content.find('{').and_then(|i| serde_json::from_str(&o.content[i..]).ok()).unwrap_or_default() } else { st };
    let submit = st["observation"]["elements"].as_array().into_iter().flatten().find(|e| e["label"] == "Submit").and_then(|e| e["elementRef"].as_str()).map(str::to_string).unwrap_or_else(|| panic!("no Submit in {st}"));
    let (o, _) = run(oc.as_ref(), &c, json!({"action": "left_click", "elementRef": submit}));
    assert!(!o.is_error, "{}", o.content);
    assert!(wait_until(Duration::from_secs(10), || matches!(app.child().try_wait(), Ok(Some(_)))), "the form did not close on Submit");
    assert_eq!(std::fs::read_to_string(&out).unwrap(), expect, "what computer_use set and typed reached the window");
}
