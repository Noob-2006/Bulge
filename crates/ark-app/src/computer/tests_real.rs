//! computer_use on a real Bot Desktop (gen1-304): TigerVNC Xvnc + Xfce started by ark's own
//! launcher (`ark screen start`), driven through the `computer_use` / `computer` tools with
//! real xdotool input, ImageMagick captures and AT-SPI (gdbus) accessibility.
//!
//! Needs the desktop stack, so `tests/real/realtest.sh` runs it inside the
//! `ark-test-realtest-desktop-*` container (image `tests/real/realtest/Containerfile`):
//!
//! ```sh
//! ARK_REAL_TESTS=1 ARK_REAL_DESKTOP=1 <ark-app test binary> --ignored --exact \
//!     computer::tests_real::real_bot_desktop_computer_use
//! ```
//!
//! `ARK_REAL_DESKTOP=1` is the "this machine may grow an Xvnc screen" opt-in on top of
//! `ARK_REAL_TESTS=1`; the desktop and the target app are stopped by guards on any exit.

use super::fake_driver::{ctx, find_json, run};
use ark_browser::control::screen::Desktop;
use ark_core::proc::{spawn_tied, wait_until, ChildGuard};
use serde_json::{json, Value};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::Duration;

fn gate() -> bool {
    let on = std::env::var("ARK_REAL_TESTS").ok().as_deref() == Some("1") && std::env::var("ARK_REAL_DESKTOP").ok().as_deref() == Some("1");
    if !on {
        eprintln!("skipping: needs ARK_REAL_TESTS=1 and ARK_REAL_DESKTOP=1 (run tests/real/realtest.sh)");
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
    let home = ark_core::tmp::TempDir::new("ark-cu-real");
    let d = Desktop::new(home.path());
    let st = d.start().unwrap_or_else(|e| panic!("Bot Desktop did not start: {e}"));
    let screen = Screen(d);
    eprintln!("bot desktop: {st:?}");
    let env = screen.0.published_env();
    assert!(env.iter().any(|(k, _)| k == "DISPLAY"), "the launcher publishes DISPLAY: {env:?}");

    // The app the agent will operate: a zenity entry dialog that prints what was typed.
    let mut z = Command::new("zenity");
    z.args(["--entry", "--title=ark-target", "--text=Name"]).envs(env.iter().cloned()).env("GTK_MODULES", "gail:atk-bridge").env("NO_AT_BRIDGE", "0").stdout(Stdio::piped()).stderr(Stdio::null());
    let mut app = ChildGuard::group(spawn_tied(z, false).unwrap());
    assert!(wait_until(Duration::from_secs(20), || !sh(&env, &["xdotool", "search", "--name", "ark-target"]).trim().is_empty()), "zenity window never mapped");

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
    let win = sh(&env, &["xdotool", "search", "--name", "ark-target"]).lines().next().unwrap_or("").to_string();
    let _ = sh(&env, &["xdotool", "windowactivate", "--sync", &win]);
    // XTest input goes to the focused window: wait until the window manager has given it focus.
    assert!(wait_until(Duration::from_secs(10), || sh(&env, &["xdotool", "getwindowfocus"]).trim() == win), "zenity never got focus");
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "type", "text": "hello ark"}));
    eprintln!("type: {}", o.content.chars().take(300).collect::<String>());
    assert!(!o.is_error, "{}", o.content);
    let (o, _) = run(cu.as_ref(), &c, json!({"action": "key", "keys": "Return"}));
    eprintln!("key: {}", o.content.chars().take(300).collect::<String>());
    assert!(!o.is_error, "{}", o.content);
    assert!(wait_until(Duration::from_secs(10), || matches!(app.child().try_wait(), Ok(Some(_)))), "zenity did not close on Return");
    let mut typed = String::new();
    app.child().stdout.take().unwrap().read_to_string(&mut typed).unwrap();
    assert_eq!(typed.trim(), "hello ark", "the text computer_use typed reached the app");

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
