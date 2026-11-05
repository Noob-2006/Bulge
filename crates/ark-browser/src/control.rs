//! Runtime browser control for `/browser` and `ark browser` (connect / disconnect / status /
//! use / close-profile), plus the `ark computer-use` and `ark screen` commands in
//! [`cua`] and [`screen`]. Ports Hermes `cli_commands_mixin._handle_browser_command`,
//! `cli_browser_gateway._normalize_cdp_url`, `browser_connect.py` and
//! `hermes_cli/subcommands/browser.py` (MIT).
//!
//! `/browser connect [url]` validates the CDP URL, finds a browser already serving
//! DevTools there (both loopbacks for the default `http://127.0.0.1:9222`) or launches a
//! debug Chromium on a dedicated profile, then points the browser tools at it
//! (`BROWSER_CDP_URL`, which [`crate::BrowserConfig::backend`] reads) and returns a system
//! note for the model. `disconnect` reverts; `use [off]` toggles Browser Use mode
//! (`browser.exec_enabled`, applied by the host's config writer).

pub mod cua;
pub mod screen;

use crate::{launch, manager, util, BrowserConfig};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const DEFAULT_CDP_PORT: u16 = 9222;
pub const DEFAULT_CDP_URL: &str = "http://127.0.0.1:9222";

/// What a `/browser` invocation asks the host to do besides showing `text`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SlashReply {
    pub text: String,
    /// A `[System note: …]` to queue as the next user turn (tells the model what changed).
    pub note: Option<String>,
    /// Config to persist: (dotted key, TOML value literal).
    pub config: Option<(String, String)>,
    /// Start a new session so the changed tool set takes effect.
    pub new_session: bool,
}

/// Alias the wiring contract uses for [`SlashReply`] (`ark_browser::control::Reply`).
pub type Reply = SlashReply;

fn say(lines: &[String]) -> String {
    lines.join("\n")
}

/// Validate a `/browser connect` URL → `(url, port)`. A `/devtools/browser/<id>` path is kept
/// verbatim; anything else is reduced to the origin.
pub fn normalize_cdp_url(raw: &str) -> Result<(String, u16), String> {
    let raw = raw.trim();
    let full = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    let (scheme, rest) = full.split_once("://").unwrap();
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https" | "ws" | "wss") {
        return Err(format!(
            "⚠ Unsupported browser url scheme: {} (expected one of: http, https, ws, wss)",
            if scheme.is_empty() {
                "(missing)"
            } else {
                &scheme
            }
        ));
    }
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let (host, port) = if let Some(r) = hostport.strip_prefix('[') {
        let (h, after) = r
            .split_once(']')
            .ok_or_else(|| format!("⚠ Missing host in browser url: {raw}"))?;
        (h.to_string(), after.strip_prefix(':'))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (hostport.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err(format!("⚠ Missing host in browser url: {raw}"));
    }
    let port = match port {
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or_else(|| format!("⚠ Invalid port in browser url: {raw}"))?,
        None => {
            if matches!(scheme.as_str(), "https" | "wss") {
                443
            } else {
                80
            }
        }
    };
    if path.starts_with("/devtools/browser/") {
        return Ok((full, port));
    }
    Ok((format!("{scheme}://{authority}"), port))
}

/// Does `url` expose a reachable DevTools endpoint (`/json/version` or `/json`)?
pub fn is_debug_ready(url: &str, timeout: Duration) -> bool {
    let full = if url.contains("://") {
        url.to_string()
    } else {
        format!("http://{url}")
    };
    let Some((scheme, rest)) = full.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return false;
    }
    if matches!(scheme, "ws" | "wss") && rest[authority.len()..].starts_with("/devtools/browser/") {
        let hp = authority
            .rsplit_once('@')
            .map(|(_, h)| h)
            .unwrap_or(authority);
        let addr = if hp.contains(':') {
            hp.to_string()
        } else {
            format!("{hp}:{}", if scheme == "wss" { 443 } else { 80 })
        };
        return tcp_open(&addr, timeout);
    }
    let http_scheme = match scheme {
        "ws" => "http",
        "wss" => "https",
        s => s,
    };
    if !matches!(http_scheme, "http" | "https") {
        return false;
    }
    let base = format!("{http_scheme}://{authority}");
    ["/json/version", "/json"]
        .iter()
        .any(|p| crate::cdp::get_json(&base, p, None, timeout).is_ok())
}

fn tcp_open(addr: &str, timeout: Duration) -> bool {
    use std::net::ToSocketAddrs;
    addr.to_socket_addrs()
        .ok()
        .into_iter()
        .flatten()
        .any(|a| std::net::TcpStream::connect_timeout(&a, timeout).is_ok())
}

/// First loopback (IPv4, then IPv6) speaking CDP on `port`.
pub fn discover_local(port: u16, timeout: Duration) -> Option<String> {
    [
        format!("http://127.0.0.1:{port}"),
        format!("http://[::1]:{port}"),
    ]
    .into_iter()
    .find(|u| is_debug_ready(u, timeout))
}

pub fn local_port_in_use(port: u16) -> bool {
    tcp_open(&format!("127.0.0.1:{port}"), Duration::from_millis(500))
        || tcp_open(&format!("[::1]:{port}"), Duration::from_millis(500))
}

/// First port after `preferred` bindable on loopback.
pub fn find_free_port(preferred: u16) -> u16 {
    (preferred.saturating_add(1)..preferred.saturating_add(11))
        .find(|p| std::net::TcpListener::bind(("127.0.0.1", *p)).is_ok())
        .unwrap_or(preferred.saturating_add(1))
}

/// Isolated debug profile for `/browser connect` launches (never the user's main profile).
pub fn debug_data_dir(home: &Path) -> PathBuf {
    home.join("browser").join("chrome-debug")
}

pub fn debug_args(port: u16, data_dir: &Path) -> Vec<String> {
    vec![
        format!("--remote-debugging-port={port}"),
        format!("--user-data-dir={}", data_dir.display()),
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
    ]
}

/// Launch a debug Chromium on `port`; waits for DevTools. `Err` carries a manual command hint.
pub fn launch_debug_browser(cfg: &BrowserConfig, home: &Path, port: u16) -> Result<String, String> {
    let exe = launch::find_executable(&cfg.executable).map_err(|_| {
        "No supported Chromium-family browser executable found in this environment".to_string()
    })?;
    let dir = debug_data_dir(home);
    util::private_dir(&dir).map_err(|e| e.to_string())?;
    let args = debug_args(port, &dir);
    let manual = format!("{} {}", exe.display(), args.join(" "));
    let log = std::fs::File::create(dir.join("launch-stderr.log")).map_err(|e| e.to_string())?;
    use std::os::unix::process::CommandExt;
    let mut child = std::process::Command::new(&exe).args(&args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(log).process_group(0).spawn().map_err(|e| format!("could not start {}: {e}\n     Launch a Chromium-family browser manually:\n     {manual}", exe.display()))?;
    for _ in 0..40 {
        if let Some(u) = discover_local(port, Duration::from_millis(500)) {
            std::mem::forget(child);
            return Ok(u);
        }
        if let Ok(Some(st)) = child.try_wait() {
            let tail = std::fs::read_to_string(dir.join("launch-stderr.log")).unwrap_or_default();
            let tail = tail.trim();
            return Err(format!("{} exited ({st}) before port {port} opened{}\n     Launch a Chromium-family browser manually:\n     {manual}", exe.display(), if tail.is_empty() { String::new() } else { format!(": {}", util::cut(&tail[tail.len().saturating_sub(2000)..], 2000)) }));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    std::mem::forget(child);
    Err(format!("⚠ Browser launched but port {port} isn't responding yet\n     Try again in a few seconds — the debug instance may still be starting"))
}

const CONNECT_NOTE: &str = "[System note: The user invoked /browser connect and connected your browser tools to a Chromium-family dev/debug browser via Chrome DevTools Protocol. Your browser tools now control that CDP browser. The command itself is a signal that using browser tools for their current browser-related request is expected; do not wait for separate permission just because CDP is connected. This is typically an ark-managed isolated debug profile, not the user's main everyday browser. It is still user-visible and may contain pages, logged-in sessions, or cookies in that debug profile, so avoid destructive actions, closing tabs, or navigating away unless the user's task calls for it.]";
const DISCONNECT_NOTE: &str = "[System note: The user has disconnected the browser tools from their live Chromium-family browser. Browser tools are back to default mode (headless local browser or cloud provider).]";

/// `/browser connect|disconnect|status|use` (Hermes `_BROWSER_SUBCOMMANDS`). `home` = ark data dir.
pub fn browser_slash(cfg: &BrowserConfig, home: &Path, args: &str) -> SlashReply {
    let mut parts = args.trim().splitn(2, char::is_whitespace);
    // The subcommand matches case-insensitively; the URL keeps its case (CDP paths are case-sensitive).
    let word = parts
        .next()
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
        .unwrap_or_else(|| "status".into());
    let rest = parts.next().unwrap_or("").trim().to_string();
    match word.as_str() {
        "connect" => connect(cfg, home, if rest.is_empty() { DEFAULT_CDP_URL } else { &rest }),
        "disconnect" => disconnect(),
        "status" => SlashReply { text: status(cfg), ..Default::default() },
        "use" => browser_use(if rest.is_empty() { "on".into() } else { rest.to_ascii_lowercase() }),
        _ => SlashReply {
            text: say(&[
                "Usage: /browser connect|disconnect|status|use".into(),
                String::new(),
                "   connect      Connect browser tools to your live Chromium-family browser session".into(),
                "   disconnect   Revert to default browser backend".into(),
                "   status       Show current browser mode".into(),
                "   use [off]    Switch to Browser Use mode (browser_exec) / back to built-in tools".into(),
            ]),
            ..Default::default()
        },
    }
}

fn connect(cfg: &BrowserConfig, home: &Path, raw: &str) -> SlashReply {
    let (url, port) = match normalize_cdp_url(raw) {
        Ok(v) => v,
        Err(e) => {
            return SlashReply {
                text: format!("   {e}"),
                ..Default::default()
            }
        }
    };
    // Clear existing sessions so the next tool call uses the new backend.
    manager::global().stop_all();
    let mut lines = vec![];
    let is_default = url == DEFAULT_CDP_URL;
    let mut found = if is_default {
        discover_local(port, Duration::from_secs(1))
    } else {
        is_debug_ready(&url, Duration::from_secs(1)).then(|| url.clone())
    };
    if let Some(f) = &found {
        lines.push(format!(
            "   ✓ Chromium-family browser is already listening at {f}"
        ));
    } else if is_default {
        let mut launch_port = port;
        if local_port_in_use(port) {
            launch_port = find_free_port(port);
            lines.push(format!(
                "   ⚠ Port {port} is occupied by another application that isn't a CDP browser"
            ));
            lines.push(format!("     (an IDE debugger or dev server may be using it) — launching on port {launch_port} instead..."));
        } else {
            lines.push("   Chromium-family browser isn't running with remote debugging — attempting to launch...".into());
        }
        match launch_debug_browser(cfg, home, launch_port) {
            Ok(u) => {
                lines.push(format!(
                    "   ✓ Chromium-family browser launched and listening on port {launch_port}"
                ));
                found = Some(u);
            }
            Err(e) => {
                lines.push("   ⚠ Could not auto-launch a Chromium-family browser".into());
                lines.push(format!("     {e}"));
            }
        }
    } else {
        lines.push(format!("   ⚠ Port {port} is not reachable at {url}"));
    }
    let Some(found) = found else {
        lines.push("Browser not connected — start a Chromium-family browser with remote debugging and retry /browser connect".into());
        return SlashReply {
            text: say(&lines),
            ..Default::default()
        };
    };
    std::env::set_var("BROWSER_CDP_URL", &found);
    lines.push("🌐 Browser connected to live Chromium-family browser via CDP".into());
    lines.push(format!("   Endpoint: {found}"));
    SlashReply {
        text: say(&lines),
        note: Some(CONNECT_NOTE.into()),
        ..Default::default()
    }
}

fn disconnect() -> SlashReply {
    if std::env::var("BROWSER_CDP_URL")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        return SlashReply { text: "Browser is not connected to a live Chromium-family browser (already using default mode)".into(), ..Default::default() };
    }
    std::env::remove_var("BROWSER_CDP_URL");
    manager::global().stop_all();
    SlashReply {
        text: say(&[
            "🌐 Browser disconnected from live Chromium-family browser".into(),
            "   Browser tools reverted to default mode (local headless or cloud provider)".into(),
        ]),
        note: Some(DISCONNECT_NOTE.into()),
        ..Default::default()
    }
}

fn browser_use(arg: String) -> SlashReply {
    if arg != "on" && arg != "off" {
        return SlashReply {
            text: say(&["Usage: /browser use [off]".into(), "   /browser use       — switch to Browser Use mode (browser_exec via the Browser Use CLI)".into(), "   /browser use off   — revert to the built-in browser tools".into()]),
            ..Default::default()
        };
    }
    let on = arg == "on";
    SlashReply {
        text: say(&[
            if on {
                "🌐 Browser Use mode enabled — browser_exec via the Browser Use CLI"
            } else {
                "🌐 Browser Use mode disabled — built-in browser tools restored"
            }
            .into(),
            "   Session reset. New tool configuration is active.".into(),
        ]),
        config: Some(("browser.exec_enabled".into(), on.to_string())),
        new_session: true,
        ..Default::default()
    }
}

/// `/browser status` text.
pub fn status(cfg: &BrowserConfig) -> String {
    let mut l = vec![];
    let current = std::env::var("BROWSER_CDP_URL")
        .unwrap_or_default()
        .trim()
        .to_string();
    if cfg.exec_enabled {
        l.push("🌐 Browser: Browser Use mode (browser_exec via the Browser Use CLI)".into());
        l.push("   Local Chrome via CDP, or Browser Use cloud browsers".into());
        l.push("   /browser use off      — revert to the built-in browser tools".into());
        return say(&l);
    }
    let backend = cfg.backend();
    if !current.is_empty() || backend == "cdp" {
        let url = if current.is_empty() {
            cfg.cdp_override()
        } else {
            current
        };
        l.push("🌐 Browser: connected to live Chromium-family browser via CDP".into());
        l.push(format!("   Endpoint: {url}"));
        l.push(if is_debug_ready(&url, Duration::from_secs(1)) {
            "   Status: ✓ reachable".into()
        } else {
            "   Status: ⚠ not reachable (browser may not be running)".into()
        });
    } else {
        match backend.as_str() {
            "browserbase" | "browser-use" | "firecrawl" => l.push(format!(
                "🌐 Browser: {} (cloud)",
                match backend.as_str() {
                    "browserbase" => "Browserbase",
                    "browser-use" => "Browser Use",
                    _ => "Firecrawl",
                }
            )),
            "camofox" => l.push(format!("🌐 Browser: Camofox at {}", cfg.camofox_url())),
            "lightpanda" => {
                l.push("🌐 Browser: local Lightpanda".into());
                l.push("   ⚡ Lightpanda: faster navigation, no screenshot support".into());
                l.push("   Automatic Chromium fallback for screenshots and failed commands".into());
                if launch::lightpanda_binary().is_none() {
                    l.push("   ⚠ lightpanda binary not found".into());
                }
            }
            "sandbox" => l.push("🌐 Browser: sandboxed container Chromium".into()),
            "extension" => {
                l.push("🌐 Browser: your browser through the ark extension relay".into())
            }
            _ => l.push(if cfg.headless_effective() {
                "🌐 Browser: local headless Chromium".into()
            } else {
                "🌐 Browser: local headed Chromium".into()
            }),
        }
    }
    l.push("   /browser connect      — connect to your live Chromium-family browser".into());
    l.push("   /browser disconnect   — revert to default".into());
    say(&l)
}

/// `ark browser` help (Hermes prints this parser's help when the action is not `close-profile`).
pub const BROWSER_HELP: &str = "usage: ark browser close-profile [--browser chrome|edge|brave|brave-origin|chromium]
       ark browser status | install [--url ZIP] | extension

Real-profile browsing helpers (browser.use_real_profile).
  close-profile  stop the browser holding your default profile so ark can copy it — DESTRUCTIVE
                 (unsaved tabs in that browser are lost; run only with the user's explicit OK)
  status         the backend, the CDP endpoint and the extension relay
  install        download a pinned Chrome for Testing build into this ark home
  extension      start the browser-extension relay and print the pairing token path";

/// `ark browser …`: exit code, output on `io`.
pub fn browser_command(cfg: &BrowserConfig, home: &Path, args: &[String], io: &mut dyn screen::Io) -> i32 {
    match args.first().map(String::as_str) {
        Some("close-profile") => {
            let (code, msg) = browser_cli(args);
            io.line(&msg);
            code
        }
        Some("status") => {
            io.line(&status(cfg));
            io.line(&format!("   extension relay: {}", serde_json::to_string(&crate::extension::status()).unwrap_or_default()));
            0
        }
        Some("install") => {
            let url = args.iter().position(|a| a == "--url").and_then(|i| args.get(i + 1)).map(String::as_str);
            match launch::install_chromium(cfg, home, url, &mut |l| io.line(l)) {
                Ok(p) => {
                    io.line(&format!("✓ Chrome for Testing installed: {}", p.display()));
                    io.line("   The local backend picks it up automatically (browser.executable stays empty).");
                    0
                }
                Err(e) => {
                    io.line(&format!("✗ {e}"));
                    1
                }
            }
        }
        Some("extension") => {
            let dir = home.join("browser");
            let _ = std::fs::create_dir_all(&dir);
            match crate::extension::listen(cfg, &dir) {
                Ok(port) => {
                    io.line(&format!("extension relay listening on 127.0.0.1:{port}"));
                    io.line("   load ui/browser-extension as an unpacked extension, then paste this token into its options:");
                    io.line(&format!("   {}", crate::extension::token(&dir).map(|t| dir.join("extension-token").display().to_string() + " (token " + &t[..8] + "…)").unwrap_or_default()));
                    0
                }
                Err(e) => {
                    io.line(&format!("✗ {e}"));
                    1
                }
            }
        }
        _ => {
            io.line(BROWSER_HELP);
            2
        }
    }
}

/// Readiness for `ark doctor` (browser tools are optional, so this never fails the run).
pub fn doctor_check(cfg: &BrowserConfig) -> Result<String, String> {
    let backend = cfg.backend();
    match backend.as_str() {
        "local" => {
            let exe = launch::find_executable(&cfg.executable).map_err(|e| format!("{e} Run `ark browser install`, or set browser.executable."))?;
            Ok(format!("local ({})", exe.display()))
        }
        "lightpanda" => launch::lightpanda_binary().map(|p| format!("lightpanda ({})", p.display())).ok_or_else(|| "engine is lightpanda but no lightpanda binary was found (set browser.engine = auto)".into()),
        "sandbox" => match crate::sandbox::cli_path() {
            Some(p) => Ok(format!("sandbox ({} at {})", crate::sandbox::docker(), p.display())),
            None => Err(format!("the sandbox backend needs a container CLI (set ARK_DOCKER, or install docker/podman): `{}` was not found", crate::sandbox::docker())),
        },
        "extension" => {
            let s = crate::extension::status();
            if s["extension_connected"] == true {
                Ok(format!("browser extension connected on 127.0.0.1:{}", s["listening"]))
            } else {
                Err("no ark browser extension is connected: load ui/browser-extension in Chrome, open its options and paste the token from ~/.local/share/ark/browser/extension-token".into())
            }
        }
        other => Ok(other.to_string()),
    }
}

/// `ark browser close-profile …` → (exit code, output).
pub fn browser_cli(args: &[String]) -> (i32, String) {
    if args.first().map(String::as_str) != Some("close-profile") {
        return (2, BROWSER_HELP.into());
    }
    let explicit = args
        .iter()
        .position(|a| a == "--browser")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or_else(|| {
            args.iter()
                .find_map(|a| a.strip_prefix("--browser=").map(str::to_string))
        });
    let (name, dir) = match explicit {
        Some(b) => {
            let b = b.to_ascii_lowercase();
            let canon =
                match b.as_str() {
                    "chrome" | "google-chrome" => "chrome",
                    "edge" | "msedge" => "edge",
                    "brave" | "brave-origin" => "brave",
                    "chromium" => "chromium",
                    _ => return (
                        1,
                        format!(
                            "✗ Unsupported browser `{b}` (chrome/edge/brave/brave-origin/chromium)"
                        ),
                    ),
                };
            match launch::real_data_dir(canon) {
                Some(d) => (canon.to_string(), d),
                None => {
                    return (
                        1,
                        format!("✗ Could not resolve the {canon} profile directory."),
                    )
                }
            }
        }
        None => match launch::detect_real_browser() {
            Ok(rb) => (rb.name.to_string(), rb.data_dir),
            Err(e) => return (1, format!("✗ {e}")),
        },
    };
    close_profile_dir(&name, &dir)
}

/// Close whatever holds `dir` (the profile's default user-data-dir).
pub fn close_profile_dir(name: &str, dir: &Path) -> (i32, String) {
    // Processes without --user-data-dir only count when `dir` IS that browser's default dir
    // (otherwise a temp dir would match — and kill — every unrelated Chrome on the machine).
    let is_default = launch::real_data_dir(name).is_some_and(|d| d == dir);
    // Hermes `_dispatch_browser`: nothing holding the profile is an error (`✗`, exit 1), so a runbook
    // that only "succeeded" because the browser was already gone is not reported as a close.
    if launch::processes_on(dir, is_default).is_empty() {
        // Clear a crashed instance's leftover singleton files, but report the close as failed
        // (Hermes `_dispatch_browser` answers `✗` + 1 when nothing held the profile).
        launch::clear_stale_locks(dir);
        return (
            1,
            "✗ no matching browser process found holding the profile.".into(),
        );
    }
    match launch::close_profile(dir, is_default) {
        Ok(m) => (0, format!("✓ {m} ({name})")),
        Err(e) => (1, format!("✗ {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::Mutex;

    static ENV: Mutex<()> = Mutex::new(());

    /// A fake DevTools HTTP endpoint answering /json/version.
    fn fake_devtools() -> (String, u16) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let mut b = [0u8; 2048];
                let n = s.read(&mut b).unwrap_or(0);
                let req = String::from_utf8_lossy(&b[..n]);
                let body = if req.starts_with("GET /json/version") {
                    format!("{{\"Browser\":\"Chrome/140\",\"webSocketDebuggerUrl\":\"ws://127.0.0.1:{port}/devtools/browser/abc\"}}")
                } else {
                    "[]".into()
                };
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes());
            }
        });
        (format!("http://127.0.0.1:{port}"), port)
    }

    #[test]
    fn normalize_rules_follow_hermes() {
        assert_eq!(
            normalize_cdp_url("127.0.0.1:9333/json?x").unwrap(),
            ("http://127.0.0.1:9333".into(), 9333)
        );
        assert_eq!(
            normalize_cdp_url("https://box.example").unwrap(),
            ("https://box.example".into(), 443)
        );
        assert_eq!(
            normalize_cdp_url("ws://h:9222/devtools/browser/AbC").unwrap(),
            ("ws://h:9222/devtools/browser/AbC".into(), 9222)
        );
        assert_eq!(
            normalize_cdp_url("http://[::1]:9222/").unwrap(),
            ("http://[::1]:9222".into(), 9222)
        );
        assert!(normalize_cdp_url("ftp://h")
            .unwrap_err()
            .contains("Unsupported browser url scheme: ftp"));
        assert!(normalize_cdp_url("http://h:99999")
            .unwrap_err()
            .contains("Invalid port"));
        assert!(normalize_cdp_url("http://:9222")
            .unwrap_err()
            .contains("Missing host"));
    }

    #[test]
    fn connect_status_disconnect_and_use() {
        let _g = ENV.lock().unwrap();
        crate::config::CDP_ENV_OPT_IN.with(|c| c.set(true));
        std::env::remove_var("BROWSER_CDP_URL");
        let home = ark_core::tmp::scratch_path(format!("ark-ctl-{}", std::process::id()));
        let cfg = BrowserConfig::parse(&toml::Table::new()).unwrap();
        let (url, port) = fake_devtools();
        assert!(is_debug_ready(&url, Duration::from_secs(2)));
        assert_eq!(
            discover_local(port, Duration::from_secs(2)).as_deref(),
            Some(url.as_str())
        );
        let r = browser_slash(&cfg, &home, &format!("CONNECT {url}/json"));
        assert!(
            r.text.contains("already listening") && r.text.contains("connected to live"),
            "{}",
            r.text
        );
        assert!(r.note.as_deref().unwrap().contains("/browser connect"));
        assert_eq!(std::env::var("BROWSER_CDP_URL").unwrap(), url);
        let cfg2 = BrowserConfig::parse(&toml::Table::new()).unwrap();
        assert_eq!(
            cfg2.backend(),
            "cdp",
            "the browser tools follow the override"
        );
        let st = browser_slash(&cfg2, &home, "status").text;
        assert!(
            st.contains(&format!("Endpoint: {url}")) && st.contains("✓ reachable"),
            "{st}"
        );
        let d = browser_slash(&cfg2, &home, "disconnect");
        assert!(d.text.contains("disconnected") && d.note.is_some());
        assert!(std::env::var("BROWSER_CDP_URL").is_err());
        assert!(browser_slash(&cfg2, &home, "disconnect")
            .text
            .contains("already using default mode"));
        // An unreachable explicit URL is reported, not connected.
        let dead = format!("http://127.0.0.1:{}", util::free_port());
        let r = browser_slash(&cfg2, &home, &format!("connect {dead}"));
        assert!(
            r.text.contains("is not reachable") && r.text.contains("Browser not connected"),
            "{}",
            r.text
        );
        assert!(r.note.is_none() && std::env::var("BROWSER_CDP_URL").is_err());
        assert!(browser_slash(&cfg2, &home, "connect gopher://x")
            .text
            .contains("Unsupported"));
        // Browser Use mode toggles exec_enabled and resets the session.
        let u = browser_slash(&cfg2, &home, "use");
        assert_eq!(
            u.config,
            Some(("browser.exec_enabled".into(), "true".into()))
        );
        assert!(u.new_session);
        assert_eq!(
            browser_slash(&cfg2, &home, "use OFF").config.unwrap().1,
            "false"
        );
        assert!(browser_slash(&cfg2, &home, "use maybe")
            .text
            .starts_with("Usage: /browser use"));
        let mut t = toml::Table::new();
        t.insert("exec_enabled".into(), toml::Value::Boolean(true));
        assert!(browser_slash(&BrowserConfig::parse(&t).unwrap(), &home, "")
            .text
            .contains("Browser Use mode"));
        assert!(browser_slash(&cfg2, &home, "help")
            .text
            .starts_with("Usage: /browser connect"));
        assert!(status(&cfg2).contains("local headless Chromium"));
    }

    /// Spawn the copied `/bin/sh` stand-in "chrome". Concurrent tests fork (screen/cua fakes) while this
    /// file may still be open for writing in that child, which surfaces as ETXTBSY — retry briefly.
    fn spawn_fake(fake: &Path, args: &[String]) -> std::process::Child {
        for _ in 0..40 {
            match std::process::Command::new(fake).args(args).spawn() {
                Ok(c) => return c,
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(50))
                }
                Err(e) => panic!("spawn {}: {e}", fake.display()),
            }
        }
        panic!("spawn {}: still ETXTBSY", fake.display());
    }

    #[test]
    fn close_profile_cli() {
        let (c, h) = browser_cli(&[]);
        assert_eq!(c, 2);
        assert!(h.starts_with("usage: ark browser close-profile"));
        assert!(h.contains("--browser"));
        assert_eq!(
            browser_cli(&[
                "close-profile".into(),
                "--browser".into(),
                "netscape".into()
            ])
            .0,
            1
        );
        // A real "browser" holding a temp profile: a process named chrome with --user-data-dir.
        let dir = ark_core::tmp::scratch_path(format!("ark-ctl-prof-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("chrome");
        std::fs::copy("/bin/sh", &fake).unwrap();
        let udd = dir.join("udd");
        std::fs::create_dir_all(&udd).unwrap();
        let mut child = spawn_fake(
            &fake,
            &[
                "-c".into(),
                "sleep 30; :".into(),
                format!("--user-data-dir={}", udd.display()),
            ],
        );
        std::thread::sleep(Duration::from_millis(200));
        let (code, msg) = close_profile_dir("chrome", &udd);
        assert_eq!(code, 0, "{msg}");
        assert!(msg.starts_with('✓') && msg.contains("browser process"), "{msg}");
        assert!(child.wait().is_ok());
        // Nothing holds it any more: Hermes reports that as a failed close, not a ✓.
        let (code, msg) = close_profile_dir("chrome", &udd);
        assert_eq!(code, 1, "{msg}");
        assert!(msg.starts_with('✗'), "{msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// SAFETY: a temp profile must never match — let alone signal — a browser process that was started
    /// without `--user-data-dir` (the shape of every one of the user's own Chrome instances).
    #[test]
    fn close_profile_never_touches_a_browser_without_this_profile() {
        let dir = ark_core::tmp::scratch_path(format!("ark-ctl-safe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("chrome");
        std::fs::copy("/bin/sh", &fake).unwrap();
        let udd = dir.join("udd");
        std::fs::create_dir_all(&udd).unwrap();
        // Our own fake "browser" with NO --user-data-dir: only its own argument list is distinctive.
        let mut mine = spawn_fake(
            &fake,
            &["-c".into(), "sleep 30; :".into()],
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(launch::processes_on(&udd, false).is_empty(), "temp profile must not match");
        let (code, msg) = close_profile_dir("chrome", &udd);
        assert_eq!(code, 1, "{msg}");
        assert!(msg.contains("no matching browser process"), "{msg}");
        // Still alive: nothing we did not start ourselves was signalled.
        let mut st = 0;
        let r = unsafe { libc::waitpid(mine.id() as i32, &mut st, libc::WNOHANG) };
        assert_eq!(r, 0, "the unrelated process must still be running");
        let _ = mine.kill();
        let _ = mine.wait();
        // And the same holds for every other real default dir: `default_dir` is only ever set for the
        // dir that IS that browser's default (launch::real_data_dir), never for a temp profile.
        assert!(!launch::real_data_dir("chrome").is_some_and(|d| d == udd));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `ark doctor` prints the browser line from this (`main.rs`: "✓ browser: …" / "· browser: …"):
    /// every backend either says how it is ready or names what is missing, and never panics.
    #[test]
    fn doctor_reports_browser_readiness_per_backend() {
        let dir = ark_core::tmp::scratch_path(format!("ark-ctl-doc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("chromium");
        std::fs::copy("/bin/sh", &exe).unwrap();
        let local = BrowserConfig { executable: exe.display().to_string(), ..Default::default() };
        assert_eq!(doctor_check(&local).unwrap(), format!("local ({})", exe.display()));
        let lp = BrowserConfig { engine: "lightpanda".into(), ..Default::default() };
        match doctor_check(&lp) {
            Ok(s) => assert!(s.contains("lightpanda"), "{s}"),
            Err(e) => assert!(e.contains("lightpanda"), "{e}"),
        }
        let ext = BrowserConfig { backend: "extension".into(), ..Default::default() };
        let e = doctor_check(&ext).unwrap_err();
        assert!(e.contains("browser extension") && e.contains("ui/browser-extension") && e.contains("extension-token"), "{e}");
        let sandbox = BrowserConfig { backend: "sandbox".into(), ..Default::default() };
        match doctor_check(&sandbox) {
            Ok(s) => assert!(s.starts_with("sandbox ("), "{s}"),
            Err(e) => assert!(e.contains("docker"), "{e}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
