//! The per-OS half of [`crate::launch`]: where Chromium-family browsers are installed, which
//! Chrome for Testing build fits this host, the user's real profile directories, and finding /
//! stopping browser processes by their command line.
//!
//! Linux keeps its lists and `/proc` scan in `launch.rs`, unchanged. This module adds:
//!
//! | | Windows | macOS | Android / iOS |
//! |---|---|---|---|
//! | install paths | `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%LocalAppData%` × Chrome / Brave / Edge / Chromium | `/Applications` and `~/Applications` app bundles | none: [`MOBILE_NOTE`] |
//! | Chrome for Testing | `win64` / `win32`, `chrome.exe` | `mac-arm64` / `mac-x64`, the `.app` bundle | none |
//! | real profile | `%LocalAppData%\<vendor>\User Data` | `~/Library/Application Support/<vendor>` | none |
//! | processes | `Win32_Process` command lines (PowerShell CIM) | `ps -axww -o pid=,command=` | `/proc` (Android) |
//! | stop | `taskkill` (WM_CLOSE), then `TerminateProcess` | `SIGTERM`, `SIGKILL` (in `launch.rs`) | |

#[cfg(any(windows, target_os = "macos"))]
use std::path::{Path, PathBuf};

/// Why there is no local browser on a phone, and what to use instead.
pub const MOBILE_NOTE: &str = "A local Chromium cannot be started or driven on Android / iOS. Use a remote DevTools endpoint instead: set browser.backend = \"cdp\" and browser.cdp_url to a Chromium on a paired computer (seagent node), or pick a cloud backend (browserbase, browser-use, firecrawl).";

/// Chrome for Testing platform name for this host (`None`: no build exists). Linux is always
/// `linux64`, as before (Google publishes no Linux arm64 build).
pub fn cft_platform() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some("linux64")
    } else if cfg!(all(windows, target_pointer_width = "64")) {
        Some("win64")
    } else if cfg!(windows) {
        Some("win32")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("mac-arm64")
    } else if cfg!(target_os = "macos") {
        Some("mac-x64")
    } else {
        None
    }
}

/// The directory a Chrome for Testing zip unpacks to (`chrome-linux64` on Linux).
pub fn cft_dir() -> String {
    format!("chrome-{}", cft_platform().unwrap_or("linux64"))
}

/// The executable inside [`cft_dir`] (`chrome` on Linux).
pub fn cft_exe_rel() -> &'static str {
    if cfg!(windows) {
        "chrome.exe"
    } else if cfg!(target_os = "macos") {
        "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"
    } else {
        "chrome"
    }
}

/// File name of [`cft_exe_rel`] (what to look for in an unpacked archive).
pub fn cft_exe_name() -> &'static str {
    cft_exe_rel().rsplit('/').next().unwrap_or("chrome")
}

/// Playwright's browser cache and the Chromium executable inside a `chromium-*` build.
#[cfg(any(windows, target_os = "macos"))]
pub fn playwright_layout() -> Option<(PathBuf, &'static str)> {
    if let Some(p) = std::env::var_os("PLAYWRIGHT_BROWSERS_PATH") {
        return Some((PathBuf::from(p), playwright_exe_rel()));
    }
    #[cfg(windows)]
    let base = PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join("ms-playwright");
    #[cfg(target_os = "macos")]
    let base = PathBuf::from(std::env::var_os("HOME")?).join("Library/Caches/ms-playwright");
    Some((base, playwright_exe_rel()))
}

#[cfg(any(windows, target_os = "macos"))]
fn playwright_exe_rel() -> &'static str {
    if cfg!(windows) {
        "chrome-win/chrome.exe"
    } else {
        "chrome-mac/Chromium.app/Contents/MacOS/Chromium"
    }
}

/// `(kind, executable)` for every well-known install location on this OS, in search order.
#[cfg(windows)]
pub fn install_paths() -> Vec<(&'static str, PathBuf)> {
    const REL: &[(&str, &str)] = &[
        ("chrome", r"Google\Chrome\Application\chrome.exe"),
        ("brave", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
        ("edge", r"Microsoft\Edge\Application\msedge.exe"),
        ("chromium", r"Chromium\Application\chrome.exe"),
    ];
    let bases: Vec<PathBuf> = ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"].iter().filter_map(|k| std::env::var_os(k)).map(PathBuf::from).collect();
    REL.iter().flat_map(|(kind, rel)| bases.iter().map(move |b| (*kind, b.join(rel)))).collect()
}

/// `(kind, executable)` for every well-known install location on this OS, in search order.
#[cfg(target_os = "macos")]
pub fn install_paths() -> Vec<(&'static str, PathBuf)> {
    const APPS: &[(&str, &str)] = &[
        ("chrome", "Google Chrome.app/Contents/MacOS/Google Chrome"),
        ("brave", "Brave Browser.app/Contents/MacOS/Brave Browser"),
        ("edge", "Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
        ("chromium", "Chromium.app/Contents/MacOS/Chromium"),
    ];
    let mut bases = vec![PathBuf::from("/Applications")];
    if let Some(h) = std::env::var_os("HOME") {
        bases.push(PathBuf::from(h).join("Applications"));
    }
    APPS.iter().flat_map(|(kind, rel)| bases.iter().map(move |b| (*kind, b.join(rel)))).collect()
}

/// The installed binary of browser `name` (chrome / chromium / brave / edge).
#[cfg(any(windows, target_os = "macos"))]
pub fn real_binary(name: &str) -> Option<PathBuf> {
    install_paths().into_iter().filter(|(k, _)| *k == name).map(|(_, p)| p).find(|p| p.is_file())
}

/// The real profile directory of browser `name`.
#[cfg(any(windows, target_os = "macos"))]
pub fn real_data_dir(name: &str) -> Option<PathBuf> {
    #[cfg(windows)]
    let (base, rel) = (
        PathBuf::from(std::env::var_os("LOCALAPPDATA")?),
        match name {
            "chrome" => r"Google\Chrome\User Data",
            "chromium" => r"Chromium\User Data",
            "brave" => r"BraveSoftware\Brave-Browser\User Data",
            "edge" => r"Microsoft\Edge\User Data",
            _ => return None,
        },
    );
    #[cfg(target_os = "macos")]
    let (base, rel) = (
        PathBuf::from(std::env::var_os("HOME")?).join("Library/Application Support"),
        match name {
            "chrome" => "Google/Chrome",
            "chromium" => "Chromium",
            "brave" => "BraveSoftware/Brave-Browser",
            "edge" => "Microsoft Edge",
            _ => return None,
        },
    );
    Some(base.join(rel))
}

// ───────────────────────── processes ─────────────────────────

/// `(argv0, --user-data-dir value)` from a flat command line (`ps` output or a Windows
/// `CommandLine`): argv0 is the quoted first token, else everything before the first ` -`
/// (macOS paths carry spaces); the flag value is quoted, or runs to the next ` --`.
pub fn parse_command_line(line: &str) -> (String, Option<String>) {
    let line = line.trim();
    let argv0 = if let Some(rest) = line.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").to_string()
    } else {
        line.split(" -").next().unwrap_or("").trim().to_string()
    };
    let udd = line.split_once("--user-data-dir=").map(|(_, v)| {
        if let Some(q) = v.strip_prefix('"') {
            q.split('"').next().unwrap_or("").to_string()
        } else {
            v.split(" --").next().unwrap_or("").trim().to_string()
        }
    });
    (argv0, udd)
}

/// `(pid, command line)` of every process this account can see.
#[cfg(windows)]
fn command_lines() -> Vec<(i32, String)> {
    let script = "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine } | ForEach-Object { \"$($_.ProcessId)`t$($_.CommandLine)\" }";
    let Ok((0, out, _)) = crate::util::run(&["powershell", "-NoProfile", "-NonInteractive", "-Command", script], std::time::Duration::from_secs(20), None, &[]) else { return vec![] };
    out.lines().filter_map(|l| l.split_once('\t')).filter_map(|(p, c)| Some((p.trim().parse().ok()?, c.to_string()))).collect()
}

#[cfg(target_os = "macos")]
fn command_lines() -> Vec<(i32, String)> {
    let Ok((0, out, _)) = crate::util::run(&["ps", "-axww", "-o", "pid=,command="], std::time::Duration::from_secs(10), None, &[]) else { return vec![] };
    out.lines().filter_map(|l| l.trim_start().split_once(' ')).filter_map(|(p, c)| Some((p.parse().ok()?, c.to_string()))).collect()
}

/// Pids of browser processes using `dir` as user-data-dir (see `launch::processes_on`).
#[cfg(any(windows, target_os = "macos"))]
pub fn processes_on(dir: &Path, default_dir: bool, chromey: fn(&str) -> bool) -> Vec<i32> {
    let norm = |s: &str| {
        let t = s.trim_end_matches(['/', '\\']);
        if cfg!(windows) {
            t.replace('/', "\\").to_ascii_lowercase()
        } else {
            t.to_string()
        }
    };
    let want = norm(&dir.to_string_lossy());
    command_lines()
        .into_iter()
        .filter(|(pid, _)| *pid as u32 != std::process::id())
        .filter_map(|(pid, line)| {
            let (argv0, udd) = parse_command_line(&line);
            let name = Path::new(&argv0).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            if !chromey(&name) {
                return None;
            }
            let hit = match udd {
                Some(d) => norm(&d) == want,
                None => default_dir,
            };
            hit.then_some(pid)
        })
        .collect()
}

/// Ask a browser process to close (Windows: `taskkill` without `/F` posts WM_CLOSE).
#[cfg(windows)]
pub fn ask_exit(pid: i32) {
    let _ = crate::util::run(&["taskkill", "/PID", &pid.to_string()], std::time::Duration::from_secs(5), None, &[]);
}

/// End a browser process now (`TerminateProcess`).
#[cfg(windows)]
pub fn force_exit(pid: i32) {
    seagent_core::platform::proc::kill_group(pid, std::time::Duration::ZERO);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_lines_parse_on_every_os() {
        let (a, d) = parse_command_line(r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --user-data-dir="C:\Users\a b\p" --flag"#);
        assert_eq!(a, r"C:\Program Files\Google\Chrome\Application\chrome.exe");
        assert_eq!(d.as_deref(), Some(r"C:\Users\a b\p"));
        let (a, d) = parse_command_line("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/Users/x/Library/p q --no-first-run");
        assert_eq!(a, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
        assert_eq!(d.as_deref(), Some("/Users/x/Library/p q"));
        assert_eq!(parse_command_line("/usr/bin/chromium").1, None);
        assert!(cft_exe_rel().ends_with(cft_exe_name()));
        if cfg!(target_os = "linux") {
            assert_eq!((cft_dir().as_str(), cft_exe_rel()), ("chrome-linux64", "chrome"));
        }
    }
}
