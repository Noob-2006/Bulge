//! Node host commands on Windows and macOS (docs/cross-platform.md: 鍵鼠 / 螢幕, 錄音 / 通知).
//! Linux keeps its tools in `node.rs` (xdotool / ydotool, grim / import, ffmpeg x11grab, v4l2,
//! notify-send, dunst / mako); this module gives the same commands their native substitutes:
//!
//! | command | Windows | macOS |
//! |---|---|---|
//! | `screen.snapshot` | PowerShell + GDI `CopyFromScreen` (primary screen, physical pixels) | `screencapture -x` |
//! | `screen.record` | `ffmpeg -f gdigrab` | `ffmpeg -f avfoundation`, else `screencapture -V` |
//! | `computer.act` input | `SendInput` / `SetCursorPos` (this process) | `cliclick` when installed, else CGEvent through JXA (`osascript -l JavaScript`); text through System Events |
//! | `camera.list` / `camera.snap` | `ffmpeg -f dshow` device list / grab | `ffmpeg -f avfoundation` |
//! | `location.get` | `System.Device.Location.GeoCoordinateWatcher` | `CoreLocationCLI` when installed |
//! | `system.notify` | WinRT toast (`ToastNotificationManager`, no module needed) | `osascript display notification` |
//! | `notifications.*` | not offered: no API reads other apps' notifications | not offered (same) |
//! | `talk.ptt.*` (microphone) | `ffmpeg -f dshow` audio device | `rec` (SoX), else `ffmpeg -f avfoundation` |
//!
//! Text from the model (titles, bodies, typed text, paths) reaches PowerShell / AppleScript
//! only through environment variables or argv, never spliced into a script.

#[cfg(windows)]
use super::with_env;
use super::{run_cmd, run_ctl, tmp_file, which, Ctl, HostPolicy};
use serde_json::{json, Value};
use std::time::Duration;

/// `backend` reported by `computer.act`.
#[cfg(windows)]
pub(crate) const INPUT_NAME: &str = "sendinput";
#[cfg(target_os = "macos")]
pub(crate) const INPUT_NAME: &str = "cgevent";

/// The device commands this host offers under `policy` (the portable ones are added by the caller).
pub(crate) fn commands(policy: &HostPolicy) -> Vec<&'static str> {
    let mut c = vec![];
    let ffmpeg = which("ffmpeg").is_some();
    if policy.screen {
        c.push("screen.snapshot");
        if ffmpeg || cfg!(target_os = "macos") {
            c.push("screen.record");
        }
    }
    if policy.camera && ffmpeg {
        c.extend(["camera.list", "camera.snap"]);
    }
    if policy.location && (cfg!(windows) || which("CoreLocationCLI").is_some()) {
        c.push("location.get");
    }
    if policy.computer {
        c.push("computer.act");
    }
    if policy.microphone && policy.stt.is_some() && super::talk::available() {
        c.extend(["talk.ptt.start", "talk.ptt.stop", "talk.ptt.cancel", "talk.ptt.once"]);
    }
    if policy.canvas {
        c.push("canvas.present");
    }
    c
}

/// Run `command` when it is one this module implements (`None`: the portable code in node.rs).
pub(crate) fn run(policy: &HostPolicy, command: &str, p: &Value, t: Duration, ctl: &Ctl) -> Option<Result<Value, String>> {
    Some(match command {
        "system.notify" => notify(p["title"].as_str().unwrap_or("seagent"), p["body"].as_str().unwrap_or(""), t).map(|_| json!("shown")),
        "device.info" => Ok(json!({"hostname": seagent_core::platform::sysinfo::hostname(), "os": std::env::consts::OS, "arch": std::env::consts::ARCH, "kernel": seagent_core::platform::sysinfo::kernel_release().unwrap_or_default(), "commands": super::host_commands(policy)})),
        "screen.record" if policy.screen => record(p, ctl),
        "computer.act" if policy.computer => computer(policy, p, t),
        "camera.list" if policy.camera => Ok(json!(devices("video"))),
        "camera.snap" if policy.camera => camera_snap(p, t),
        "location.get" if policy.location => location(t),
        "notifications.list" | "notifications.actions" if policy.notifications => Err(format!("{command} is not available on {} nodes: the OS has no API for reading other apps' notifications", std::env::consts::OS)),
        _ => return None,
    })
}

// ───────────────────────── screen ─────────────────────────

/// PNG of the primary screen.
#[cfg(windows)]
pub(crate) fn snapshot(t: Duration) -> Result<Vec<u8>, String> {
    // DPI-aware first, so the bitmap is in physical pixels (the coordinates SendInput uses).
    const PS: &str = "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public static class SeagentDpi { [DllImport(\"user32.dll\")] public static extern bool SetProcessDPIAware(); }'; [SeagentDpi]::SetProcessDPIAware() | Out-Null; $b=[System.Windows.Forms.Screen]::PrimaryScreen.Bounds; $bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; $g=[System.Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($b.Left,$b.Top,0,0,$bmp.Size); $bmp.Save($env:SEAGENT_SHOT,[System.Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $bmp.Dispose()";
    let tmp = tmp_file("shot", "png");
    let r = with_env(&[("SEAGENT_SHOT".into(), tmp.display().to_string())], || powershell(PS, t));
    let b = r.and_then(|_| std::fs::read(&tmp).map_err(|e| format!("screenshot: {e}")));
    let _ = std::fs::remove_file(&tmp);
    b
}

/// PNG of the main display (`screencapture -x`: no sound; needs the Screen Recording grant).
#[cfg(target_os = "macos")]
pub(crate) fn snapshot(t: Duration) -> Result<Vec<u8>, String> {
    let tmp = tmp_file("shot", "png");
    let r = run_cmd(&["screencapture", "-x", "-t", "png", &tmp.display().to_string()], t);
    let b = r.and_then(|_| std::fs::read(&tmp).map_err(|e| format!("screencapture wrote nothing ({e}); grant Screen Recording to this terminal / seagent in System Settings → Privacy & Security")));
    let _ = std::fs::remove_file(&tmp);
    b
}

/// A region of [`snapshot`] (OpenClaw `zoom`), cropped in memory.
pub(crate) fn crop(x: i64, y: i64, w: i64, h: i64, t: Duration) -> Result<Vec<u8>, String> {
    if w <= 0 || h <= 0 {
        return Err("zoom region must have x2 > x1 and y2 > y1".into());
    }
    let png = snapshot(t)?;
    let img = image::load_from_memory(&png).map_err(|e| format!("zoom capture: {e}"))?;
    let part = img.crop_imm(x.max(0) as u32, y.max(0) as u32, w as u32, h as u32);
    let mut out = std::io::Cursor::new(Vec::new());
    part.write_to(&mut out, image::ImageFormat::Png).map_err(|e| format!("zoom capture: {e}"))?;
    Ok(out.into_inner())
}

fn record(p: &Value, ctl: &Ctl) -> Result<Value, String> {
    let ms = p["durationMs"].as_u64().unwrap_or(5000).clamp(500, 60_000);
    let fps = p["fps"].as_u64().unwrap_or(10).clamp(1, 30).to_string();
    let secs = format!("{:.1}", ms as f64 / 1000.0);
    let budget = Duration::from_millis(ms + 20_000);
    let ffmpeg = which("ffmpeg").is_some();
    let (tmp, mime) = if ffmpeg || cfg!(windows) { (tmp_file("rec", "mp4"), "video/mp4") } else { (tmp_file("rec", "mov"), "video/quicktime") };
    let path = tmp.display().to_string();
    let r = if ffmpeg {
        #[cfg(windows)]
        let input: Vec<String> = ["-f", "gdigrab", "-framerate", fps.as_str(), "-i", "desktop"].map(String::from).to_vec();
        #[cfg(target_os = "macos")]
        let input: Vec<String> = {
            // AVFoundation lists the screens after the cameras; its index is the list position.
            let screen = devices("video").iter().position(|d| d.starts_with("Capture screen")).ok_or("ffmpeg lists no \"Capture screen\" device (grant Screen Recording)")?;
            vec!["-f".into(), "avfoundation".into(), "-framerate".into(), fps.clone(), "-capture_cursor".into(), "1".into(), "-i".into(), format!("{screen}:none")]
        };
        let mut argv: Vec<String> = ["ffmpeg", "-loglevel", "error", "-y"].map(String::from).to_vec();
        argv.extend(input);
        argv.extend(["-t", secs.as_str(), "-pix_fmt", "yuv420p", path.as_str()].map(String::from));
        let a: Vec<&str> = argv.iter().map(String::as_str).collect();
        run_ctl(&a, budget, ctl, false)
    } else if cfg!(target_os = "macos") {
        run_ctl(&["screencapture", "-x", "-v", "-V", &secs, &path], budget, ctl, false)
    } else {
        Err("screen.record on Windows needs ffmpeg on PATH (gdigrab)".into())
    };
    let b = r.and_then(|_| std::fs::read(&tmp).map_err(|e| e.to_string()));
    let _ = std::fs::remove_file(&tmp);
    let b = b?;
    if b.len() > 24 << 20 {
        return Err("recording larger than 24 MB; record less".into());
    }
    Ok(json!({"mime": mime, "durationMs": ms, "base64": seagent_net::crypto::b64(&b)}))
}

// ───────────────────────── media devices (ffmpeg) ─────────────────────────

/// Names of ffmpeg's capture devices of `kind` ("video" / "audio"): DirectShow on Windows,
/// AVFoundation on macOS. Empty without ffmpeg.
pub(crate) fn devices(kind: &str) -> Vec<String> {
    #[cfg(windows)]
    let argv = ["ffmpeg", "-hide_banner", "-list_devices", "true", "-f", "dshow", "-i", "dummy"];
    #[cfg(target_os = "macos")]
    let argv = ["ffmpeg", "-hide_banner", "-f", "avfoundation", "-list_devices", "true", "-i", ""];
    if which("ffmpeg").is_none() {
        return vec![];
    }
    // ffmpeg prints the list on stderr and exits non-zero (there is no real input).
    let Ok(o) = seagent_core::platform::proc::command(argv[0]).args(&argv[1..]).stdin(std::process::Stdio::null()).output() else { return vec![] };
    parse_devices(&String::from_utf8_lossy(&o.stderr), kind)
}

/// Parse ffmpeg's device list. DirectShow: `"Name" (video)` lines (ffmpeg ≥ 5) or `"Name"` under a
/// `DirectShow video devices` header; AVFoundation: `[N] Name` under `AVFoundation video devices:`.
pub(crate) fn parse_devices(stderr: &str, kind: &str) -> Vec<String> {
    let mut section = "";
    let mut out = vec![];
    for l in stderr.lines() {
        let low = l.to_ascii_lowercase();
        if low.contains("video devices") {
            section = "video";
            continue;
        }
        if low.contains("audio devices") {
            section = "audio";
            continue;
        }
        if low.contains("alternative name") {
            continue;
        }
        let tagged = if low.trim_end().ends_with("(video)") {
            "video"
        } else if low.trim_end().ends_with("(audio)") {
            "audio"
        } else {
            section
        };
        if tagged != kind {
            continue;
        }
        if let Some(q) = l.find('"') {
            if let Some(name) = l[q + 1..].split('"').next().filter(|n| !n.is_empty()) {
                out.push(name.to_string());
            }
        } else if let Some(rest) = l.rsplit_once("] [").map(|(_, r)| r) {
            // `[AVFoundation indev @ 0x…] [0] FaceTime HD Camera`
            if let Some((_, name)) = rest.split_once("] ") {
                out.push(name.trim().to_string());
            }
        }
    }
    out
}

/// ffmpeg input arguments for capture device `name` of `kind` (validated against the list).
pub(crate) fn ffmpeg_input(kind: &str, name: Option<&str>) -> Result<Vec<String>, String> {
    let list = devices(kind);
    let pick = match name.filter(|n| !n.is_empty()) {
        Some(n) => list.iter().find(|d| d.as_str() == n).cloned().ok_or_else(|| format!("no {kind} device named `{n}`; camera.list / the ffmpeg device list shows: {}", list.join(", ")))?,
        None => list.iter().find(|d| !d.starts_with("Capture screen")).cloned().ok_or_else(|| format!("ffmpeg lists no {kind} capture device"))?,
    };
    #[cfg(windows)]
    return Ok(vec!["-f".into(), "dshow".into(), "-i".into(), format!("{kind}={pick}")]);
    #[cfg(target_os = "macos")]
    {
        let i = list.iter().position(|d| *d == pick).unwrap_or(0);
        let spec = if kind == "video" { format!("{i}:none") } else { format!(":{i}") };
        let mut v: Vec<String> = vec!["-f".into(), "avfoundation".into()];
        if kind == "video" {
            v.extend(["-framerate".into(), "30".into()]);
        }
        v.extend(["-i".into(), spec]);
        Ok(v)
    }
}

fn camera_snap(p: &Value, t: Duration) -> Result<Value, String> {
    let tmp = tmp_file("cam", "jpg");
    let mut argv: Vec<String> = ["ffmpeg", "-loglevel", "error", "-y"].map(String::from).to_vec();
    argv.extend(ffmpeg_input("video", p["device"].as_str())?);
    argv.extend(["-frames:v".into(), "1".into(), tmp.display().to_string()]);
    let a: Vec<&str> = argv.iter().map(String::as_str).collect();
    run_cmd(&a, t)?;
    let b = std::fs::read(&tmp).map_err(|e| e.to_string());
    let _ = std::fs::remove_file(&tmp);
    Ok(json!({"mime": "image/jpeg", "base64": seagent_net::crypto::b64(&b?)}))
}

// ───────────────────────── notifications, location ─────────────────────────

#[cfg(windows)]
fn notify(title: &str, body: &str, t: Duration) -> Result<(), String> {
    // WinRT through Windows PowerShell 5.1 (pwsh cannot load WinRT types). The app id is
    // PowerShell's own, so the toast shows without registering a shortcut.
    const PS: &str = "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null; [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null; $e=[System.Security.SecurityElement]; $x=New-Object Windows.Data.Xml.Dom.XmlDocument; $x.LoadXml(\"<toast><visual><binding template='ToastGeneric'><text>$($e::Escape($env:SEAGENT_TITLE))</text><text>$($e::Escape($env:SEAGENT_BODY))</text></binding></visual></toast>\"); [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($x))";
    with_env(&[("SEAGENT_TITLE".into(), title.into()), ("SEAGENT_BODY".into(), body.into())], || run_cmd(&["powershell", "-NoProfile", "-NonInteractive", "-Command", PS], t)).map(|_| ())
}

#[cfg(target_os = "macos")]
fn notify(title: &str, body: &str, t: Duration) -> Result<(), String> {
    run_cmd(&["osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, body], t).map(|_| ())
}

#[cfg(windows)]
fn location(t: Duration) -> Result<Value, String> {
    const PS: &str = "Add-Type -AssemblyName System.Device; $w=New-Object System.Device.Location.GeoCoordinateWatcher; $w.Start(); $n=0; while (($w.Status -ne 'Ready') -and ($n -lt 100)) { Start-Sleep -Milliseconds 100; $n++ }; $c=$w.Position.Location; if ($w.Permission -eq 'Denied') { 'denied' } elseif ($c.IsUnknown) { 'unknown' } else { '{0},{1} accuracy {2}m' -f $c.Latitude,$c.Longitude,$c.HorizontalAccuracy }";
    let out = powershell(PS, t)?;
    match out.trim() {
        "denied" => Err("location access is denied: turn on Settings → Privacy & security → Location for desktop apps".into()),
        "unknown" => Err("Windows location service returned no fix (is Location turned on?)".into()),
        s => Ok(Value::String(s.to_string())),
    }
}

#[cfg(target_os = "macos")]
fn location(t: Duration) -> Result<Value, String> {
    which("CoreLocationCLI").ok_or("location.get on macOS needs CoreLocationCLI (`brew install corelocationcli`) with Location Services granted")?;
    run_cmd(&["CoreLocationCLI", "-once", "-format", "%latitude,%longitude accuracy %h_accuracym"], t).map(|s| Value::String(s.trim().to_string()))
}

#[cfg(windows)]
fn powershell(script: &str, t: Duration) -> Result<String, String> {
    run_cmd(&["powershell", "-NoProfile", "-NonInteractive", "-STA", "-Command", script], t)
}

// ───────────────────────── computer.act ─────────────────────────

fn computer(policy: &HostPolicy, p: &Value, t: Duration) -> Result<Value, String> {
    let action = p["action"].as_str().unwrap_or("");
    let os = std::env::consts::OS;
    match action {
        "screenshot" => return Ok(json!({"mime": "image/png", "base64": seagent_net::crypto::b64(&snapshot(t)?)})),
        "get_browser_state" | "browser_navigate" | "browser_click" | "browser_type" => return super::cdp::act(&policy.cdp_url, p),
        "launch_app" => {
            let app = p["app"].as_str().filter(|a| !a.is_empty() && !a.starts_with('-') && a.chars().all(|c| c.is_ascii_alphanumeric() || "._- ".contains(c))).ok_or("launch_app needs `app`: an application name such as notepad / TextEdit")?;
            #[cfg(windows)]
            run_cmd(&["cmd", "/C", "start", "", app], t)?;
            #[cfg(target_os = "macos")]
            run_cmd(&["open", "-a", app], t)?;
            return Ok(json!({"ok": true, "app": app}));
        }
        "list_apps" | "list_windows" | "get_accessibility_tree" | "get_window_state" | "set_value" | "bring_to_front" => {
            return Err(format!("computer.act action `{action}` (accessibility tree) is not available on {os} nodes yet; act by coordinate on a screenshot"));
        }
        "left_click" | "double_click" if p["x"].is_null() && p["y"].is_null() && p["elementRef"].is_string() => {
            return Err(format!("element clicks need the accessibility tree, which {os} nodes do not offer yet; pass x and y"));
        }
        "kill_app" | "zoom" | "invoke_menu" | "browser_prepare" | "browser_dialog" | "browser_set_input_files" | "browser_download" | "browser_pointer" | "escalate_scope" | "get_recording_state" | "start_recording" | "stop_recording" | "replay_trajectory" => {
            return Err(format!("computer.act action `{action}` is not available on {os} nodes"));
        }
        _ => {}
    }
    let out = act(p, t)?;
    if action == "get_cursor_position" {
        let get = |k: &str| out.lines().find_map(|l| l.strip_prefix(k)).and_then(|v| v.trim().parse::<i64>().ok());
        return Ok(json!({"x": get("X="), "y": get("Y=")}));
    }
    Ok(json!({"ok": true, "action": p["action"], "backend": INPUT_NAME}))
}

/// The pointer / keyboard part of one `computer.act` step (the actions `node::computer_argv`
/// maps for Linux). `get_cursor_position` answers `X=…\nY=…` like `xdotool getmouselocation`.
pub(crate) fn act(p: &Value, _t: Duration) -> Result<String, String> {
    let action = p["action"].as_str().ok_or("computer.act needs `action`")?;
    let num = |k: &str| p[k].as_f64().map(|f| f.max(0.0).round() as i64);
    let xy = num("x").zip(num("y"));
    let mods: Vec<String> = p["modifiers"].as_str().filter(|m| !m.is_empty()).map(|m| m.split('+').map(str::to_string).collect()).unwrap_or_default();
    match action {
        "mouse_move" => {
            let (x, y) = xy.ok_or("mouse_move needs x and y")?;
            imp::move_to(x, y)
        }
        "left_click" | "right_click" | "middle_click" | "double_click" | "triple_click" => {
            let button = match action {
                "right_click" => imp::Button::Right,
                "middle_click" => imp::Button::Middle,
                _ => imp::Button::Left,
            };
            let n = match action {
                "double_click" => 2,
                "triple_click" => 3,
                _ => 1,
            };
            imp::click(xy, button, n, &mods)
        }
        "left_mouse_down" | "left_mouse_up" => imp::button(xy, action == "left_mouse_down"),
        "left_click_drag" => {
            let (Some(fx), Some(fy)) = (num("fromX"), num("fromY")) else { return Err("left_click_drag needs fromX, fromY, x, y".into()) };
            let to = xy.ok_or("left_click_drag needs fromX, fromY, x, y")?;
            imp::drag((fx, fy), to)
        }
        "scroll" => {
            let n = p["scrollAmount"].as_u64().unwrap_or(3).clamp(1, 50) as i32;
            let (dx, dy) = match p["scrollDirection"].as_str().unwrap_or("down") {
                "up" => (0, n),
                "left" => (-n, 0),
                "right" => (n, 0),
                _ => (0, -n),
            };
            imp::scroll(xy, dx, dy)
        }
        "type" => {
            let text = p["text"].as_str().ok_or("type needs text")?;
            if text.len() > 4000 {
                return Err("text longer than 4000 bytes".into());
            }
            imp::type_text(text)
        }
        "key" | "hold_key" => {
            let combos = p["keys"].as_str().filter(|k| !k.trim().is_empty()).ok_or("key needs keys (e.g. ctrl+c)")?;
            let hold = Duration::from_millis(p["durationMs"].as_u64().unwrap_or(500).min(10_000));
            for combo in combos.split_whitespace() {
                imp::key(combo, (action == "hold_key").then_some(hold))?;
            }
            Ok(String::new())
        }
        "wait" => {
            std::thread::sleep(Duration::from_millis(p["durationMs"].as_u64().unwrap_or(1000).min(30_000)));
            Ok(String::new())
        }
        "get_cursor_position" => imp::cursor().map(|(x, y)| format!("X={x}\nY={y}\n")),
        other => Err(format!("computer.act action `{other}` is not supported on {} nodes", std::env::consts::OS)),
    }
}

/// Windows: `SendInput` from this process (physical pixels after `SetProcessDPIAware`).
#[cfg(windows)]
mod imp {
    use std::time::Duration;
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, MOUSEINPUT};
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetCursorPos, SetCursorPos, SetProcessDPIAware};

    #[derive(Clone, Copy)]
    pub enum Button {
        Left,
        Right,
        Middle,
    }

    const LEFTDOWN: u32 = 0x0002;
    const LEFTUP: u32 = 0x0004;
    const RIGHTDOWN: u32 = 0x0008;
    const RIGHTUP: u32 = 0x0010;
    const MIDDLEDOWN: u32 = 0x0020;
    const MIDDLEUP: u32 = 0x0040;
    const WHEEL: u32 = 0x0800;
    const HWHEEL: u32 = 0x1000;
    const KEYUP: u32 = 0x0002;
    const UNICODE: u32 = 0x0004;
    const EXTENDED: u32 = 0x0001;

    fn dpi() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        // SAFETY: plain user32 call without arguments.
        ONCE.call_once(|| unsafe {
            SetProcessDPIAware();
        });
    }

    fn send(inputs: &[INPUT]) -> Result<String, String> {
        if inputs.is_empty() {
            return Ok(String::new());
        }
        // SAFETY: `inputs` is a valid slice of initialised INPUT structs.
        let n = unsafe { SendInput(inputs.len() as u32, inputs.as_ptr(), std::mem::size_of::<INPUT>() as i32) };
        if n as usize != inputs.len() {
            return Err(format!("SendInput injected {n} of {} events: {} (input to an elevated window needs an elevated seagent)", inputs.len(), std::io::Error::last_os_error()));
        }
        Ok(String::new())
    }

    fn mouse(flags: u32, data: i32) -> INPUT {
        INPUT { r#type: INPUT_MOUSE, Anonymous: INPUT_0 { mi: MOUSEINPUT { dx: 0, dy: 0, mouseData: data as _, dwFlags: flags, time: 0, dwExtraInfo: 0 } } }
    }

    fn kbd(vk: u16, scan: u16, flags: u32) -> INPUT {
        INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 } } }
    }

    pub fn move_to(x: i64, y: i64) -> Result<String, String> {
        dpi();
        // SAFETY: plain user32 call.
        if unsafe { SetCursorPos(x as i32, y as i32) } == 0 {
            return Err(format!("SetCursorPos: {}", std::io::Error::last_os_error()));
        }
        Ok(String::new())
    }

    pub fn cursor() -> Result<(i64, i64), String> {
        dpi();
        let mut p = POINT { x: 0, y: 0 };
        // SAFETY: `p` is a valid POINT.
        if unsafe { GetCursorPos(&mut p) } == 0 {
            return Err(format!("GetCursorPos: {}", std::io::Error::last_os_error()));
        }
        Ok((p.x as i64, p.y as i64))
    }

    fn flags(b: Button) -> (u32, u32) {
        match b {
            Button::Left => (LEFTDOWN, LEFTUP),
            Button::Right => (RIGHTDOWN, RIGHTUP),
            Button::Middle => (MIDDLEDOWN, MIDDLEUP),
        }
    }

    pub fn click(at: Option<(i64, i64)>, b: Button, n: u32, mods: &[String]) -> Result<String, String> {
        if let Some((x, y)) = at {
            move_to(x, y)?;
        }
        let codes = mods.iter().map(|m| vk(m).ok_or_else(|| format!("unknown key `{m}`"))).collect::<Result<Vec<_>, _>>()?;
        let (down, up) = flags(b);
        let mut v: Vec<INPUT> = codes.iter().map(|&(k, e)| kbd(k, 0, e)).collect();
        for _ in 0..n {
            v.push(mouse(down, 0));
            v.push(mouse(up, 0));
        }
        v.extend(codes.iter().rev().map(|&(k, e)| kbd(k, 0, e | KEYUP)));
        send(&v)
    }

    pub fn button(at: Option<(i64, i64)>, down: bool) -> Result<String, String> {
        if let Some((x, y)) = at {
            move_to(x, y)?;
        }
        send(&[mouse(if down { LEFTDOWN } else { LEFTUP }, 0)])
    }

    pub fn drag(from: (i64, i64), to: (i64, i64)) -> Result<String, String> {
        move_to(from.0, from.1)?;
        send(&[mouse(LEFTDOWN, 0)])?;
        // A few intermediate moves: some targets only start a drag after real motion.
        for i in 1..=8 {
            let f = i as f64 / 8.0;
            move_to(from.0 + ((to.0 - from.0) as f64 * f) as i64, from.1 + ((to.1 - from.1) as f64 * f) as i64)?;
            std::thread::sleep(Duration::from_millis(10));
        }
        send(&[mouse(LEFTUP, 0)])
    }

    pub fn scroll(at: Option<(i64, i64)>, dx: i32, dy: i32) -> Result<String, String> {
        if let Some((x, y)) = at {
            move_to(x, y)?;
        }
        let mut v = vec![];
        if dy != 0 {
            v.push(mouse(WHEEL, dy * 120));
        }
        if dx != 0 {
            v.push(mouse(HWHEEL, dx * 120));
        }
        send(&v)
    }

    pub fn type_text(text: &str) -> Result<String, String> {
        let mut v = vec![];
        for c in text.chars() {
            if c == '\n' {
                v.push(kbd(0x0D, 0, 0));
                v.push(kbd(0x0D, 0, KEYUP));
                continue;
            }
            let mut buf = [0u16; 2];
            for u in c.encode_utf16(&mut buf) {
                v.push(kbd(0, *u, UNICODE));
                v.push(kbd(0, *u, UNICODE | KEYUP));
            }
        }
        send(&v)
    }

    pub fn key(combo: &str, hold: Option<Duration>) -> Result<String, String> {
        let codes = combo.split('+').map(|k| vk(k).ok_or_else(|| format!("unknown key `{k}`"))).collect::<Result<Vec<_>, _>>()?;
        send(&codes.iter().map(|&(k, e)| kbd(k, 0, e)).collect::<Vec<_>>())?;
        if let Some(h) = hold {
            std::thread::sleep(h);
        }
        send(&codes.iter().rev().map(|&(k, e)| kbd(k, 0, e | KEYUP)).collect::<Vec<_>>())
    }

    /// Virtual-key code (+ the extended-key flag for the navigation block).
    fn vk(k: &str) -> Option<(u16, u32)> {
        let l = k.to_ascii_lowercase();
        if l.len() == 1 {
            let c = l.as_bytes()[0];
            return Some((
                match c {
                    b'a'..=b'z' => (c - b'a' + 0x41) as u16,
                    b'0'..=b'9' => (c - b'0' + 0x30) as u16,
                    b'-' => 0xBD,
                    b'=' => 0xBB,
                    b'[' => 0xDB,
                    b']' => 0xDD,
                    b';' => 0xBA,
                    b'\'' => 0xDE,
                    b',' => 0xBC,
                    b'.' => 0xBE,
                    b'/' => 0xBF,
                    b'`' => 0xC0,
                    b'\\' => 0xDC,
                    b' ' => 0x20,
                    _ => return None,
                },
                0,
            ));
        }
        if let Some(n) = l.strip_prefix('f').and_then(|n| n.parse::<u16>().ok()).filter(|n| (1..=24).contains(n)) {
            return Some((0x6F + n, 0));
        }
        let (code, ext) = match l.as_str() {
            "ctrl" | "control" | "control_l" => (0x11, 0),
            "shift" | "shift_l" => (0x10, 0),
            "alt" | "alt_l" | "option" => (0x12, 0),
            "super" | "meta" | "cmd" | "win" | "super_l" => (0x5B, EXTENDED),
            "enter" | "return" => (0x0D, 0),
            "esc" | "escape" => (0x1B, 0),
            "tab" => (0x09, 0),
            "space" => (0x20, 0),
            "backspace" => (0x08, 0),
            "delete" | "del" => (0x2E, EXTENDED),
            "insert" => (0x2D, EXTENDED),
            "home" => (0x24, EXTENDED),
            "end" => (0x23, EXTENDED),
            "pageup" | "page_up" | "prior" => (0x21, EXTENDED),
            "pagedown" | "page_down" | "next" => (0x22, EXTENDED),
            "up" => (0x26, EXTENDED),
            "down" => (0x28, EXTENDED),
            "left" => (0x25, EXTENDED),
            "right" => (0x27, EXTENDED),
            "capslock" | "caps_lock" => (0x14, 0),
            "print" => (0x2C, 0),
            _ => return None,
        };
        Some((code, ext))
    }
}

/// macOS: `cliclick` for the pointer when installed, else CGEvent through JXA; keys through
/// CGEvent, text through System Events (all need the Accessibility grant).
#[cfg(target_os = "macos")]
mod imp {
    use super::super::{run_cmd, which, with_env};
    use std::time::Duration;

    #[derive(Clone, Copy)]
    pub enum Button {
        Left,
        Right,
        Middle,
    }

    const T: Duration = Duration::from_secs(15);

    fn jxa(body: &str) -> Result<String, String> {
        let script = format!("ObjC.import('CoreGraphics');\nfunction post(e){{$.CGEventPost(0,e);}}\nfunction mouse(t,x,y,b,n){{var e=$.CGEventCreateMouseEvent($(),t,$.CGPointMake(x,y),b);if(n){{$.CGEventSetIntegerValueField(e,1,n);}}post(e);}}\nfunction here(){{return $.CGEventGetLocation($.CGEventCreate($()));}}\n{body}");
        run_cmd(&["osascript", "-l", "JavaScript", "-e", &script], T)
    }

    fn cliclick(args: &[String]) -> Option<Result<String, String>> {
        which("cliclick")?;
        let mut a: Vec<&str> = vec!["cliclick"];
        a.extend(args.iter().map(String::as_str));
        Some(run_cmd(&a, T))
    }

    pub fn move_to(x: i64, y: i64) -> Result<String, String> {
        if let Some(r) = cliclick(&[format!("m:{x},{y}")]) {
            return r;
        }
        jxa(&format!("mouse(5,{x},{y},0,0);"))
    }

    pub fn cursor() -> Result<(i64, i64), String> {
        let out = jxa("var p=here(); Math.round(p.x)+','+Math.round(p.y)")?;
        let (x, y) = out.trim().split_once(',').ok_or_else(|| format!("cursor position: {out}"))?;
        Ok((x.trim().parse().map_err(|_| format!("cursor position: {out}"))?, y.trim().parse().map_err(|_| format!("cursor position: {out}"))?))
    }

    fn mods_mask(mods: &[String]) -> Result<u64, String> {
        mods.iter().try_fold(0u64, |m, k| Ok(m | flag(k).ok_or_else(|| format!("unknown modifier `{k}`"))?))
    }

    pub fn click(at: Option<(i64, i64)>, b: Button, n: u32, mods: &[String]) -> Result<String, String> {
        let mask = mods_mask(mods)?;
        if let (Button::Left | Button::Right, 0, Some((x, y))) = (b, mask, at) {
            let verb = match (b, n) {
                (Button::Right, _) => "rc",
                (_, 2) => "dc",
                (_, 3) => "tc",
                _ => "c",
            };
            if let Some(r) = cliclick(&[format!("{verb}:{x},{y}")]) {
                return r;
            }
        }
        let (down, up, btn) = match b {
            Button::Left => (1, 2, 0),
            Button::Right => (3, 4, 1),
            Button::Middle => (25, 26, 2),
        };
        let pos = match at {
            Some((x, y)) => format!("var x={x},y={y};mouse(5,x,y,0,0);"),
            None => "var p=here(),x=p.x,y=p.y;".into(),
        };
        let mut s = pos;
        for i in 1..=n {
            s.push_str(&format!("var d=$.CGEventCreateMouseEvent($(),{down},$.CGPointMake(x,y),{btn});$.CGEventSetIntegerValueField(d,1,{i});$.CGEventSetFlags(d,{mask});post(d);var u=$.CGEventCreateMouseEvent($(),{up},$.CGPointMake(x,y),{btn});$.CGEventSetIntegerValueField(u,1,{i});$.CGEventSetFlags(u,{mask});post(u);"));
        }
        jxa(&s)
    }

    pub fn button(at: Option<(i64, i64)>, down: bool) -> Result<String, String> {
        let pos = match at {
            Some((x, y)) => format!("var x={x},y={y};mouse(5,x,y,0,0);"),
            None => "var p=here(),x=p.x,y=p.y;".into(),
        };
        jxa(&format!("{pos}mouse({},x,y,0,0);", if down { 1 } else { 2 }))
    }

    pub fn drag(from: (i64, i64), to: (i64, i64)) -> Result<String, String> {
        if let Some(r) = cliclick(&[format!("dd:{},{}", from.0, from.1), format!("dm:{},{}", to.0, to.1), format!("du:{},{}", to.0, to.1)]) {
            return r;
        }
        let (fx, fy, tx, ty) = (from.0, from.1, to.0, to.1);
        jxa(&format!("mouse(5,{fx},{fy},0,0);mouse(1,{fx},{fy},0,0);for(var i=1;i<=8;i++){{mouse(6,{fx}+({tx}-{fx})*i/8,{fy}+({ty}-{fy})*i/8,0,0);delay(0.01);}}mouse(2,{tx},{ty},0,0);"))
    }

    pub fn scroll(at: Option<(i64, i64)>, dx: i32, dy: i32) -> Result<String, String> {
        let pos = at.map(|(x, y)| format!("mouse(5,{x},{y},0,0);")).unwrap_or_default();
        // CGEventCreateScrollWheelEvent2: units 1 = lines, 2 wheels (vertical, horizontal).
        jxa(&format!("{pos}post($.CGEventCreateScrollWheelEvent2($(),1,2,{dy},{dx},0));"))
    }

    pub fn type_text(text: &str) -> Result<String, String> {
        // The text travels in the environment, never inside the script.
        with_env(&[("SEAGENT_TEXT".into(), text.into())], || jxa("var t=$.NSProcessInfo.processInfo.environment.objectForKey('SEAGENT_TEXT').js; Application('System Events').keystroke(t); ''"))
    }

    pub fn key(combo: &str, hold: Option<Duration>) -> Result<String, String> {
        let parts: Vec<&str> = combo.split('+').collect();
        let mut mask = 0u64;
        let mut mod_codes = vec![];
        let mut main = None;
        for k in &parts {
            match (flag(k), code(k)) {
                (Some(f), Some(c)) if parts.len() > 1 || main.is_some() => {
                    mask |= f;
                    mod_codes.push(c);
                }
                (_, Some(c)) => main = Some(c),
                _ => return Err(format!("unknown key `{k}`")),
            }
        }
        let main = main.or_else(|| mod_codes.pop()).ok_or_else(|| format!("unknown key `{combo}`"))?;
        let ms = hold.map(|h| h.as_secs_f64()).unwrap_or(0.0);
        let mut s = String::new();
        for c in &mod_codes {
            s.push_str(&format!("post($.CGEventCreateKeyboardEvent($(),{c},true));"));
        }
        s.push_str(&format!("var d=$.CGEventCreateKeyboardEvent($(),{main},true);$.CGEventSetFlags(d,{mask});post(d);"));
        if ms > 0.0 {
            s.push_str(&format!("delay({ms:.3});"));
        }
        s.push_str(&format!("var u=$.CGEventCreateKeyboardEvent($(),{main},false);$.CGEventSetFlags(u,{mask});post(u);"));
        for c in mod_codes.iter().rev() {
            s.push_str(&format!("post($.CGEventCreateKeyboardEvent($(),{c},false));"));
        }
        jxa(&s)
    }

    /// CGEventFlags mask of a modifier name.
    fn flag(k: &str) -> Option<u64> {
        Some(match k.to_ascii_lowercase().as_str() {
            "shift" | "shift_l" => 0x20000,
            "ctrl" | "control" | "control_l" => 0x40000,
            "alt" | "alt_l" | "option" => 0x80000,
            "super" | "meta" | "cmd" | "win" | "super_l" | "command" => 0x100000,
            _ => return None,
        })
    }

    /// macOS virtual key code (US layout).
    fn code(k: &str) -> Option<u16> {
        const LETTERS: [u16; 26] = [0, 11, 8, 2, 14, 3, 5, 4, 34, 38, 40, 37, 46, 45, 31, 35, 12, 15, 1, 17, 32, 9, 13, 7, 16, 6];
        const DIGITS: [u16; 10] = [29, 18, 19, 20, 21, 23, 22, 26, 28, 25];
        const F: [u16; 12] = [122, 120, 99, 118, 96, 97, 98, 100, 101, 109, 103, 111];
        let l = k.to_ascii_lowercase();
        if l.len() == 1 {
            let c = l.as_bytes()[0];
            return Some(match c {
                b'a'..=b'z' => LETTERS[(c - b'a') as usize],
                b'0'..=b'9' => DIGITS[(c - b'0') as usize],
                b'-' => 27,
                b'=' => 24,
                b'[' => 33,
                b']' => 30,
                b';' => 41,
                b'\'' => 39,
                b',' => 43,
                b'.' => 47,
                b'/' => 44,
                b'`' => 50,
                b'\\' => 42,
                b' ' => 49,
                _ => return None,
            });
        }
        if let Some(n) = l.strip_prefix('f').and_then(|n| n.parse::<usize>().ok()).filter(|n| (1..=12).contains(n)) {
            return Some(F[n - 1]);
        }
        Some(match l.as_str() {
            "ctrl" | "control" | "control_l" => 59,
            "shift" | "shift_l" => 56,
            "alt" | "alt_l" | "option" => 58,
            "super" | "meta" | "cmd" | "win" | "super_l" | "command" => 55,
            "enter" | "return" => 36,
            "esc" | "escape" => 53,
            "tab" => 48,
            "space" => 49,
            "backspace" => 51,
            "delete" | "del" => 117,
            "home" => 115,
            "end" => 119,
            "pageup" | "page_up" | "prior" => 116,
            "pagedown" | "page_down" | "next" => 121,
            "up" => 126,
            "down" => 125,
            "left" => 123,
            "right" => 124,
            "capslock" | "caps_lock" => 57,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::parse_devices;

    #[test]
    fn ffmpeg_device_lists_parse() {
        let dshow = "[dshow @ 0000] \"Integrated Camera\" (video)\n[dshow @ 0000]   Alternative name \"@device_pnp_x\"\n[dshow @ 0000] \"Microphone Array (Realtek(R) Audio)\" (audio)\n";
        assert_eq!(parse_devices(dshow, "video"), ["Integrated Camera"]);
        assert_eq!(parse_devices(dshow, "audio"), ["Microphone Array (Realtek(R) Audio)"]);
        let av = "[AVFoundation indev @ 0x1] AVFoundation video devices:\n[AVFoundation indev @ 0x1] [0] FaceTime HD Camera\n[AVFoundation indev @ 0x1] [1] Capture screen 0\n[AVFoundation indev @ 0x1] AVFoundation audio devices:\n[AVFoundation indev @ 0x1] [0] MacBook Pro Microphone\n";
        assert_eq!(parse_devices(av, "video"), ["FaceTime HD Camera", "Capture screen 0"]);
        assert_eq!(parse_devices(av, "audio"), ["MacBook Pro Microphone"]);
    }
}
