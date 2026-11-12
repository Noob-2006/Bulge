//! The Windows side of [`super`]: display enumeration, the driver's class key, monitor
//! placement, the elevated installer, region grabs and the window herder that keeps hosted apps
//! on the virtual monitor and off the taskbar.

use super::{herd, hosted, installed_version, out_of_the_way, script_args, script_in, virtual_monitor, Action, Rect, Screen, Status};
use crate::control::screen_windows::Shot;
use std::collections::HashSet;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, BOOL, HWND, LPARAM, RECT, TRUE};
use windows_sys::Win32::Graphics::Gdi::{BitBlt, ChangeDisplaySettingsExW, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, EnumDisplayDevicesW, EnumDisplaySettingsW, GetDC, GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, CDS_NORESET, CDS_UPDATEREGISTRY, DEVMODEW, DIB_RGB_COLORS, DISPLAY_DEVICEW, DISPLAY_DEVICE_ATTACHED_TO_DESKTOP, DISPLAY_DEVICE_PRIMARY_DEVICE, DISP_CHANGE_SUCCESSFUL, DM_POSITION, ENUM_CURRENT_SETTINGS, SRCCOPY};
use windows_sys::Win32::System::Registry::{RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_SZ};
use windows_sys::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION};
use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SHELLEXECUTEINFOW};
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindow, GetWindowLongPtrW, GetWindowRect, GetWindowThreadProcessId, IsIconic, IsWindow, IsWindowVisible, IsZoomed, SetWindowLongPtrW, SetWindowPos, ShowWindow, GWL_EXSTYLE, GW_OWNER, SWP_NOACTIVATE, SWP_NOZORDER, SW_HIDE, SW_MAXIMIZE, SW_RESTORE, SW_SHOWNA, SW_SHOWNORMAL, WS_EX_APPWINDOW, WS_EX_TOOLWINDOW};

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn from_wide(b: &[u16]) -> String {
    String::from_utf16_lossy(&b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())])
}

/// Every display device with its current mode (detached ones report an empty rectangle).
pub fn screens() -> Vec<Screen> {
    let mut out = vec![];
    for i in 0..64 {
        // SAFETY: zeroed out-structs with their size fields set, filled by user32.
        unsafe {
            let mut dd: DISPLAY_DEVICEW = std::mem::zeroed();
            dd.cb = std::mem::size_of::<DISPLAY_DEVICEW>() as u32;
            if EnumDisplayDevicesW(std::ptr::null(), i, &mut dd, 0) == 0 {
                break;
            }
            let mut dm: DEVMODEW = std::mem::zeroed();
            dm.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
            let attached = dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP != 0 && EnumDisplaySettingsW(dd.DeviceName.as_ptr(), ENUM_CURRENT_SETTINGS, &mut dm) != 0;
            let pos = dm.Anonymous1.Anonymous2.dmPosition;
            let rect = if attached { Rect { x: pos.x, y: pos.y, w: dm.dmPelsWidth as i32, h: dm.dmPelsHeight as i32 } } else { Rect::default() };
            out.push(Screen { name: from_wide(&dd.DeviceName), adapter: from_wide(&dd.DeviceString), id: from_wide(&dd.DeviceID), attached, primary: dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE != 0, rect, hz: dm.dmDisplayFrequency });
        }
    }
    out
}

/// (`MatchingDeviceId`, `DriverVersion`) of every installed display driver (the class's driver
/// keys; readable without elevation, a subkey that is not is skipped).
fn class_keys() -> Vec<(String, String)> {
    let class = wide("SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}");
    let mut out = vec![];
    // SAFETY: a registry key opened for reading and closed below; value buffers are locals with
    // their sizes passed in.
    unsafe {
        let mut key: HKEY = 0;
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, class.as_ptr(), 0, KEY_READ, &mut key) != 0 {
            return out;
        }
        let value = |sub: &[u16], name: &str| -> Option<String> {
            let n = wide(name);
            let mut buf = [0u16; 260];
            let mut len = (buf.len() * 2) as u32;
            (RegGetValueW(key, sub.as_ptr(), n.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len) == 0).then(|| from_wide(&buf))
        };
        for i in 0..256 {
            let mut name = [0u16; 64];
            let mut len = name.len() as u32;
            if RegEnumKeyExW(key, i, name.as_mut_ptr(), &mut len, std::ptr::null(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
                break;
            }
            let sub: Vec<u16> = name[..len as usize].iter().copied().chain(Some(0)).collect();
            if let (Some(id), Some(ver)) = (value(&sub, "MatchingDeviceId"), value(&sub, "DriverVersion")) {
                out.push((id, ver));
            }
        }
        RegCloseKey(key);
    }
    out
}

fn script() -> Option<PathBuf> {
    script_in(std::env::var_os("SEAGENT_VDD_DIR").map(PathBuf::from), std::env::current_exe().ok().as_deref())
}

/// The driver, the monitor and the bundled installer as they are now.
pub fn probe() -> Status {
    Status {
        windows: true,
        version: installed_version(&class_keys()),
        monitor: virtual_monitor(&screens()).cloned(),
        script: script(),
        forced_isolated: !super::hosting_allowed(std::env::var(super::ENV).ok().as_deref()),
    }
}

/// Move display `name` to (x, y), its mode unchanged (no elevation needed).
fn place(name: &str, x: i32, y: i32) -> Result<(), String> {
    let n = wide(name);
    // SAFETY: a zeroed DEVMODEW with its size and the position field set; null "apply" call.
    unsafe {
        let mut dm: DEVMODEW = std::mem::zeroed();
        dm.dmSize = std::mem::size_of::<DEVMODEW>() as u16;
        dm.dmFields = DM_POSITION;
        dm.Anonymous1.Anonymous2.dmPosition.x = x;
        dm.Anonymous1.Anonymous2.dmPosition.y = y;
        let r = ChangeDisplaySettingsExW(n.as_ptr(), &dm, 0, CDS_UPDATEREGISTRY | CDS_NORESET, std::ptr::null());
        ChangeDisplaySettingsExW(std::ptr::null(), std::ptr::null(), 0, 0, std::ptr::null());
        if r != DISP_CHANGE_SUCCESSFUL {
            return Err(format!("ChangeDisplaySettingsExW({name}) = {r}"));
        }
    }
    Ok(())
}

/// The virtual monitor's rectangle, after moving it to the outside corner when it shares an edge
/// with a real screen (someone rearranged the displays). `None`: no virtual monitor attached.
pub fn ensure_out_of_the_way() -> Option<Rect> {
    let all = screens();
    let v = virtual_monitor(&all)?.clone();
    let real: Vec<Rect> = all.iter().filter(|s| s.attached && !s.is_virtual()).map(|s| s.rect).collect();
    if out_of_the_way(&v.rect, &real) {
        return Some(v.rect);
    }
    let (x, y) = super::corner_origin(&real);
    if let Err(e) = place(&v.name, x, y) {
        eprintln!("seagent: virtual display: {e}");
        return Some(v.rect);
    }
    virtual_monitor(&screens()).map(|s| s.rect)
}

/// Run the bundled installer elevated (the UAC prompt appears on the user's desktop) and return
/// at once; the console window it opens shows its progress. `Err` when the user declined.
pub fn elevate(action: Action) -> Result<(), String> {
    let script = script().ok_or("this build does not bundle the virtual display driver (vdd/install-vdd.ps1 is missing)")?;
    run_elevated(&script, action)
}

fn run_elevated(script: &Path, action: Action) -> Result<(), String> {
    let (verb, file, args) = (wide("runas"), wide("powershell.exe"), wide(&script_args(action, script)));
    // SAFETY: a zeroed SHELLEXECUTEINFOW with its size and the three strings above, which live
    // until the call returns.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = args.as_ptr();
        info.nShow = SW_SHOWNORMAL;
        if ShellExecuteExW(&mut info) == 0 {
            let e = std::io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(1223) { "the administrator prompt was declined".into() } else { format!("could not start the installer: {e}") });
        }
    }
    Ok(())
}

/// A picture of `r` on the displayed desktop (GDI; the fallback when DXGI duplication is not
/// available, and the computer tool's screenshot in hosted mode).
pub fn grab_region(r: Rect) -> Result<Shot, String> {
    if r.w <= 0 || r.h <= 0 {
        return Err("empty region".into());
    }
    // SAFETY: the screen DC of this thread's (displayed) desktop, a compatible bitmap of `r`'s
    // size and a buffer of exactly w*h*4 bytes; every GDI object is freed before returning.
    unsafe {
        let screen = GetDC(0);
        if screen == 0 {
            return Err("no screen DC".into());
        }
        let mem = CreateCompatibleDC(screen);
        let bmp = CreateCompatibleBitmap(screen, r.w, r.h);
        let old = SelectObject(mem, bmp as _);
        let ok = BitBlt(mem, 0, 0, r.w, r.h, screen, r.x, r.y, SRCCOPY | CAPTUREBLT);
        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader = BITMAPINFOHEADER { biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32, biWidth: r.w, biHeight: -r.h, biPlanes: 1, biBitCount: 32, biCompression: BI_RGB, ..std::mem::zeroed() };
        let mut bgra = vec![0u8; (r.w * r.h * 4) as usize];
        let rows = GetDIBits(mem, bmp, 0, r.h as u32, bgra.as_mut_ptr().cast(), &mut bi, DIB_RGB_COLORS);
        SelectObject(mem, old);
        DeleteObject(bmp as _);
        DeleteDC(mem);
        ReleaseDC(0, screen);
        if ok == 0 || rows == 0 {
            return Err("the virtual monitor could not be read".into());
        }
        Ok(Shot { width: r.w, height: r.h, bgra })
    }
}

/// A launch whose windows the herder takes over.
struct Adopt {
    pid: u32,
    /// The launched image's file name, lower case: packaged apps (Notepad, Paint) start a stub
    /// that hands over to another process of the same name.
    image: String,
    /// Top-level windows that existed before the launch (never taken by image name).
    before: HashSet<isize>,
    until: Instant,
    /// A window was already taken by image name for this launch.
    taken: bool,
}

#[derive(Default)]
struct Herd {
    adopt: Vec<Adopt>,
    pids: HashSet<u32>,
    owned: HashSet<isize>,
    running: bool,
}

static HERD: Mutex<Option<Herd>> = Mutex::new(None);

fn with_herd<T>(f: impl FnOnce(&mut Herd) -> T) -> T {
    let mut g = HERD.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Herd::default))
}

/// Visible, non-minimised top-level windows of this thread's desktop.
fn top_windows() -> Vec<isize> {
    unsafe extern "system" fn cb(hwnd: HWND, p: LPARAM) -> BOOL {
        // SAFETY: `p` is the Vec below, alive for the whole enumeration.
        unsafe { (*(p as *mut Vec<isize>)).push(hwnd) };
        TRUE
    }
    let mut all: Vec<isize> = vec![];
    // SAFETY: enumeration into a local.
    unsafe {
        EnumWindows(Some(cb), &mut all as *mut _ as LPARAM);
        all.retain(|&h| IsWindowVisible(h) != 0 && IsIconic(h) == 0);
    }
    all
}

fn image_of(pid: u32) -> Option<String> {
    // SAFETY: a query-only process handle, closed below; the name buffer is a local.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h == 0 {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) != 0;
        CloseHandle(h);
        ok.then(|| String::from_utf16_lossy(&buf[..len as usize])).and_then(|p| Path::new(&p).file_name().map(|n| n.to_string_lossy().to_lowercase()))
    }
}

/// Shell processes that host windows of many launches: one window per launch, never the pid.
fn shared_process(image: &str) -> bool {
    image == "explorer.exe"
}

/// Start `exe args` on the displayed desktop and keep its windows on the hosted monitor.
pub fn launch_native(exe: &Path, args: &[String]) -> Result<u32, String> {
    if hosted().is_none() {
        return Err("the Bot Desktop is not hosted on the virtual display".into());
    }
    let before: HashSet<isize> = top_windows().into_iter().collect();
    let child = std::process::Command::new(exe).args(args).spawn().map_err(|e| format!("failed to start {}: {e}", exe.display()))?;
    let pid = child.id();
    drop(child);
    let image = exe.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    register(pid, Some(Adopt { pid, image, before, until: Instant::now() + Duration::from_secs(20), taken: false }));
    Ok(pid)
}

/// Keep the windows of process `pid` (started on the displayed desktop for the hosted Bot
/// Desktop, e.g. its browser) on the virtual monitor. By pid only: a browser's image name is
/// also the user's own browser.
pub fn adopt_pid(pid: u32) {
    if hosted().is_some() {
        register(pid, None);
    }
}

fn register(pid: u32, adopt: Option<Adopt>) {
    let start = with_herd(|h| {
        h.pids.insert(pid);
        h.adopt.extend(adopt);
        !std::mem::replace(&mut h.running, true)
    });
    if start {
        let _ = std::thread::Builder::new().name("seagent-vdd-herd".into()).spawn(herd_loop);
    }
}

/// Every 150 ms while the Bot Desktop is hosted: adopt new windows of hosted launches, hide them
/// from the taskbar / Alt+Tab and keep them on the virtual monitor.
fn herd_loop() {
    loop {
        let Some(mon) = hosted() else {
            with_herd(|h| *h = Herd::default());
            return;
        };
        let now = Instant::now();
        let wins = top_windows();
        let fresh: Vec<isize> = with_herd(|h| {
            h.adopt.retain(|a| now < a.until);
            h.owned.retain(|&w| unsafe { IsWindow(w) } != 0);
            let mut fresh = vec![];
            for &w in &wins {
                if h.owned.contains(&w) {
                    continue;
                }
                let mut pid = 0u32;
                // SAFETY: plain user32 queries on a window handle from the enumeration.
                let owner = unsafe {
                    GetWindowThreadProcessId(w, &mut pid);
                    GetWindow(w, GW_OWNER)
                };
                let mine = h.pids.contains(&pid) || (owner != 0 && h.owned.contains(&owner)) || {
                    let img = image_of(pid);
                    match h.adopt.iter_mut().find(|a| !a.taken && !a.before.contains(&w) && img.as_deref() == Some(a.image.as_str())) {
                        Some(a) => {
                            a.taken = true;
                            if !shared_process(&a.image) && pid != a.pid {
                                h.pids.insert(pid);
                            }
                            true
                        }
                        None => false,
                    }
                };
                if mine {
                    h.owned.insert(w);
                    fresh.push(w);
                }
            }
            fresh
        });
        for w in fresh {
            hide_from_taskbar(w);
        }
        for w in with_herd(|h| h.owned.iter().copied().collect::<Vec<_>>()) {
            keep_on(w, mon);
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// Close every window the herder keeps (the hosted Bot Desktop is stopping; on the isolated
/// desktop its apps go away with the desktop) and forget the launches.
pub fn close_hosted() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{PostMessageW, WM_CLOSE};
    let owned = with_herd(|h| {
        h.adopt.clear();
        h.pids.clear();
        std::mem::take(&mut h.owned)
    });
    for w in owned {
        // SAFETY: a posted close request to a window handle (ignored when it is gone).
        unsafe { PostMessageW(w, WM_CLOSE, 0, 0) };
    }
}

/// Visible top-level windows of the displayed desktop that overlap `r`, bottom first (tests,
/// diagnostics).
pub fn windows_in(r: Rect) -> Vec<isize> {
    let mut v: Vec<isize> = top_windows()
        .into_iter()
        .filter(|&w| {
            let mut wr: RECT = unsafe { std::mem::zeroed() };
            // SAFETY: rect query into a local.
            (unsafe { GetWindowRect(w, &mut wr) } != 0) && wr.left < r.right() && wr.right > r.x && wr.top < r.bottom() && wr.bottom > r.y
        })
        .collect();
    v.reverse();
    v
}

/// Move window `w` by `dx` pixels (tests: a cheap way to make DWM compose a new frame).
pub fn nudge(w: isize, dx: i32) {
    // SAFETY: rect query and a no-activate move of a test's own window.
    unsafe {
        let mut r: RECT = std::mem::zeroed();
        if GetWindowRect(w, &mut r) != 0 {
            SetWindowPos(w, 0, r.left + dx, r.top, 0, 0, SWP_NOZORDER | SWP_NOACTIVATE | 0x0001);
        }
    }
}

fn hide_from_taskbar(w: isize) {
    // SAFETY: style change on a window the herder owns; hide/show makes the shell re-read it.
    unsafe {
        let ex = GetWindowLongPtrW(w, GWL_EXSTYLE) as u32;
        let want = (ex | WS_EX_TOOLWINDOW) & !WS_EX_APPWINDOW;
        if want != ex {
            ShowWindow(w, SW_HIDE);
            SetWindowLongPtrW(w, GWL_EXSTYLE, want as isize);
            ShowWindow(w, SW_SHOWNA);
        }
    }
}

fn keep_on(w: isize, mon: Rect) {
    // SAFETY: rect query and move of a window the herder owns, without activating it.
    unsafe {
        let mut r: RECT = std::mem::zeroed();
        if GetWindowRect(w, &mut r) == 0 {
            return;
        }
        let cur = Rect { x: r.left, y: r.top, w: r.right - r.left, h: r.bottom - r.top };
        let Some(to) = herd(cur, mon) else { return };
        let zoomed = IsZoomed(w) != 0;
        if zoomed {
            ShowWindow(w, SW_RESTORE);
        }
        SetWindowPos(w, 0, to.x, to.y, to.w, to.h, SWP_NOZORDER | SWP_NOACTIVATE);
        if zoomed {
            ShowWindow(w, SW_MAXIMIZE);
        }
    }
}
