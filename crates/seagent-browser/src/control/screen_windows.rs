//! The Windows substitute for the Linux Xvnc + Xfce Bot Desktop ([`super::screen`]): a real
//! isolated desktop object on the interactive window station, created with `CreateDesktopW`.
//! The headed browser is launched onto it (`STARTUPINFOW.lpDesktop`, honoured by
//! [`crate::launch`] through `SEAGENT_BD_DESKTOP`), so its windows never touch the user's own
//! desktop and the user's windows never touch the agent's.
//!
//! Unlike Xvnc, Windows renders only the one active desktop, so the agent acts on this desktop
//! by making it active ([`WinDesktop::take_over`] → `SwitchDesktop`) and the human takes back
//! control by switching to the default desktop; the browser keeps running on the isolated
//! desktop throughout, and its CDP screenshots work whether or not it is the active desktop.
//! [`WinDesktop::screenshot`] additionally grabs the desktop's framebuffer through GDI for the
//! full-desktop computer_use path (black until the desktop has been active at least once).
//!
//! A keep-alive process (an idle Windows PowerShell pinned to the desktop with `lpDesktop`)
//! holds the desktop object open independently of any daemon, the way the Linux launcher
//! process holds the X server; `stop` ends it and the desktop is destroyed.
#![cfg(windows)]

use std::collections::HashMap;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
#[cfg(test)]
use std::time::Duration;
use windows_sys::Win32::Foundation::{BOOL, LPARAM, TRUE};
use windows_sys::Win32::Graphics::Gdi::{BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, CreateDCW, DeleteDC, DeleteObject, GetDIBits, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HDC, SRCCOPY};
use windows_sys::Win32::System::StationsAndDesktops::{CloseDesktop, CreateDesktopW, EnumDesktopsW, GetProcessWindowStation, GetThreadDesktop, OpenDesktopW, OpenInputDesktop, SetThreadDesktop, SwitchDesktop, HDESK};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

/// The desktop handles this process holds open, keyed by desktop name. A desktop is destroyed
/// when its last handle closes and no thread is on it, so the seagent process holds one for the
/// desktop's lifetime (the browser launched onto it, tied to seagent's Job Object, holds it too
/// while it runs — the same "dies with seagent" model as every other browser).
fn held() -> &'static Mutex<HashMap<String, isize>> {
    static H: OnceLock<Mutex<HashMap<String, isize>>> = OnceLock::new();
    H.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The full desktop access this session needs (create / enumerate / read / switch to it).
const DESKTOP_ACCESS: u32 = 0x01FF; // DESKTOP_* generic read+write+createwindow+switch

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// A window-station + desktop name is a sanitised profile (`seagent-<profile>`): the object
/// namespace allows no backslash (the station separator) or control characters.
pub fn desktop_name(profile: &str) -> String {
    let p: String = profile.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).take(64).collect();
    format!("seagent-{}", if p.is_empty() { "default".into() } else { p })
}

/// This home's isolated desktop. Every field a test overrides is explicit.
#[derive(Debug, Clone)]
pub struct WinDesktop {
    pub home: PathBuf,
    pub profile: String,
    pub geometry: String,
}

impl WinDesktop {
    pub fn new(home: &Path, profile: &str, geometry: &str) -> WinDesktop {
        WinDesktop { home: home.to_path_buf(), profile: profile.to_string(), geometry: geometry.to_string() }
    }

    pub fn state_dir(&self) -> PathBuf {
        self.home.join("bot-desktop")
    }

    pub fn name(&self) -> String {
        desktop_name(&self.profile)
    }

    /// `WinSta0\seagent-<profile>` — the value for `STARTUPINFOW.lpDesktop` and the browser's
    /// `SEAGENT_BD_DESKTOP`.
    pub fn qualified(&self) -> String {
        format!("WinSta0\\{}", self.name())
    }

    /// The pid holding this desktop open (`launcher.pid`), when that process is still alive.
    /// seagent writes its own pid; the desktop lives as long as that process does.
    pub fn launcher_pid(&self) -> Option<i32> {
        let raw = std::fs::read_to_string(self.state_dir().join("launcher.pid")).ok()?;
        let pid: i32 = raw.split_whitespace().next()?.parse().ok()?;
        crate::util::pid_alive(pid).then_some(pid)
    }

    pub fn running(&self) -> bool {
        self.launcher_pid().is_some() && self.exists()
    }

    /// Is a desktop of this name present on the interactive window station?
    pub fn exists(&self) -> bool {
        desktop_names().iter().any(|n| n == &self.name())
    }

    /// Create the desktop (idempotent) and hold its handle open for this process's lifetime.
    pub fn start(&self) -> Result<(), String> {
        crate::util::private_dir(&self.state_dir()).map_err(|e| e.to_string())?;
        let name = self.name();
        let wname = wide(&name);
        let mut map = held().lock().unwrap();
        if !map.contains_key(&name) {
            // SAFETY: standard CreateDesktopW; the handle is kept in `held` (closed by `stop`)
            // for this process's lifetime, which keeps the desktop object alive. A console
            // process launched onto a background desktop cannot init its console and exits, so
            // the desktop is held by an open handle, not a resident process.
            let h: HDESK = unsafe { CreateDesktopW(wname.as_ptr(), std::ptr::null(), std::ptr::null(), 0, DESKTOP_ACCESS, std::ptr::null()) };
            if h == 0 {
                return Err(format!("CreateDesktopW({name}) failed ({})", last_error()));
            }
            map.insert(name.clone(), h);
        }
        drop(map);
        let sd = self.state_dir();
        std::fs::write(sd.join("launcher.pid"), std::process::id().to_string()).map_err(|e| e.to_string())?;
        std::fs::write(sd.join("env"), format!("SEAGENT_BD_DESKTOP={}\nSEAGENT_BD_GEOMETRY={}\n", self.qualified(), self.geometry)).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Close this process's handle to the desktop (destroyed once the browser on it is gone) and
    /// clear the state files. True when a desktop was held.
    pub fn stop(&self) -> bool {
        let had = held().lock().unwrap().remove(&self.name());
        if let Some(h) = had {
            // SAFETY: a desktop handle this process created and kept in `held`.
            unsafe { CloseDesktop(h) };
        }
        let sd = self.state_dir();
        for n in ["launcher.pid", "env", "activity"] {
            let _ = std::fs::remove_file(sd.join(n));
        }
        had.is_some()
    }

    /// Make this desktop the active (visible, input) desktop — a human-takeover / agent-acts
    /// switch. The caller restores the default desktop afterwards (`switch_to_default`).
    pub fn take_over(&self) -> Result<(), String> {
        let name = wide(&self.name());
        // SAFETY: open and switch to our own desktop; the handle is closed before returning.
        unsafe {
            let h = CreateDesktopW(name.as_ptr(), std::ptr::null(), std::ptr::null(), 0, DESKTOP_ACCESS, std::ptr::null());
            if h == 0 {
                return Err(format!("the Bot Desktop {} is not available ({})", self.name(), last_error()));
            }
            let ok = SwitchDesktop(h);
            CloseDesktop(h);
            if ok == 0 {
                return Err(format!("SwitchDesktop to {} failed ({})", self.name(), last_error()));
            }
        }
        Ok(())
    }

    /// A BGRA framebuffer grab of the desktop (`width`, `height`, `bgra`), taken by binding a
    /// throwaway thread to it — the visible desktop is never changed. The pixels are black until
    /// the desktop has been the active desktop at least once (Windows renders only the active
    /// one); the browser's own CDP screenshots do not have that limitation.
    pub fn screenshot(&self) -> Result<Shot, String> {
        let name = self.name();
        // The capture runs on its own thread: SetThreadDesktop only takes effect on a thread with
        // no windows, and must not disturb this thread's desktop.
        std::thread::spawn(move || capture(&name)).join().map_err(|_| "screenshot thread panicked".to_string())?
    }
}

/// A raw framebuffer grab.
#[derive(Debug, Clone, PartialEq)]
pub struct Shot {
    pub width: i32,
    pub height: i32,
    pub bgra: Vec<u8>,
}

fn capture(name: &str) -> Result<Shot, String> {
    let wname = wide(name);
    // SAFETY: open the desktop read-only, bind this (window-less) thread to it, grab its display
    // DC, and free every GDI object and handle on the way out.
    unsafe {
        let hdesk = CreateDesktopW(wname.as_ptr(), std::ptr::null(), std::ptr::null(), 0, DESKTOP_ACCESS, std::ptr::null());
        if hdesk == 0 {
            return Err(format!("the Bot Desktop {name} is not available ({})", last_error()));
        }
        let restore = GetThreadDesktop(GetCurrentThreadId());
        let set = SetThreadDesktop(hdesk);
        let display = wide("DISPLAY");
        let dc: HDC = CreateDCW(display.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null());
        let out = if dc == 0 {
            Err(format!("no display DC for {name} ({})", last_error()))
        } else {
            grab(dc)
        };
        if dc != 0 {
            DeleteDC(dc);
        }
        if set != 0 && restore != 0 {
            SetThreadDesktop(restore);
        }
        CloseDesktop(hdesk);
        out
    }
}

/// SAFETY: `dc` is a live display DC bound to the calling thread's desktop.
unsafe fn grab(dc: HDC) -> Result<Shot, String> {
    use windows_sys::Win32::Graphics::Gdi::{GetDeviceCaps, HORZRES, VERTRES};
    let (w, h) = (GetDeviceCaps(dc, HORZRES as i32), GetDeviceCaps(dc, VERTRES as i32));
    if w <= 0 || h <= 0 {
        return Err("the desktop has no size yet".into());
    }
    let mem = CreateCompatibleDC(dc);
    let bmp = CreateCompatibleBitmap(dc, w, h);
    let old = SelectObject(mem, bmp as _);
    let ok = BitBlt(mem, 0, 0, w, h, dc, 0, 0, SRCCOPY);
    let mut bi: BITMAPINFO = std::mem::zeroed();
    bi.bmiHeader = BITMAPINFOHEADER { biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32, biWidth: w, biHeight: -h, biPlanes: 1, biBitCount: 32, biCompression: BI_RGB as u32, ..std::mem::zeroed() };
    let mut bgra = vec![0u8; (w * h * 4) as usize];
    let rows = GetDIBits(mem, bmp, 0, h as u32, bgra.as_mut_ptr() as _, &mut bi, DIB_RGB_COLORS);
    SelectObject(mem, old);
    DeleteObject(bmp as _);
    DeleteDC(mem);
    if ok == 0 || rows == 0 {
        return Err("the desktop framebuffer could not be read".into());
    }
    Ok(Shot { width: w, height: h, bgra })
}

/// Run `f` with the calling thread bound to the isolated desktop `qualified` (`WinSta0\name`),
/// restoring the previous desktop after. A child spawned inside `f` with a std `Command`
/// inherits this desktop, since std leaves `STARTUPINFO.lpDesktop` null (= inherit the parent
/// thread's). This is how [`crate::launch`] lands the headed browser on the Bot Desktop.
pub fn on_desktop<T>(qualified: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    let name = wide(qualified.rsplit('\\').next().unwrap_or(qualified));
    // SAFETY: open the desktop, bind this window-less thread to it, run `f`, restore and close.
    unsafe {
        let h = OpenDesktopW(name.as_ptr(), 0, 0, DESKTOP_ACCESS);
        if h == 0 {
            return Err(format!("the Bot Desktop {qualified} is not open ({})", last_error()));
        }
        let restore = GetThreadDesktop(GetCurrentThreadId());
        if SetThreadDesktop(h) == 0 {
            CloseDesktop(h);
            return Err(format!("cannot bind to {qualified} ({})", last_error()));
        }
        let out = f();
        if restore != 0 {
            SetThreadDesktop(restore);
        }
        CloseDesktop(h);
        Ok(out)
    }
}

/// Switch back to the default interactive desktop (end a `take_over`).
pub fn switch_to_default() -> Result<(), String> {
    let name = wide("Default");
    // SAFETY: open the default desktop and switch to it; close the handle.
    unsafe {
        let h = CreateDesktopW(name.as_ptr(), std::ptr::null(), std::ptr::null(), 0, DESKTOP_ACCESS, std::ptr::null());
        if h == 0 {
            return Err(format!("cannot open the default desktop ({})", last_error()));
        }
        let ok = SwitchDesktop(h);
        CloseDesktop(h);
        if ok == 0 {
            return Err(format!("SwitchDesktop to Default failed ({})", last_error()));
        }
    }
    Ok(())
}

/// Names of the desktops on the interactive window station (`EnumDesktopsW`, current station).
pub fn desktop_names() -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    unsafe extern "system" fn cb(name: *const u16, param: LPARAM) -> BOOL {
        let out = &mut *(param as *mut Vec<String>);
        let mut n = 0isize;
        while *name.offset(n) != 0 {
            n += 1;
        }
        out.push(String::from_utf16_lossy(std::slice::from_raw_parts(name, n as usize)));
        TRUE
    }
    // SAFETY: enumerate the process's own window station, pushing each desktop name into `names`.
    unsafe {
        EnumDesktopsW(GetProcessWindowStation(), Some(cb), &mut names as *mut _ as LPARAM);
    }
    let _ = OpenInputDesktop; // kept for take-over symmetry / future input routing
    names
}

fn last_error() -> u32 {
    // SAFETY: reads this thread's last-error value.
    unsafe { windows_sys::Win32::Foundation::GetLastError() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_sanitised_and_qualified() {
        assert_eq!(desktop_name("work"), "seagent-work");
        assert_eq!(desktop_name("a b\\c"), "seagent-a_b_c");
        assert_eq!(desktop_name(""), "seagent-default");
        let d = WinDesktop::new(Path::new("C:\\h"), "work", "1440x900");
        assert_eq!(d.qualified(), "WinSta0\\seagent-work");
    }

    /// The real window-station API on this host: start creates the desktop and a keep-alive
    /// process, EnumDesktopsW lists it, a throwaway-thread screenshot reads its framebuffer, and
    /// stop destroys it — the visible desktop is never switched.
    #[test]
    fn isolated_desktop_lifecycle() {
        let root = seagent_core::tmp::TempDir::new("seagent-winscreen");
        let d = WinDesktop::new(root.path(), &format!("t{}", std::process::id()), "800x600");
        assert!(!d.exists());
        if let Err(e) = d.start() {
            // Service / session-0 hosts without an interactive window station cannot create one.
            eprintln!("skipped: {e}");
            return;
        }
        assert!(d.exists(), "desktop {} not in {:?}", d.name(), desktop_names());
        assert!(d.running(), "the desktop is held open");
        assert!(desktop_names().iter().any(|n| n == &d.name()));
        let env = std::fs::read_to_string(d.state_dir().join("env")).unwrap();
        assert!(env.contains(&format!("SEAGENT_BD_DESKTOP=WinSta0\\{}", d.name())));
        // A capture succeeds (pixels may be black: the desktop has never been the active one).
        match d.screenshot() {
            Ok(s) => assert!(s.width > 0 && s.height > 0 && s.bgra.len() == (s.width * s.height * 4) as usize),
            Err(e) => eprintln!("screenshot unavailable on this host: {e}"),
        }
        assert!(d.start().is_ok(), "idempotent");
        assert!(d.stop());
        std::thread::sleep(Duration::from_millis(300));
        assert!(!d.running());
    }
}
