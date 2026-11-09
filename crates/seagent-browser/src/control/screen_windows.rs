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
//! full-desktop computer_use path and the console's live view. While the desktop is not the
//! active one its framebuffer is black, so the picture is then composed from its windows
//! instead: each visible top-level window renders itself (`PrintWindow`, full content) and is
//! placed bottom-to-top at its position — the visible desktop is never switched.
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

    /// A BGRA picture of the desktop (`width`, `height`, `bgra`), taken by binding a throwaway
    /// thread to it — the visible desktop is never changed. Windows renders only the active
    /// desktop, so while this one is not active the picture is composed from its windows
    /// (`PrintWindow`) instead of read from the (black) framebuffer.
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
            use windows_sys::Win32::Graphics::Gdi::{GetDeviceCaps, HORZRES, VERTRES};
            let (w, h) = (GetDeviceCaps(dc, HORZRES as i32), GetDeviceCaps(dc, VERTRES as i32));
            match grab(dc) {
                // Not the active desktop: nothing was rendered to the framebuffer (it reads as
                // black, or cannot be read at all) — compose the picture from its windows.
                Ok(s) if is_black(&s.bgra) => compose(hdesk, dc, s.width, s.height).or(Ok(s)),
                Err(e) if w > 0 && h > 0 => compose(hdesk, dc, w, h).map_err(|c| format!("{e}; {c}")),
                other => other,
            }
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

/// A capture worker for a live stream: one thread bound to the desktop for the stream's
/// lifetime, holding its desktop handle and display DC, so a frame costs the grab itself (no
/// thread, desktop open and DC per frame). Frames come at most `max_w` wide: an inactive
/// desktop is composed straight at that size (each window `StretchBlt`ed, HALFTONE), so less
/// is copied, hashed and encoded. Dropping it ends the worker.
/// A request to the capture worker.
enum CaptureRequest {
    /// One whole frame, at most this wide.
    Grab(u32, std::sync::mpsc::Sender<Result<Shot, String>>),
    /// What changed since the last `Track` ([`TrackUpdate`]).
    Track(std::sync::mpsc::Sender<Result<TrackUpdate, String>>),
}

/// What changed on the desktop since the last [`LiveCapture::track`].
#[derive(Debug)]
pub enum TrackUpdate {
    /// The whole desktop (first call, or the window layout changed).
    Full(Shot),
    /// These rectangles changed: (x, y, pixels).
    Rects(Vec<(i32, i32, Shot)>),
    Same,
}

pub struct LiveCapture {
    tx: Option<std::sync::mpsc::Sender<CaptureRequest>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl LiveCapture {
    pub fn start(desktop_name: &str) -> LiveCapture {
        let (tx, rx) = std::sync::mpsc::channel::<CaptureRequest>();
        let name = desktop_name.to_string();
        let worker = std::thread::Builder::new()
            .name("seagent-bd-capture".into())
            .spawn(move || {
                let wname = wide(&name);
                // SAFETY: this window-less thread binds to the desktop once, keeps one display DC
                // for its lifetime and frees both when the stream ends.
                unsafe {
                    let hdesk = CreateDesktopW(wname.as_ptr(), std::ptr::null(), std::ptr::null(), 0, DESKTOP_ACCESS, std::ptr::null());
                    let ok = hdesk != 0 && SetThreadDesktop(hdesk) != 0;
                    let display = wide("DISPLAY");
                    let dc: HDC = if ok { CreateDCW(display.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null()) } else { 0 };
                    let mut tracker = Tracker::default();
                    for req in rx {
                        let gone = || format!("the Bot Desktop {name} is not available ({})", last_error());
                        match req {
                            CaptureRequest::Grab(max_w, reply) => {
                                let _ = reply.send(if dc == 0 { Err(gone()) } else { capture_on(hdesk, dc, max_w) });
                            }
                            CaptureRequest::Track(reply) => {
                                let _ = reply.send(if dc == 0 { Err(gone()) } else { tracker.track(hdesk, dc) });
                            }
                        }
                    }
                    drop(tracker);
                    if dc != 0 {
                        DeleteDC(dc);
                    }
                    if hdesk != 0 {
                        CloseDesktop(hdesk);
                    }
                }
            })
            .ok();
        LiveCapture { tx: worker.as_ref().map(|_| tx), worker }
    }

    /// One frame, at most `max_w` wide.
    pub fn grab(&self, max_w: u32) -> Result<Shot, String> {
        let tx = self.tx.as_ref().ok_or("the capture worker did not start")?;
        let (rtx, rrx) = std::sync::mpsc::channel();
        tx.send(CaptureRequest::Grab(max_w, rtx)).map_err(|_| "the capture worker stopped".to_string())?;
        rrx.recv().map_err(|_| "the capture worker stopped".to_string())?
    }

    /// What changed on the desktop since the last call (full size): the window tracker keeps
    /// one bitmap per window and a composite, re-renders windows that changed last time every
    /// call and the others every [`STATIC_REGRAB`], in parallel, and returns only the
    /// rectangles of windows whose pixels changed (cut from the composite, so overlapping
    /// windows stay right). A new window layout returns the whole desktop.
    pub fn track(&self) -> Result<TrackUpdate, String> {
        let tx = self.tx.as_ref().ok_or("the capture worker did not start")?;
        let (rtx, rrx) = std::sync::mpsc::channel();
        tx.send(CaptureRequest::Track(rtx)).map_err(|_| "the capture worker stopped".to_string())?;
        rrx.recv().map_err(|_| "the capture worker stopped".to_string())?
    }
}

/// How often a window that did not change is rendered again to check (the others: every call).
pub const STATIC_REGRAB: std::time::Duration = std::time::Duration::from_millis(300);

/// A 32-bit top-down DIB section selected into its own memory DC: GDI draws into it and its
/// pixels are read in place (no `GetDIBits` copy).
struct Dib {
    dc: HDC,
    bmp: isize,
    old: isize,
    bits: *mut u8,
    w: i32,
    h: i32,
}

// SAFETY: a memory DC and its DIB are used by one thread at a time (the tracker hands each to
// exactly one grabbing thread and waits for them all).
unsafe impl Send for Dib {}

impl Dib {
    /// SAFETY: `screen` is a live display DC.
    unsafe fn new(screen: HDC, w: i32, h: i32) -> Option<Dib> {
        use windows_sys::Win32::Graphics::Gdi::CreateDIBSection;
        let dc = CreateCompatibleDC(screen);
        if dc == 0 {
            return None;
        }
        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader = BITMAPINFOHEADER { biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32, biWidth: w, biHeight: -h, biPlanes: 1, biBitCount: 32, biCompression: BI_RGB, ..std::mem::zeroed() };
        let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
        let bmp = CreateDIBSection(dc, &bi, DIB_RGB_COLORS, &mut bits, 0, 0);
        if bmp == 0 || bits.is_null() {
            DeleteDC(dc);
            return None;
        }
        let old = SelectObject(dc, bmp as _);
        Some(Dib { dc, bmp: bmp as isize, old: old as isize, bits: bits.cast(), w, h })
    }
    fn pixels(&self) -> &[u8] {
        // SAFETY: the DIB section holds w*h*4 bytes for its lifetime; callers GdiFlush first.
        unsafe { std::slice::from_raw_parts(self.bits, (self.w * self.h * 4) as usize) }
    }
    fn hash(&self) -> u64 {
        self.pixels().as_chunks::<8>().0.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, w| (h ^ u64::from_le_bytes(*w)).wrapping_mul(0x0100_0000_01b3))
    }
    /// The pixels of (x, y, w, h), clipped by the caller to the bitmap.
    fn cut(&self, x: i32, y: i32, w: i32, h: i32) -> Shot {
        let (stride, row) = (self.w as usize * 4, w as usize * 4);
        let px = self.pixels();
        let mut bgra = Vec::with_capacity(row * h as usize);
        for yy in y..y + h {
            let a = yy as usize * stride + x as usize * 4;
            bgra.extend_from_slice(&px[a..a + row]);
        }
        Shot { width: w, height: h, bgra }
    }
}

impl Drop for Dib {
    fn drop(&mut self) {
        // SAFETY: we own the DC and the bitmap; deselect before deleting.
        unsafe {
            SelectObject(self.dc, self.old as _);
            DeleteObject(self.bmp as _);
            DeleteDC(self.dc);
        }
    }
}

/// A device-dependent bitmap in its own memory DC: what `PrintWindow` renders into (fast;
/// rendering straight into a DIB section forces a slow GPU readback inside the render).
struct Ddb {
    dc: HDC,
    bmp: isize,
    old: isize,
}

// SAFETY: as for Dib (one thread at a time).
unsafe impl Send for Ddb {}

impl Ddb {
    /// SAFETY: `screen` is a live display DC.
    unsafe fn new(screen: HDC, w: i32, h: i32) -> Option<Ddb> {
        let dc = CreateCompatibleDC(screen);
        let bmp = CreateCompatibleBitmap(screen, w, h);
        if dc == 0 || bmp == 0 {
            if dc != 0 {
                DeleteDC(dc);
            }
            return None;
        }
        let old = SelectObject(dc, bmp as _);
        Some(Ddb { dc, bmp: bmp as isize, old: old as isize })
    }
}

impl Drop for Ddb {
    fn drop(&mut self) {
        // SAFETY: we own the DC and the bitmap.
        unsafe {
            SelectObject(self.dc, self.old as _);
            DeleteObject(self.bmp as _);
            DeleteDC(self.dc);
        }
    }
}

/// One top-level window of the tracked desktop.
struct TrackedWin {
    hwnd: isize,
    rect: (i32, i32, i32, i32),
    ddb: Ddb,
    dib: Dib,
    hash: u64,
    hot: bool,
    grabbed: std::time::Instant,
}

/// The window tracker behind [`LiveCapture::track`] (lives on the desktop-bound worker).
#[derive(Default)]
struct Tracker {
    comp: Option<Dib>,
    wins: Vec<TrackedWin>,
}

impl Tracker {
    /// SAFETY: `hdesk` / `dc` are this thread's desktop and display DC.
    unsafe fn track(&mut self, hdesk: HDESK, dc: HDC) -> Result<TrackUpdate, String> {
        use windows_sys::Win32::Graphics::Gdi::{GdiFlush, GetDeviceCaps, PatBlt, BLACKNESS, HORZRES, VERTRES};
        let (w, h) = (GetDeviceCaps(dc, HORZRES as i32), GetDeviceCaps(dc, VERTRES as i32));
        if w <= 0 || h <= 0 {
            return Err("the desktop has no size yet".into());
        }
        let list = visible_top_windows(hdesk);
        let same_layout = self.comp.as_ref().is_some_and(|c| (c.w, c.h) == (w, h)) && list.len() == self.wins.len() && list.iter().zip(&self.wins).all(|((hw, r), t)| *hw == t.hwnd && *r == t.rect);
        let now = std::time::Instant::now();
        if !same_layout {
            // New layout: (re)build every window bitmap, render all, compose from scratch.
            let mut old: Vec<TrackedWin> = std::mem::take(&mut self.wins);
            for (hwnd, r) in list {
                let size = (r.2 - r.0, r.3 - r.1);
                let (ddb, dib) = match old.iter().position(|t| t.hwnd == hwnd && (t.dib.w, t.dib.h) == size) {
                    Some(i) => {
                        let t = old.swap_remove(i);
                        (t.ddb, t.dib)
                    }
                    None => match (Ddb::new(dc, size.0, size.1), Dib::new(dc, size.0, size.1)) {
                        (Some(a), Some(b)) => (a, b),
                        _ => continue,
                    },
                };
                self.wins.push(TrackedWin { hwnd, rect: r, ddb, dib, hash: 0, hot: true, grabbed: now });
            }
            let all: Vec<usize> = (0..self.wins.len()).collect();
            render(hdesk, &mut self.wins, &all);
            if self.comp.as_ref().is_none_or(|c| (c.w, c.h) != (w, h)) {
                self.comp = Dib::new(dc, w, h);
            }
            let comp = self.comp.as_ref().ok_or("cannot allocate the desktop bitmap")?;
            PatBlt(comp.dc, 0, 0, w, h, BLACKNESS);
            for t in &self.wins {
                BitBlt(comp.dc, t.rect.0, t.rect.1, t.dib.w, t.dib.h, t.dib.dc, 0, 0, SRCCOPY);
            }
            GdiFlush();
            for t in &mut self.wins {
                t.hash = t.dib.hash();
            }
            return Ok(TrackUpdate::Full(comp.cut(0, 0, w, h)));
        }
        // Same layout: render the windows that changed last time, and the others now and then.
        let due: Vec<usize> = self.wins.iter().enumerate().filter(|(_, t)| t.hot || now.duration_since(t.grabbed) >= STATIC_REGRAB).map(|(i, _)| i).collect();
        render(hdesk, &mut self.wins, &due);
        GdiFlush();
        let mut dirty = vec![];
        for &i in &due {
            let t = &mut self.wins[i];
            let hsh = t.dib.hash();
            t.hot = hsh != t.hash;
            t.grabbed = now;
            if t.hot {
                t.hash = hsh;
                dirty.push(t.rect);
            }
        }
        if dirty.is_empty() {
            return Ok(TrackUpdate::Same);
        }
        let comp = self.comp.as_ref().ok_or("no desktop bitmap")?;
        let mut out = vec![];
        for (l, t, r, b) in dirty {
            let (x0, y0, x1, y1) = (l.max(0), t.max(0), r.min(w), b.min(h));
            if x1 <= x0 || y1 <= y0 {
                continue;
            }
            // Re-compose the area bottom-to-top, so windows above stay above.
            for tw in &self.wins {
                let (ix0, iy0, ix1, iy1) = (x0.max(tw.rect.0), y0.max(tw.rect.1), x1.min(tw.rect.2), y1.min(tw.rect.3));
                if ix1 > ix0 && iy1 > iy0 {
                    BitBlt(comp.dc, ix0, iy0, ix1 - ix0, iy1 - iy0, tw.dib.dc, ix0 - tw.rect.0, iy0 - tw.rect.1, SRCCOPY);
                }
            }
            GdiFlush();
            out.push((x0, y0, comp.cut(x0, y0, x1 - x0, y1 - y0)));
        }
        Ok(if out.is_empty() { TrackUpdate::Same } else { TrackUpdate::Rects(out) })
    }
}

/// Visible, non-minimised top-level windows of the desktop, bottom first: (hwnd, rect).
/// SAFETY: `hdesk` is an open desktop handle.
unsafe fn visible_top_windows(hdesk: HDESK) -> Vec<(isize, (i32, i32, i32, i32))> {
    use windows_sys::Win32::Foundation::{HWND, RECT};
    use windows_sys::Win32::System::StationsAndDesktops::EnumDesktopWindows;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowRect, IsIconic, IsWindowVisible};
    unsafe extern "system" fn cb(hwnd: HWND, param: LPARAM) -> BOOL {
        (*(param as *mut Vec<HWND>)).push(hwnd);
        TRUE
    }
    let mut wins: Vec<HWND> = Vec::new();
    EnumDesktopWindows(hdesk, Some(cb), &mut wins as *mut _ as LPARAM);
    wins.iter()
        .rev()
        .filter_map(|&hw| {
            let mut r: RECT = std::mem::zeroed();
            (IsWindowVisible(hw) != 0 && IsIconic(hw) == 0 && GetWindowRect(hw, &mut r) != 0 && r.right - r.left > 1 && r.bottom - r.top > 1).then_some((hw, (r.left, r.top, r.right, r.bottom)))
        })
        .collect()
}

/// Render the windows `which` into their bitmaps (`PrintWindow`, full content), several at a
/// time on threads bound to the desktop (one window each; PrintWindow waits on the window's
/// own thread, so different windows render in parallel).
/// SAFETY: `hdesk` is an open desktop handle; each window's DIB is touched by one thread only.
unsafe fn render(hdesk: HDESK, wins: &mut [TrackedWin], which: &[usize]) {
    // (window, render DC, readback DC, size)
    let jobs: Vec<(isize, HDC, HDC, i32, i32)> = which.iter().map(|&i| (wins[i].hwnd, wins[i].ddb.dc, wins[i].dib.dc, wins[i].dib.w, wins[i].dib.h)).collect();
    let one = |(hw, ddb, dib, w, h): (isize, HDC, HDC, i32, i32)| {
        // SAFETY: the window's own render / readback DCs, used by this thread only.
        unsafe {
            PrintWindow(hw as _, ddb, PW_RENDERFULLCONTENT);
            BitBlt(dib, 0, 0, w, h, ddb, 0, 0, SRCCOPY);
        }
    };
    if jobs.len() <= 1 {
        jobs.into_iter().for_each(one);
        return;
    }
    let desk = hdesk;
    let threads = jobs.len().min(4);
    std::thread::scope(|sc| {
        for k in 0..threads {
            let mine: Vec<(isize, HDC, HDC, i32, i32)> = jobs.iter().skip(k).step_by(threads).copied().collect();
            sc.spawn(move || {
                // SAFETY: a fresh window-less thread binds to the desktop, then renders its windows.
                unsafe {
                    SetThreadDesktop(desk);
                }
                mine.into_iter().for_each(one);
            });
        }
    });
}

impl Drop for LiveCapture {
    fn drop(&mut self) {
        self.tx = None;
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}

/// SAFETY: `hdesk` is an open desktop handle and `dc` a display DC, both of the calling thread.
unsafe fn capture_on(hdesk: HDESK, dc: HDC, max_w: u32) -> Result<Shot, String> {
    use windows_sys::Win32::Graphics::Gdi::{GetDeviceCaps, HORZRES, VERTRES};
    let (w, h) = (GetDeviceCaps(dc, HORZRES as i32), GetDeviceCaps(dc, VERTRES as i32));
    if w <= 0 || h <= 0 {
        return Err("the desktop has no size yet".into());
    }
    // An active desktop renders to its framebuffer; an inactive one reads black or fails.
    if let Ok(s) = grab(dc) {
        if !is_black(&s.bgra) {
            return Ok(s);
        }
    }
    let scale = (f64::from(max_w.max(160)) / f64::from(w)).min(1.0);
    compose_scaled(hdesk, dc, w, h, scale)
}

/// [`compose`] straight into a `scale`d bitmap (HALFTONE `StretchBlt` per window).
/// SAFETY: as for [`compose`].
unsafe fn compose_scaled(hdesk: HDESK, dc: HDC, w: i32, h: i32, scale: f64) -> Result<Shot, String> {
    use windows_sys::Win32::Foundation::{HWND, RECT};
    use windows_sys::Win32::Graphics::Gdi::{SetBrushOrgEx, SetStretchBltMode, StretchBlt, HALFTONE};
    use windows_sys::Win32::System::StationsAndDesktops::EnumDesktopWindows;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowRect, IsIconic, IsWindowVisible};
    unsafe extern "system" fn cb(hwnd: HWND, param: LPARAM) -> BOOL {
        (*(param as *mut Vec<HWND>)).push(hwnd);
        TRUE
    }
    let (tw, th) = (((f64::from(w) * scale).round() as i32).max(1), ((f64::from(h) * scale).round() as i32).max(1));
    let mut wins: Vec<HWND> = Vec::new();
    EnumDesktopWindows(hdesk, Some(cb), &mut wins as *mut _ as LPARAM);
    let mem = CreateCompatibleDC(dc);
    let bmp = CreateCompatibleBitmap(dc, tw, th);
    let old = SelectObject(mem, bmp as _);
    SetStretchBltMode(mem, HALFTONE as _);
    SetBrushOrgEx(mem, 0, 0, std::ptr::null_mut());
    let mut drawn = 0;
    for &hwnd in wins.iter().rev() {
        let mut r: RECT = std::mem::zeroed();
        if IsWindowVisible(hwnd) == 0 || IsIconic(hwnd) != 0 || GetWindowRect(hwnd, &mut r) == 0 {
            continue;
        }
        let (ww, wh) = (r.right - r.left, r.bottom - r.top);
        if ww <= 1 || wh <= 1 || r.right <= 0 || r.bottom <= 0 || r.left >= w || r.top >= h {
            continue;
        }
        let wdc = CreateCompatibleDC(dc);
        let wbmp = CreateCompatibleBitmap(dc, ww, wh);
        let wold = SelectObject(wdc, wbmp as _);
        if PrintWindow(hwnd, wdc, PW_RENDERFULLCONTENT) != 0 {
            let s = |v: i32| (f64::from(v) * scale).round() as i32;
            if scale >= 1.0 {
                BitBlt(mem, r.left, r.top, ww, wh, wdc, 0, 0, SRCCOPY);
            } else {
                StretchBlt(mem, s(r.left), s(r.top), s(ww).max(1), s(wh).max(1), wdc, 0, 0, ww, wh, SRCCOPY);
            }
            drawn += 1;
        }
        SelectObject(wdc, wold);
        DeleteObject(wbmp as _);
        DeleteDC(wdc);
    }
    let mut bi: BITMAPINFO = std::mem::zeroed();
    bi.bmiHeader = BITMAPINFOHEADER { biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32, biWidth: tw, biHeight: -th, biPlanes: 1, biBitCount: 32, biCompression: BI_RGB, ..std::mem::zeroed() };
    let mut bgra = vec![0u8; (tw * th * 4) as usize];
    let rows = GetDIBits(mem, bmp, 0, th as u32, bgra.as_mut_ptr() as _, &mut bi, DIB_RGB_COLORS);
    SelectObject(mem, old);
    DeleteObject(bmp as _);
    DeleteDC(mem);
    if rows == 0 || drawn == 0 {
        return Err(format!("no window on the desktop could be rendered ({} top-level windows)", wins.len()));
    }
    Ok(Shot { width: tw, height: th, bgra })
}

/// Is the process `pid`'s window the top visible window over every corner and the centre of
/// `rect` (x, y, w, h) on the desktop `name`? (The live view may then paint that browser's
/// page over the picture without covering another window.)
pub fn on_top(name: &str, pid: u32, rect: (i32, i32, i32, i32)) -> bool {
    use windows_sys::Win32::Foundation::{HWND, RECT};
    use windows_sys::Win32::System::StationsAndDesktops::EnumDesktopWindows;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowRect, GetWindowThreadProcessId, IsIconic, IsWindowVisible};
    unsafe extern "system" fn cb(hwnd: HWND, param: LPARAM) -> BOOL {
        (*(param as *mut Vec<HWND>)).push(hwnd);
        TRUE
    }
    let (x, y, w, h) = rect;
    let points = [(x + 2, y + 2), (x + w - 3, y + 2), (x + 2, y + h - 3), (x + w - 3, y + h - 3), (x + w / 2, y + h / 2)];
    let wn = wide(name);
    // SAFETY: enumerate the desktop's windows (top first) and read their rects and owners.
    unsafe {
        let hd = OpenDesktopW(wn.as_ptr(), 0, 0, DESKTOP_ACCESS);
        if hd == 0 {
            return false;
        }
        let mut wins: Vec<HWND> = Vec::new();
        EnumDesktopWindows(hd, Some(cb), &mut wins as *mut _ as LPARAM);
        CloseDesktop(hd);
        points.iter().all(|&(px, py)| {
            for &hwnd in &wins {
                let mut r: RECT = std::mem::zeroed();
                if IsWindowVisible(hwnd) == 0 || IsIconic(hwnd) != 0 || GetWindowRect(hwnd, &mut r) == 0 {
                    continue;
                }
                if px >= r.left && px < r.right && py >= r.top && py < r.bottom {
                    let mut owner = 0u32;
                    GetWindowThreadProcessId(hwnd, &mut owner);
                    return owner == pid;
                }
            }
            false
        })
    }
}

/// Every pixel black (sampled): an inactive desktop's framebuffer.
fn is_black(bgra: &[u8]) -> bool {
    (0..bgra.len() / 4).step_by(97).all(|i| bgra[i * 4] == 0 && bgra[i * 4 + 1] == 0 && bgra[i * 4 + 2] == 0)
}

#[link(name = "user32")]
extern "system" {
    // windows-sys files this under `Win32_Storage_Xps`; one import is not worth the feature.
    fn PrintWindow(hwnd: windows_sys::Win32::Foundation::HWND, hdc: HDC, flags: u32) -> BOOL;
}
const PW_RENDERFULLCONTENT: u32 = 2;

/// The desktop's picture composed from its windows (`w`×`h`, the display's size): each
/// visible, non-minimised top-level window renders itself into a bitmap (`PrintWindow`, which
/// works on a desktop that is not being displayed) and is drawn bottom-to-top at its place.
/// SAFETY: `hdesk` is an open desktop handle and `dc` a display DC bound to it.
unsafe fn compose(hdesk: HDESK, dc: HDC, w: i32, h: i32) -> Result<Shot, String> {
    use windows_sys::Win32::Foundation::{HWND, RECT};
    use windows_sys::Win32::System::StationsAndDesktops::EnumDesktopWindows;
    use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowRect, IsIconic, IsWindowVisible};
    unsafe extern "system" fn cb(hwnd: HWND, param: LPARAM) -> BOOL {
        (*(param as *mut Vec<HWND>)).push(hwnd);
        TRUE
    }
    let mut wins: Vec<HWND> = Vec::new();
    EnumDesktopWindows(hdesk, Some(cb), &mut wins as *mut _ as LPARAM);
    let mem = CreateCompatibleDC(dc);
    let bmp = CreateCompatibleBitmap(dc, w, h);
    let old = SelectObject(mem, bmp as _);
    let (mut drawn, mut visible) = (0, 0);
    // EnumDesktopWindows lists top-first: paint from the bottom up.
    for &hwnd in wins.iter().rev() {
        let mut r: RECT = std::mem::zeroed();
        if IsWindowVisible(hwnd) == 0 || IsIconic(hwnd) != 0 || GetWindowRect(hwnd, &mut r) == 0 {
            continue;
        }
        let (ww, wh) = (r.right - r.left, r.bottom - r.top);
        if ww <= 1 || wh <= 1 || r.right <= 0 || r.bottom <= 0 || r.left >= w || r.top >= h {
            continue;
        }
        visible += 1;
        let wdc = CreateCompatibleDC(dc);
        let wbmp = CreateCompatibleBitmap(dc, ww, wh);
        let wold = SelectObject(wdc, wbmp as _);
        if PrintWindow(hwnd, wdc, PW_RENDERFULLCONTENT) != 0 {
            BitBlt(mem, r.left, r.top, ww, wh, wdc, 0, 0, SRCCOPY);
            drawn += 1;
        }
        SelectObject(wdc, wold);
        DeleteObject(wbmp as _);
        DeleteDC(wdc);
    }
    let mut bi: BITMAPINFO = std::mem::zeroed();
    bi.bmiHeader = BITMAPINFOHEADER { biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32, biWidth: w, biHeight: -h, biPlanes: 1, biBitCount: 32, biCompression: BI_RGB, ..std::mem::zeroed() };
    let mut bgra = vec![0u8; (w * h * 4) as usize];
    let rows = GetDIBits(mem, bmp, 0, h as u32, bgra.as_mut_ptr() as _, &mut bi, DIB_RGB_COLORS);
    SelectObject(mem, old);
    DeleteObject(bmp as _);
    DeleteDC(mem);
    if rows == 0 || drawn == 0 {
        return Err(format!("no window on the desktop could be rendered ({} top-level windows, {visible} visible on screen, {drawn} rendered)", wins.len()));
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

/// Start `cmdline` (a full Windows command line) with its windows on the desktop `qualified`
/// (`WinSta0\name`), naming the desktop in `STARTUPINFOW.lpDesktop` explicitly. Returns the
/// pid. (A child spawned with a std `Command` from a thread bound with [`on_desktop`] was seen to
/// open its windows elsewhere on Windows 11, so callers that must land on the desktop use this.)
pub fn spawn_on_desktop(qualified: &str, cmdline: &str) -> Result<u32, String> {
    spawn_on_desktop_flags(qualified, cmdline, 0)
}

/// [`spawn_on_desktop`] with process creation flags (e.g. `CREATE_NO_WINDOW` for a console
/// program that opens its own windows: a console cannot start on a background desktop).
pub fn spawn_on_desktop_flags(qualified: &str, cmdline: &str, flags: u32) -> Result<u32, String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW};
    let mut desk = wide(qualified);
    let mut cmd = wide(cmdline);
    // SAFETY: plain CreateProcessW with owned, NUL-terminated buffers that outlive the call;
    // both returned handles are closed.
    unsafe {
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = desk.as_mut_ptr();
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        if CreateProcessW(std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 0, flags, std::ptr::null(), std::ptr::null(), &si, &mut pi) == 0 {
            return Err(format!("CreateProcessW on {qualified} failed ({})", last_error()));
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Ok(pi.dwProcessId)
    }
}

/// Quote one argument the way `CommandLineToArgvW` / the MSVC runtime read it back.
pub fn quote_arg(a: &str) -> String {
    if !a.is_empty() && !a.contains([' ', '\t', '\n', '"']) {
        return a.to_string();
    }
    let mut s = String::from('"');
    let mut bs = 0;
    for c in a.chars() {
        match c {
            '\\' => bs += 1,
            '"' => {
                s.push_str(&"\\".repeat(bs * 2 + 1));
                s.push('"');
                bs = 0;
            }
            _ => {
                s.push_str(&"\\".repeat(bs));
                bs = 0;
                s.push(c);
            }
        }
    }
    s.push_str(&"\\".repeat(bs * 2));
    s.push('"');
    s
}

/// A process [`spawn_logged_on_desktop`] started (its handle is closed on drop; the process
/// itself lives on, tied to seagent by its Job Object).
pub struct DesktopChild {
    pub pid: u32,
    handle: windows_sys::Win32::Foundation::HANDLE,
}

// SAFETY: a process handle is usable from any thread.
unsafe impl Send for DesktopChild {}

impl DesktopChild {
    /// The exit code once it has exited.
    pub fn try_wait(&self) -> Option<u32> {
        use windows_sys::Win32::System::Threading::GetExitCodeProcess;
        let mut code = 0u32;
        // SAFETY: a live process handle we own.
        let ok = unsafe { GetExitCodeProcess(self.handle, &mut code) };
        (ok != 0 && code != 259 /* STILL_ACTIVE */).then_some(code)
    }
    /// Block until it exits.
    pub fn wait(&self) {
        // SAFETY: a live process handle we own.
        unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(self.handle, u32::MAX) };
    }
}

impl Drop for DesktopChild {
    fn drop(&mut self) {
        // SAFETY: we own the handle.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

/// Start `exe args` with its windows on the desktop `qualified` (`WinSta0\name`, named in
/// `STARTUPINFOW.lpDesktop` — std cannot, and a null lpDesktop means the desktop of *this
/// process*, not of the calling thread), this process's environment plus `env`, stdout and
/// stderr appended to `log`, in its own process group and kill-on-close Job Object exactly
/// like `seagent_core::proc::spawn_tied` (created suspended, put in the job, then resumed).
pub fn spawn_logged_on_desktop(qualified: &str, exe: &Path, args: &[String], env: &[(String, String)], log: &std::fs::File) -> Result<DesktopChild, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, HANDLE};
    use windows_sys::Win32::System::Threading::{CreateProcessW, GetCurrentProcess, ResumeThread, TerminateProcess, PROCESS_INFORMATION, STARTUPINFOW};
    const CREATE_SUSPENDED: u32 = 0x4;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x200;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x400;
    const STARTF_USESTDHANDLES: u32 = 0x100;
    const DUPLICATE_SAME_ACCESS: u32 = 2;
    let line = std::iter::once(quote_arg(&exe.display().to_string())).chain(args.iter().map(|a| quote_arg(a))).collect::<Vec<_>>().join(" ");
    let mut cmd = wide(&line);
    let mut desk = wide(qualified);
    // Environment block: this process's variables with `env` on top, sorted, NUL-separated.
    let mut vars: std::collections::BTreeMap<String, (String, String)> = std::env::vars_os().map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned())).map(|(k, v)| (k.to_uppercase(), (k, v))).collect();
    for (k, v) in env {
        vars.insert(k.to_uppercase(), (k.clone(), v.clone()));
    }
    let mut block: Vec<u16> = vars.values().flat_map(|(k, v)| std::ffi::OsStr::new(&format!("{k}={v}")).encode_wide().chain(Some(0)).collect::<Vec<_>>()).collect();
    block.push(0);
    // SAFETY: CreateProcessW with owned NUL-terminated buffers that outlive the call; the
    // inheritable duplicate of the log handle and the thread handle are closed here, the
    // process handle is owned by the returned DesktopChild.
    unsafe {
        let me = GetCurrentProcess();
        let mut out: HANDLE = 0;
        if DuplicateHandle(me, log.as_raw_handle() as HANDLE, me, &mut out, 0, 1, DUPLICATE_SAME_ACCESS) == 0 {
            return Err(format!("cannot hand the log to the child ({})", last_error()));
        }
        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        si.lpDesktop = desk.as_mut_ptr();
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdOutput = out;
        si.hStdError = out;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let flags = CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT | seagent_core::platform::proc::console_flags();
        let ok = CreateProcessW(std::ptr::null(), cmd.as_mut_ptr(), std::ptr::null(), std::ptr::null(), 1, flags, block.as_ptr().cast(), std::ptr::null(), &si, &mut pi);
        let err = last_error();
        CloseHandle(out);
        if ok == 0 {
            return Err(format!("CreateProcessW({}) on {qualified} failed ({err})", exe.display()));
        }
        if let Err(e) = seagent_core::platform::proc::adopt_raw(pi.hProcess, pi.dwProcessId) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return Err(format!("cannot put pid {} in a job object: {e}", pi.dwProcessId));
        }
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        Ok(DesktopChild { pid: pi.dwProcessId, handle: pi.hProcess })
    }
}

/// Visible top-level windows on the desktop `name` (diagnostics and tests).
pub fn visible_windows(name: &str) -> Result<usize, String> {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::System::StationsAndDesktops::EnumDesktopWindows;
    use windows_sys::Win32::UI::WindowsAndMessaging::IsWindowVisible;
    unsafe extern "system" fn cb(hwnd: HWND, param: LPARAM) -> BOOL {
        if IsWindowVisible(hwnd) != 0 {
            *(param as *mut usize) += 1;
        }
        TRUE
    }
    let w = wide(name);
    // SAFETY: open the desktop for enumeration, count its visible windows, close it.
    unsafe {
        let h = OpenDesktopW(w.as_ptr(), 0, 0, DESKTOP_ACCESS);
        if h == 0 {
            return Err(format!("desktop {name} is not open ({})", last_error()));
        }
        let mut n = 0usize;
        EnumDesktopWindows(h, Some(cb), &mut n as *mut usize as LPARAM);
        CloseDesktop(h);
        Ok(n)
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

    #[test]
    fn arguments_are_quoted_for_the_msvc_runtime() {
        assert_eq!(quote_arg("--headless=new"), "--headless=new");
        assert_eq!(quote_arg("C:\\Program Files\\Edge\\msedge.exe"), "\"C:\\Program Files\\Edge\\msedge.exe\"");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("a\"b"), "\"a\\\"b\"");
        assert_eq!(quote_arg("dir with space\\"), "\"dir with space\\\\\"", "a trailing backslash is doubled before the closing quote");
    }

    /// The Bot Desktop browser really opens on the isolated desktop (not the user's), through
    /// `launch::launch` with `SEAGENT_BD_DESKTOP` (not run by default):
    /// `SEAGENT_REAL_TESTS=1 cargo test -p seagent-browser real_bot_desktop_browser -- --ignored`.
    #[test]
    #[ignore]
    fn real_bot_desktop_browser_opens_on_the_isolated_desktop() {
        let Some(exe) = crate::tests_real::real_gate() else { return };
        let root = seagent_core::tmp::TempDir::new("seagent-bd-launch");
        let d = WinDesktop::new(root.path(), &format!("launch{}", std::process::id()), "1280x800");
        d.start().expect("an interactive window station");
        let env: Vec<(String, String)> = std::fs::read_to_string(d.state_dir().join("env")).unwrap().lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let before = visible_windows(&d.name()).unwrap();
        let udd = root.path().join("profile");
        let extra = vec!["--inprivate".to_string()];
        let o = crate::launch::LaunchOpts { exe: &exe, user_data_dir: &udd, headless: false, no_sandbox: false, extra_args: &extra, port: 0, managed: true, env };
        let l = crate::launch::launch(&o, Duration::from_secs(30)).expect("the browser starts on the Bot Desktop");
        let v = crate::cdp::get_json(&l.http, "/json/version", None, Duration::from_secs(5)).expect("its DevTools answers");
        assert!(v["Browser"].is_string(), "{v}");
        let mut after = 0;
        for _ in 0..50 {
            after = visible_windows(&d.name()).unwrap();
            if after > before {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        eprintln!("Bot Desktop {}: {before} visible windows before the launch, {after} after", d.name());
        assert!(after > before, "the browser's window is on the isolated desktop");
        let shot = d.screenshot().expect("a picture of the desktop");
        assert!(!is_black(&shot.bgra), "the composed picture shows the browser");
        crate::util::kill_group(l.pid, Duration::from_secs(3));
        d.stop();
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
