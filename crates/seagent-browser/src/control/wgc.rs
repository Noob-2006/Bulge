//! Windows.Graphics.Capture for one window of the Bot Desktop: the GPU path for windows whose
//! `PrintWindow` picture only refreshes a few times a second while their desktop is not the
//! displayed one (GPU-composited apps). A D3D11 device, a capture item made for the HWND
//! (`IGraphicsCaptureItemInterop::CreateForWindow`), a free-threaded frame pool and a session
//! (no cursor, no yellow border); [`WgcWindow::latest`] drains the pool to its newest frame and
//! copies it through a CPU staging texture into BGRA.
#![cfg(windows)]

use super::screen_windows::Shot;
use windows::core::Interface;
use windows::Graphics::Capture::{Direct3D11CaptureFramePool, GraphicsCaptureItem, GraphicsCaptureSession};
use windows::Graphics::DirectX::Direct3D11::IDirect3DDevice;
use windows::Graphics::DirectX::DirectXPixelFormat;
use windows::Win32::Foundation::{HMODULE, HWND};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_HARDWARE;
use windows::Win32::Graphics::Direct3D11::{D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING};
use windows::Win32::Graphics::Dxgi::IDXGIDevice;
use windows::Win32::System::WinRT::Direct3D11::{CreateDirect3D11DeviceFromDXGIDevice, IDirect3DDxgiInterfaceAccess};
use windows::Win32::System::WinRT::Graphics::Capture::IGraphicsCaptureItemInterop;

/// A running capture of one window.
pub struct WgcWindow {
    device: ID3D11Device,
    ctx: ID3D11DeviceContext,
    pool: Direct3D11CaptureFramePool,
    session: GraphicsCaptureSession,
    staging: Option<(ID3D11Texture2D, u32, u32)>,
    /// Frames the pool delivered so far (diagnostics).
    pub frames: u64,
}

fn e(what: &str) -> impl FnOnce(windows::core::Error) -> String + '_ {
    move |err| format!("Windows.Graphics.Capture {what}: {err}")
}

impl WgcWindow {
    /// Start capturing the window `hwnd`.
    pub fn start(hwnd: isize) -> Result<WgcWindow, String> {
        // SAFETY: COM / WinRT calls on objects created here; the out-pointers are locals.
        unsafe {
            let _ = windows::Win32::System::WinRT::RoInitialize(windows::Win32::System::WinRT::RO_INIT_MULTITHREADED);
            let (mut device, mut ctx) = (None, None);
            D3D11CreateDevice(None, D3D_DRIVER_TYPE_HARDWARE, HMODULE::default(), D3D11_CREATE_DEVICE_BGRA_SUPPORT, None, D3D11_SDK_VERSION, Some(&mut device), None, Some(&mut ctx)).map_err(e("D3D11 device"))?;
            let (device, ctx): (ID3D11Device, ID3D11DeviceContext) = (device.ok_or("no D3D11 device")?, ctx.ok_or("no D3D11 context")?);
            let dxgi: IDXGIDevice = device.cast().map_err(e("DXGI device"))?;
            let d3d: IDirect3DDevice = CreateDirect3D11DeviceFromDXGIDevice(&dxgi).map_err(e("WinRT device"))?.cast().map_err(e("WinRT device"))?;
            let interop = windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>().map_err(e("interop"))?;
            let item: GraphicsCaptureItem = interop.CreateForWindow(HWND(hwnd as *mut _)).map_err(e("item for the window"))?;
            // On a desktop that is not displayed the item can report 0×0: use the window's rect.
            let mut size = item.Size().map_err(e("size"))?;
            if size.Width <= 0 || size.Height <= 0 {
                let mut r = windows::Win32::Foundation::RECT::default();
                let _ = windows::Win32::UI::WindowsAndMessaging::GetWindowRect(HWND(hwnd as *mut _), &mut r);
                size = windows::Graphics::SizeInt32 { Width: (r.right - r.left).max(1), Height: (r.bottom - r.top).max(1) };
            }
            let pool = Direct3D11CaptureFramePool::CreateFreeThreaded(&d3d, DirectXPixelFormat::B8G8R8A8UIntNormalized, 2, size).map_err(e("frame pool"))?;
            let session = pool.CreateCaptureSession(&item).map_err(e("session"))?;
            let _ = session.SetIsCursorCaptureEnabled(false);
            let _ = session.SetIsBorderRequired(false);
            session.StartCapture().map_err(e("start"))?;
            Ok(WgcWindow { device, ctx, pool, session, staging: None, frames: 0 })
        }
    }

    /// The size the capture item reports for `hwnd` (diagnostics).
    pub fn item_size(hwnd: isize) -> Result<(i32, i32), String> {
        // SAFETY: WinRT factory call; the item is dropped at once.
        unsafe {
            let interop = windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>().map_err(e("interop"))?;
            let item: GraphicsCaptureItem = interop.CreateForWindow(HWND(hwnd as *mut _)).map_err(e("item for the window"))?;
            let s = item.Size().map_err(e("size"))?;
            Ok((s.Width, s.Height))
        }
    }

    /// The newest frame since the last call (BGRA), or `None` when the window drew nothing new.
    pub fn latest(&mut self) -> Result<Option<Shot>, String> {
        let mut newest = None;
        while let Ok(f) = self.pool.TryGetNextFrame() {
            self.frames += 1;
            newest = Some(f);
        }
        let Some(frame) = newest else { return Ok(None) };
        let content = frame.ContentSize().map_err(e("content size"))?;
        // SAFETY: D3D11 calls on this capture's own device / context / textures; the mapped
        // pointer is read within its row pitch and unmapped before returning.
        unsafe {
            let access: IDirect3DDxgiInterfaceAccess = frame.Surface().map_err(e("surface"))?.cast().map_err(e("surface"))?;
            let tex: ID3D11Texture2D = access.GetInterface().map_err(e("texture"))?;
            let mut desc = D3D11_TEXTURE2D_DESC::default();
            tex.GetDesc(&mut desc);
            if self.staging.as_ref().is_none_or(|(_, w, h)| (*w, *h) != (desc.Width, desc.Height)) {
                let mut sd = desc;
                sd.Usage = D3D11_USAGE_STAGING;
                sd.BindFlags = 0;
                sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
                sd.MiscFlags = 0;
                let mut st = None;
                self.device.CreateTexture2D(&sd, None, Some(&mut st)).map_err(e("staging texture"))?;
                self.staging = Some((st.ok_or("no staging texture")?, desc.Width, desc.Height));
            }
            let (st, tw, th) = self.staging.as_ref().unwrap();
            self.ctx.CopyResource(st, &tex);
            let mut m = D3D11_MAPPED_SUBRESOURCE::default();
            self.ctx.Map(st, 0, D3D11_MAP_READ, 0, Some(&mut m)).map_err(e("map"))?;
            let (w, h) = ((content.Width.max(1) as u32).min(*tw), (content.Height.max(1) as u32).min(*th));
            let mut bgra = Vec::with_capacity((w * h * 4) as usize);
            for y in 0..h {
                let row = std::slice::from_raw_parts((m.pData as *const u8).add((y * m.RowPitch) as usize), (w * 4) as usize);
                bgra.extend_from_slice(row);
            }
            self.ctx.Unmap(st, 0);
            Ok(Some(Shot { width: w as i32, height: h as i32, bgra }))
        }
    }
}

impl Drop for WgcWindow {
    fn drop(&mut self) {
        let _ = self.session.Close();
        let _ = self.pool.Close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// A visible top-level window of the displayed desktop whose title contains `needle`.
    fn titled(needle: &str) -> Option<isize> {
        use windows::Win32::Foundation::{LPARAM, TRUE};
        use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowTextW, IsWindowVisible};
        unsafe extern "system" fn cb(h: HWND, p: LPARAM) -> windows::core::BOOL {
            // SAFETY: `p` is the `Vec` below, alive for the whole enumeration.
            unsafe { (*(p.0 as *mut Vec<HWND>)).push(h) };
            TRUE
        }
        let mut all: Vec<HWND> = Vec::new();
        // SAFETY: enumeration into a local; window text read into a local buffer.
        unsafe {
            let _ = EnumWindows(Some(cb), LPARAM(&mut all as *mut _ as isize));
            all.into_iter().find(|h| {
                let mut buf = [0u16; 256];
                let n = GetWindowTextW(*h, &mut buf);
                IsWindowVisible(*h).as_bool() && String::from_utf16_lossy(&buf[..n.max(0) as usize]).contains(needle)
            }).map(|h| h.0 as isize)
        }
    }

    /// Does WGC deliver frames for a window on a desktop that is not the displayed one? (not
    /// run by default): `SEAGENT_REAL_TESTS=1 cargo test -p seagent-browser real_wgc -- --ignored --nocapture`.
    /// An animated page in Edge on the isolated Bot Desktop; distinct frames over 5 s.
    #[test]
    #[ignore]
    fn real_wgc_on_the_bot_desktop() {
        let Some(exe) = crate::tests_real::real_gate() else { return };
        let root = seagent_core::tmp::TempDir::new("seagent-wgc");
        let d = super::super::screen_windows::WinDesktop::new(root.path(), &format!("wgc{}", std::process::id()), "1280x800");
        d.start().expect("an interactive window station");
        let html = "<title>wgcprobe</title><body style='margin:0;font:40px monospace'><div id=c></div><script>let n=0;function f(){c.textContent='frame '+(++n)+' '+performance.now().toFixed(1);document.body.style.background='hsl('+(n%360)+',60%,70%)';requestAnimationFrame(f)}f()</script>";
        let url = format!("data:text/html,{}", seagent_net::urlencode(html));
        let line = format!("\"{}\" --user-data-dir=\"{}\" --inprivate --no-first-run --no-default-browser-check --window-position=0,0 --window-size=1200,800 --app=\"{url}\"", exe.display(), root.path().join("p").display());
        let pid = super::super::screen_windows::spawn_on_desktop(&d.qualified(), &line).unwrap();
        std::thread::sleep(Duration::from_secs(4));
        let hwnd = super::super::screen_windows::largest_window(&d.name()).expect("the browser window on the Bot Desktop");
        fn measure(hwnd: isize) -> Result<(u64, u32, f64), String> {
            let mut c = WgcWindow::start(hwnd)?;
            let (t0, mut distinct, mut last) = (Instant::now(), 0u32, 0u64);
            while t0.elapsed() < Duration::from_secs(5) {
                if let Some(s) = c.latest()? {
                    let h = s.bgra.iter().step_by(61).fold(0u64, |a, b| a.wrapping_mul(31).wrapping_add(u64::from(*b)));
                    if h != last {
                        distinct += 1;
                        last = h;
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok((c.frames, distinct, t0.elapsed().as_secs_f64()))
        }
        let say = |what: &str, r: Result<(u64, u32, f64), String>, hwnd: isize| match r {
            Ok((frames, distinct, s)) => eprintln!("WGC {what}: {frames} frames delivered, {distinct} distinct pictures in {s:.1} s = {:.1} fps", f64::from(distinct) / s),
            Err(e) => eprintln!("WGC {what}: {e} (item size there: {:?})", WgcWindow::item_size(hwnd)),
        };
        say("on a non-displayed Bot Desktop, from the service thread", measure(hwnd), hwnd);
        // The same from a fresh thread bound to the Bot Desktop (the capture item's owner desktop).
        let q = d.qualified();
        let bound = std::thread::spawn(move || super::super::screen_windows::on_desktop(&q, || measure(hwnd)).and_then(|r| r)).join().unwrap();
        say("on a non-displayed Bot Desktop, from a thread bound to it", bound, hwnd);
        let _ = std::process::Command::new("taskkill").args(["/T", "/F", "/PID", &pid.to_string()]).output();
        d.stop();
        // Control: the same page on the displayed desktop (proves the capture code itself works).
        if std::env::var_os("SEAGENT_WGC_CONTROL").is_some() {
            let shown = format!("\"{}\" --user-data-dir=\"{}\" --inprivate --no-first-run --no-default-browser-check --window-position=0,0 --window-size=1200,800 --app=\"{url}\"", exe.display(), root.path().join("q").display());
            let pid = super::super::screen_windows::spawn_on_desktop("WinSta0\\Default", &shown).unwrap();
            std::thread::sleep(Duration::from_secs(4));
            let found = (0..40).find_map(|_| titled("wgcprobe").or_else(|| {
                std::thread::sleep(Duration::from_millis(250));
                None
            }));
            match found {
                Some(h) => say("on the displayed desktop (control)", measure(h), h),
                None => eprintln!("WGC control: no window for pid {pid}"),
            }
            let _ = std::process::Command::new("taskkill").args(["/T", "/F", "/PID", &pid.to_string()]).output();
        }
    }
}
