//! DXGI Desktop Duplication of one display output: the live view's capture of the virtual
//! monitor the Bot Desktop is hosted on ([`super::vdd`]). The output delivers a frame each time
//! DWM composes it (up to its refresh rate, 60 Hz) together with the rectangles that changed, so
//! a stream sends only those. Needs a thread on the displayed desktop (the daemon's own).
#![cfg(windows)]

use super::screen_windows::{Shot, TrackUpdate};
use windows::core::Interface;
use windows::Win32::Foundation::{HMODULE, RECT};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D, D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING};
use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_MOVE_RECT};

fn e(what: &str) -> impl FnOnce(windows::core::Error) -> String + '_ {
    move |err| format!("DXGI duplication {what}: {err}")
}

/// A running duplication of one output.
pub struct Duplication {
    device: ID3D11Device,
    ctx: ID3D11DeviceContext,
    dup: IDXGIOutputDuplication,
    staging: Option<(ID3D11Texture2D, u32, u32)>,
    /// The whole output as of the last frame (BGRA), and its size.
    frame: Vec<u8>,
    size: (u32, u32),
    sent: bool,
    /// Frames DWM delivered so far (diagnostics, the fps measurement).
    pub frames: u64,
}

impl Duplication {
    /// Duplicate the output whose GDI name is `device` (`\\.\DISPLAYn`), on its own adapter.
    pub fn open(device: &str) -> Result<Duplication, String> {
        // SAFETY: COM calls on objects created here; out-pointers are locals.
        unsafe {
            let factory: IDXGIFactory1 = CreateDXGIFactory1().map_err(e("factory"))?;
            for a in 0.. {
                let Ok(adapter) = factory.EnumAdapters1(a) else { break };
                for o in 0.. {
                    let Ok(output) = adapter.EnumOutputs(o) else { break };
                    let desc = output.GetDesc().map_err(e("output"))?;
                    let name = String::from_utf16_lossy(&desc.DeviceName[..desc.DeviceName.iter().position(|&c| c == 0).unwrap_or(32)]);
                    if !name.eq_ignore_ascii_case(device) {
                        continue;
                    }
                    let (mut dev, mut ctx) = (None, None);
                    D3D11CreateDevice(&adapter, D3D_DRIVER_TYPE_UNKNOWN, HMODULE::default(), D3D11_CREATE_DEVICE_BGRA_SUPPORT, None, D3D11_SDK_VERSION, Some(&mut dev), None, Some(&mut ctx)).map_err(e("D3D11 device"))?;
                    let (device, ctx): (ID3D11Device, ID3D11DeviceContext) = (dev.ok_or("no D3D11 device")?, ctx.ok_or("no D3D11 context")?);
                    let out1: IDXGIOutput1 = output.cast().map_err(e("IDXGIOutput1"))?;
                    let dup = out1.DuplicateOutput(&device).map_err(e("DuplicateOutput"))?;
                    let r = desc.DesktopCoordinates;
                    let size = ((r.right - r.left).max(1) as u32, (r.bottom - r.top).max(1) as u32);
                    return Ok(Duplication { device, ctx, dup, staging: None, frame: vec![], size, sent: false, frames: 0 });
                }
            }
        }
        Err(format!("no DXGI output named {device}"))
    }

    /// What changed since the last call, waiting at most `wait_ms` for a new frame (the first
    /// call waits up to a second for the initial picture).
    pub fn next(&mut self, wait_ms: u32) -> Result<TrackUpdate, String> {
        let wait = if self.sent { wait_ms } else { wait_ms.max(1000) };
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut res: Option<IDXGIResource> = None;
        // SAFETY: duplication calls on this object; every acquired frame is released below.
        unsafe {
            match self.dup.AcquireNextFrame(wait, &mut info, &mut res) {
                Err(err) if err.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(TrackUpdate::Same),
                Err(err) => return Err(e("frame")(err)),
                Ok(()) => {}
            }
            let r = self.copy(&info, res);
            let _ = self.dup.ReleaseFrame();
            r
        }
    }

    /// SAFETY: called with an acquired frame (released by the caller).
    unsafe fn copy(&mut self, info: &DXGI_OUTDUPL_FRAME_INFO, res: Option<IDXGIResource>) -> Result<TrackUpdate, String> {
        // Only the pointer moved (no new picture): nothing to send once the first frame is out.
        if info.LastPresentTime == 0 && self.sent {
            return Ok(TrackUpdate::Same);
        }
        let tex: ID3D11Texture2D = res.ok_or("no desktop image")?.cast().map_err(e("texture"))?;
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
        let Some((st, w, h)) = self.staging.as_ref() else { return Err("no staging texture".into()) };
        let (w, h) = (*w, *h);
        // The changed areas, read before the copy (they describe this frame).
        let mut rects: Vec<RECT> = vec![];
        if info.TotalMetadataBufferSize > 0 && self.sent {
            let cap = info.TotalMetadataBufferSize as usize;
            let mut moves = vec![DXGI_OUTDUPL_MOVE_RECT::default(); cap / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>() + 1];
            let mut used = 0u32;
            if self.dup.GetFrameMoveRects((moves.len() * std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>()) as u32, moves.as_mut_ptr(), &mut used).is_ok() {
                rects.extend(moves[..used as usize / std::mem::size_of::<DXGI_OUTDUPL_MOVE_RECT>()].iter().map(|m| m.DestinationRect));
            }
            let mut dirty = vec![RECT::default(); cap / std::mem::size_of::<RECT>() + 1];
            let mut used = 0u32;
            if self.dup.GetFrameDirtyRects((dirty.len() * std::mem::size_of::<RECT>()) as u32, dirty.as_mut_ptr(), &mut used).is_ok() {
                rects.extend_from_slice(&dirty[..used as usize / std::mem::size_of::<RECT>()]);
            }
        }
        self.ctx.CopyResource(st, &tex);
        let mut m = D3D11_MAPPED_SUBRESOURCE::default();
        self.ctx.Map(st, 0, D3D11_MAP_READ, 0, Some(&mut m)).map_err(e("map"))?;
        let resized = self.size != (w, h) || self.frame.len() != (w * h * 4) as usize;
        self.frame.resize((w * h * 4) as usize, 0);
        let row = (w * 4) as usize;
        for y in 0..h as usize {
            let src = std::slice::from_raw_parts((m.pData as *const u8).add(y * m.RowPitch as usize), row);
            self.frame[y * row..(y + 1) * row].copy_from_slice(src);
        }
        self.ctx.Unmap(st, 0);
        self.size = (w, h);
        self.frames += 1;
        let full = !self.sent || resized || rects.is_empty() && info.LastPresentTime != 0 && info.TotalMetadataBufferSize == 0;
        self.sent = true;
        if full {
            return Ok(TrackUpdate::Full(Shot { width: w as i32, height: h as i32, bgra: self.frame.clone() }));
        }
        Ok(cut(&self.frame, w, h, &rects))
    }
}

/// The changed rectangles of `frame` (`w`×`h` BGRA) as patches; most of the screen → the whole.
pub fn cut(frame: &[u8], w: u32, h: u32, rects: &[RECT]) -> TrackUpdate {
    let clamp = |r: &RECT| (r.left.clamp(0, w as i32), r.top.clamp(0, h as i32), r.right.clamp(0, w as i32), r.bottom.clamp(0, h as i32));
    let parts: Vec<(i32, i32, i32, i32)> = rects.iter().map(clamp).filter(|(l, t, r, b)| r > l && b > t).collect();
    if parts.is_empty() {
        return TrackUpdate::Same;
    }
    let area: i64 = parts.iter().map(|(l, t, r, b)| i64::from(r - l) * i64::from(b - t)).sum();
    if area * 10 > i64::from(w) * i64::from(h) * 7 {
        return TrackUpdate::Full(Shot { width: w as i32, height: h as i32, bgra: frame.to_vec() });
    }
    let stride = (w * 4) as usize;
    TrackUpdate::Rects(
        parts
            .into_iter()
            .map(|(l, t, r, b)| {
                let mut bgra = Vec::with_capacity(((r - l) * (b - t) * 4) as usize);
                for y in t..b {
                    let a = y as usize * stride + l as usize * 4;
                    bgra.extend_from_slice(&frame[a..a + (r - l) as usize * 4]);
                }
                (l, t, Shot { width: r - l, height: b - t, bgra })
            })
            .collect(),
    )
}

impl Drop for Duplication {
    fn drop(&mut self) {
        // SAFETY: releasing a frame that may still be held is harmless (DXGI_ERROR_INVALID_CALL).
        unsafe {
            let _ = self.dup.ReleaseFrame();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn changed_rectangles_become_patches_cut_from_the_frame() {
        let (w, h) = (8u32, 4u32);
        let frame: Vec<u8> = (0..w * h * 4).map(|i| (i / 4) as u8).collect();
        let rect = |l, t, r, b| RECT { left: l, top: t, right: r, bottom: b };
        let TrackUpdate::Rects(p) = cut(&frame, w, h, &[rect(2, 1, 4, 3), rect(-5, -5, 0, 0)]) else { panic!("patches") };
        assert_eq!(p.len(), 1, "an empty (clamped-away) rectangle is dropped");
        let (x, y, s) = &p[0];
        assert_eq!((*x, *y, s.width, s.height), (2, 1, 2, 2));
        assert_eq!(s.bgra.iter().step_by(4).copied().collect::<Vec<_>>(), vec![10, 11, 18, 19], "pixel (2,1) is index 10");
        assert!(matches!(cut(&frame, w, h, &[rect(0, 0, 8, 4)]), TrackUpdate::Full(_)), "most of the screen: the whole picture");
        assert!(matches!(cut(&frame, w, h, &[]), TrackUpdate::Same));
    }

    /// Counterpart that needs no driver: the same duplication code on the primary output of the
    /// displayed desktop (not run by default: it reads the user's screen, in memory only):
    /// `SEAGENT_REAL_TESTS=1 cargo test -p seagent-browser real_dxgi_dup -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn real_dxgi_dup_of_the_primary_output() {
        if std::env::var_os("SEAGENT_REAL_TESTS").is_none() {
            eprintln!("real_dxgi_dup: set SEAGENT_REAL_TESTS=1 to run");
            return;
        }
        let primary = super::super::vdd::screens().into_iter().find(|s| s.attached && s.primary).expect("a primary display");
        let mut d = Duplication::open(&primary.name).expect("duplication of the primary output");
        match d.next(1000).unwrap() {
            TrackUpdate::Full(s) => assert_eq!((s.width, s.height), (primary.rect.w, primary.rect.h), "the first update is the whole output"),
            other => panic!("first update: {other:?}"),
        }
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(2) {
            d.next(50).unwrap();
        }
        eprintln!("real_dxgi_dup: {} frames from {} in 2 s (a static screen delivers few)", d.frames, primary.name);
    }
}
