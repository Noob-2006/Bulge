//! The Linux Bot Desktop for the live view, read incrementally over RFB (VNC) from its own
//! Xvnc: the launcher serves RFB on a 0600 Unix socket only (`SecurityTypes None` is safe there,
//! see control/launcher.sh), and Xvnc answers an incremental `FramebufferUpdateRequest` with
//! just the rectangles that changed — no full-screen grab per frame, no `import`.
//!
//! Speaks RFB 3.8: security None, 32-bit RGBX pixels, Raw + CopyRect + DesktopSize encodings.
//! [`Rfb`] keeps the framebuffer and is a [`RegionSource`]: the first update is the whole
//! screen, later ones the changed rectangles (pixels cut from the framebuffer, so CopyRect
//! moves are sent as what they look like now).

use crate::live_regions::{RegionSource, Update};
use image::RgbaImage;
use std::io::{Read, Write};
use std::time::Duration;

/// Sets the read timeout of the underlying stream (a Unix socket, or a test double).
pub type SetTimeout<S> = Box<dyn Fn(&S, Option<Duration>) + Send>;
/// (x, y, w, h) on the screen.
type Rect = (u32, u32, u32, u32);

/// Above this many rectangles in one update, their bounding box is sent instead.
const MAX_RECTS: usize = 16;

pub struct Rfb<S: Read + Write> {
    s: S,
    fb: RgbaImage,
    outstanding: bool,
    first: bool,
    set_timeout: SetTimeout<S>,
}

fn rd<S: Read>(s: &mut S, n: usize) -> Result<Vec<u8>, String> {
    let mut b = vec![0u8; n];
    s.read_exact(&mut b).map_err(|e| format!("RFB read: {e}"))?;
    Ok(b)
}

fn u16_at(b: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([b[i], b[i + 1]])
}

fn u32_at(b: &[u8], i: usize) -> u32 {
    u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
}

impl Rfb<std::os::unix::net::UnixStream> {
    /// Connect to the Bot Desktop's RFB socket.
    pub fn connect(path: &std::path::Path) -> Result<Self, String> {
        let s = std::os::unix::net::UnixStream::connect(path).map_err(|e| format!("RFB {}: {e}", path.display()))?;
        Rfb::handshake(s, Box::new(|s: &std::os::unix::net::UnixStream, t| {
            let _ = s.set_read_timeout(t);
        }))
    }
}

impl<S: Read + Write + Send> Rfb<S> {
    /// Version, security None, ClientInit (shared), ServerInit, pixel format, encodings.
    pub fn handshake(mut s: S, set_timeout: SetTimeout<S>) -> Result<Self, String> {
        set_timeout(&s, Some(Duration::from_secs(5)));
        let v = rd(&mut s, 12)?;
        if !v.starts_with(b"RFB 003.") {
            return Err("not an RFB server".into());
        }
        s.write_all(b"RFB 003.008\n").map_err(|e| e.to_string())?;
        let n = rd(&mut s, 1)?[0] as usize;
        if n == 0 {
            let len = u32_at(&rd(&mut s, 4)?, 0) as usize;
            return Err(format!("RFB refused: {}", String::from_utf8_lossy(&rd(&mut s, len.min(4096))?)));
        }
        if !rd(&mut s, n)?.contains(&1) {
            return Err("the RFB server wants authentication (the Bot Desktop socket offers None)".into());
        }
        s.write_all(&[1]).map_err(|e| e.to_string())?;
        if u32_at(&rd(&mut s, 4)?, 0) != 0 {
            return Err("RFB security handshake failed".into());
        }
        s.write_all(&[1]).map_err(|e| e.to_string())?; // ClientInit: shared
        let init = rd(&mut s, 24)?;
        let (w, h) = (u16_at(&init, 0), u16_at(&init, 2));
        let name_len = u32_at(&init, 20) as usize;
        let _ = rd(&mut s, name_len.min(1 << 16))?;
        // SetPixelFormat: 32 bpp, depth 24, little endian, true colour, R/G/B at bytes 0/1/2.
        s.write_all(&[0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 0, 8, 16, 0, 0, 0]).map_err(|e| e.to_string())?;
        // SetEncodings: Raw, CopyRect, DesktopSize.
        let mut enc = vec![2, 0, 0, 3];
        for e in [0i32, 1, -223] {
            enc.extend_from_slice(&e.to_be_bytes());
        }
        s.write_all(&enc).map_err(|e| e.to_string())?;
        Ok(Rfb { s, fb: RgbaImage::new(u32::from(w), u32::from(h)), outstanding: false, first: true, set_timeout })
    }

    fn request(&mut self) -> Result<(), String> {
        let (w, h) = (self.fb.width() as u16, self.fb.height() as u16);
        let mut m = vec![3, u8::from(!self.first), 0, 0, 0, 0];
        m.extend_from_slice(&w.to_be_bytes());
        m.extend_from_slice(&h.to_be_bytes());
        self.s.write_all(&m).map_err(|e| format!("RFB write: {e}"))?;
        self.outstanding = true;
        Ok(())
    }

    /// Read one FramebufferUpdate body (after its type byte): the changed rectangles.
    fn update(&mut self) -> Result<(Vec<Rect>, bool), String> {
        let hdr = rd(&mut self.s, 3)?;
        let n = u16_at(&hdr, 1) as usize;
        let (mut rects, mut resized) = (Vec::with_capacity(n), false);
        for _ in 0..n {
            let r = rd(&mut self.s, 12)?;
            let (x, y, w, h) = (u32::from(u16_at(&r, 0)), u32::from(u16_at(&r, 2)), u32::from(u16_at(&r, 4)), u32::from(u16_at(&r, 6)));
            match i32::from_be_bytes([r[8], r[9], r[10], r[11]]) {
                0 => {
                    let px = rd(&mut self.s, (w * h * 4) as usize)?;
                    for yy in 0..h {
                        for xx in 0..w {
                            let i = ((yy * w + xx) * 4) as usize;
                            if x + xx < self.fb.width() && y + yy < self.fb.height() {
                                self.fb.put_pixel(x + xx, y + yy, image::Rgba([px[i], px[i + 1], px[i + 2], 255]));
                            }
                        }
                    }
                    rects.push((x, y, w, h));
                }
                1 => {
                    let src = rd(&mut self.s, 4)?;
                    let (sx, sy) = (u32::from(u16_at(&src, 0)), u32::from(u16_at(&src, 2)));
                    let part = image::imageops::crop_imm(&self.fb, sx, sy, w, h).to_image();
                    image::imageops::replace(&mut self.fb, &part, i64::from(x), i64::from(y));
                    rects.push((x, y, w, h));
                }
                -223 => {
                    self.fb = RgbaImage::new(w, h);
                    resized = true;
                }
                e => return Err(format!("RFB: unexpected encoding {e}")),
            }
        }
        Ok((rects, resized))
    }
}

impl<S: Read + Write + Send> RegionSource for Rfb<S> {
    fn next(&mut self) -> Result<Update, String> {
        if !self.outstanding {
            self.request()?;
        }
        // Xvnc answers an incremental request only when something changed: wait briefly.
        (self.set_timeout)(&self.s, Some(Duration::from_millis(30)));
        let mut t = [0u8; 1];
        match self.s.read(&mut t) {
            Ok(0) => return Err("the Bot Desktop's RFB server closed the connection".into()),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return Ok(Update::Same),
            Err(e) => return Err(format!("RFB read: {e}")),
        }
        (self.set_timeout)(&self.s, Some(Duration::from_secs(5)));
        match t[0] {
            0 => {
                self.outstanding = false;
                let (mut rects, resized) = self.update()?;
                if self.first || resized {
                    self.first = false;
                    return Ok(Update::Full(self.fb.clone().into()));
                }
                if rects.is_empty() {
                    return Ok(Update::Same);
                }
                if rects.len() > MAX_RECTS {
                    let (x0, y0) = (rects.iter().map(|r| r.0).min().unwrap_or(0), rects.iter().map(|r| r.1).min().unwrap_or(0));
                    let (x1, y1) = (rects.iter().map(|r| r.0 + r.2).max().unwrap_or(0), rects.iter().map(|r| r.1 + r.3).max().unwrap_or(0));
                    rects = vec![(x0, y0, x1 - x0, y1 - y0)];
                }
                Ok(Update::Rects(rects.into_iter().filter(|r| r.2 > 0 && r.3 > 0).map(|(x, y, w, h)| (x, y, image::imageops::crop_imm(&self.fb, x, y, w, h).to_image().into())).collect()))
            }
            1 => {
                let h = rd(&mut self.s, 5)?;
                let _ = rd(&mut self.s, u16_at(&h, 3) as usize * 6)?;
                Ok(Update::Same)
            }
            2 => Ok(Update::Same),
            3 => {
                let h = rd(&mut self.s, 7)?;
                let _ = rd(&mut self.s, (u32_at(&h, 3) as usize).min(1 << 20))?;
                Ok(Update::Same)
            }
            m => Err(format!("RFB: unexpected server message {m}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn raw(x: u16, y: u16, w: u16, h: u16, rgb: [u8; 3]) -> Vec<u8> {
        let mut m = vec![];
        for v in [x, y, w, h] {
            m.extend_from_slice(&v.to_be_bytes());
        }
        m.extend_from_slice(&0i32.to_be_bytes());
        for _ in 0..u32::from(w) * u32::from(h) {
            m.extend_from_slice(&[rgb[0], rgb[1], rgb[2], 0]);
        }
        m
    }

    /// Throughput of the Linux path on our side of the socket (not run by default):
    /// `cargo test --release -p seagent-app rfb_busy_window_throughput -- --ignored --nocapture`.
    /// A fake Xvnc answers every incremental request on a 1920×1080 screen with a fresh
    /// 1600×980 Raw rectangle (a scrolling editor), through the real RFB client, the region
    /// pipeline's parallel encoders and in-order sending; only Xvnc's own work is missing.
    #[test]
    #[ignore]
    fn rfb_busy_window_throughput() {
        use crate::live_regions::{stream, Sink};
        let (client, mut srv) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            srv.write_all(b"RFB 003.008\n").unwrap();
            let _ = rd(&mut srv, 12);
            srv.write_all(&[1, 1]).unwrap();
            let _ = rd(&mut srv, 1);
            srv.write_all(&0u32.to_be_bytes()).unwrap();
            let _ = rd(&mut srv, 1);
            let mut init = vec![7, 128, 4, 56];
            init.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 0, 8, 16, 0, 0, 0]);
            init.extend_from_slice(&0u32.to_be_bytes());
            srv.write_all(&init).unwrap();
            let _ = rd(&mut srv, 20);
            let _ = rd(&mut srv, 16);
            // A text-like pattern that moves one line per update (a scrolling editor).
            let mut n = 0u32;
            while let Ok(req) = rd(&mut srv, 10) {
                let (x, y, w, h) = if req[1] == 0 { (0u16, 0u16, 1920u16, 1080u16) } else { (40, 30, 1600, 980) };
                let mut m = vec![0, 0, 0, 1];
                for v in [x, y, w, h] {
                    m.extend_from_slice(&v.to_be_bytes());
                }
                m.extend_from_slice(&0i32.to_be_bytes());
                m.reserve(usize::from(w) * usize::from(h) * 4);
                for yy in 0..u32::from(h) {
                    let row = (yy + n) % 18;
                    for xx in 0..u32::from(w) {
                        let ink = row < 12 && !(xx / 7 + (yy + n) / 18).is_multiple_of(5) && (xx % 7) < 5;
                        let v = if ink { 30 } else { 250 };
                        m.extend_from_slice(&[v, v, v, 0]);
                    }
                }
                n += 1;
                if srv.write_all(&m).is_err() {
                    break;
                }
            }
        });
        let mut r = Rfb::handshake(client, Box::new(|s: &UnixStream, t| {
            let _ = s.set_read_timeout(t);
        }))
        .unwrap();
        struct Count(u32, u64, std::time::Instant);
        impl Sink for Count {
            fn poll(&mut self) -> Result<Option<(u8, u32)>, Option<String>> {
                if self.2.elapsed() > Duration::from_secs(6) {
                    return Err(None);
                }
                Ok(None)
            }
            fn send(&mut self, m: &serde_json::Value, j: &[u8]) -> Result<(), Option<String>> {
                if m["t"] == "patch" {
                    self.0 += 1;
                }
                self.1 += j.len() as u64;
                Ok(())
            }
            fn text(&mut self, _v: &serde_json::Value) -> Result<(), Option<String>> {
                Ok(())
            }
        }
        let mut c = Count(0, 0, std::time::Instant::now());
        let _ = stream(&mut c, "host", &mut r, 85, 30);
        let fps = f64::from(c.0) / 6.0;
        eprintln!("LIVE RFB path (fake Xvnc, 1600x980 changed per update at 1080p, choice 30): {fps:.1} updates/s, {:.2} MB/s, {} encoders", c.1 as f64 / 6e6, crate::live_regions::encoders());
        assert!(fps >= 30.0, "{fps:.1}");
    }

    /// A fake Xvnc: handshake, then a full frame, a raw rectangle, a CopyRect, and silence.
    #[test]
    fn reads_the_framebuffer_incrementally() {
        let (client, mut srv) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            srv.write_all(b"RFB 003.008\n").unwrap();
            assert_eq!(rd(&mut srv, 12).unwrap(), b"RFB 003.008\n");
            srv.write_all(&[1, 1]).unwrap();
            assert_eq!(rd(&mut srv, 1).unwrap(), [1]);
            srv.write_all(&0u32.to_be_bytes()).unwrap();
            assert_eq!(rd(&mut srv, 1).unwrap(), [1], "shared");
            let mut init = vec![0, 64, 0, 48];
            init.extend_from_slice(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0]);
            init.extend_from_slice(&4u32.to_be_bytes());
            init.extend_from_slice(b"fake");
            srv.write_all(&init).unwrap();
            let pf = rd(&mut srv, 20).unwrap();
            assert_eq!((pf[0], pf[4], pf[14], pf[15], pf[16]), (0, 32, 0, 8, 16), "RGBX little endian");
            let enc = rd(&mut srv, 16).unwrap();
            assert_eq!((enc[0], u16_at(&enc, 2)), (2, 3));
            // 1: non-incremental → the whole screen.
            let req = rd(&mut srv, 10).unwrap();
            assert_eq!((req[0], req[1], u16_at(&req, 6), u16_at(&req, 8)), (3, 0, 64, 48));
            let mut up = vec![0, 0, 0, 1];
            up.extend(raw(0, 0, 64, 48, [10, 20, 30]));
            srv.write_all(&up).unwrap();
            // 2: incremental → one changed rectangle.
            assert_eq!(rd(&mut srv, 10).unwrap()[1], 1, "incremental");
            let mut up = vec![0, 0, 0, 1];
            up.extend(raw(8, 8, 16, 16, [200, 0, 0]));
            srv.write_all(&up).unwrap();
            // 3: a CopyRect of that rectangle to (32, 24), plus a Bell first.
            let _ = rd(&mut srv, 10).unwrap();
            srv.write_all(&[2]).unwrap();
            let mut up = vec![0, 0, 0, 1];
            for v in [32u16, 24, 16, 16] {
                up.extend_from_slice(&v.to_be_bytes());
            }
            up.extend_from_slice(&1i32.to_be_bytes());
            up.extend_from_slice(&8u16.to_be_bytes());
            up.extend_from_slice(&8u16.to_be_bytes());
            srv.write_all(&up).unwrap();
            // 4: nothing changes → no answer.
            let _ = rd(&mut srv, 10).unwrap();
            std::thread::sleep(Duration::from_millis(300));
        });
        let mut r = Rfb::handshake(client, Box::new(|s: &UnixStream, t| {
            let _ = s.set_read_timeout(t);
        }))
        .unwrap();
        let first = loop {
            match r.next().unwrap() {
                Update::Same => continue,
                u => break u,
            }
        };
        let Update::Full(img) = first else { panic!("first: the whole screen") };
        assert_eq!((img.w, img.h, &img.data[(5 * 64 + 5) * 4..(5 * 64 + 5) * 4 + 4]), (64, 48, &[10u8, 20, 30, 255][..]));
        let Update::Rects(rs) = (loop {
            match r.next().unwrap() {
                Update::Same => continue,
                u => break u,
            }
        }) else {
            panic!("a rectangle")
        };
        assert_eq!(rs.iter().map(|(x, y, i)| (*x, *y, (i.w, i.h))).collect::<Vec<_>>(), [(8, 8, (16, 16))]);
        assert_eq!(&rs[0].2.data[..4], &[200, 0, 0, 255]);
        let moved = loop {
            match r.next().unwrap() {
                Update::Rects(rs) => break rs,
                _ => continue,
            }
        };
        assert_eq!((moved[0].0, moved[0].1, &moved[0].2.data[(3 * 16 + 3) * 4..(3 * 16 + 3) * 4 + 4]), (32, 24, &[200u8, 0, 0, 255][..]), "CopyRect copies the framebuffer");
        assert!(matches!(r.next().unwrap(), Update::Same), "a still screen: nothing");
        server.join().unwrap();
    }
}
