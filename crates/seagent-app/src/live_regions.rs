//! Region streams for the live view's full-frame desktops (no agent browser to forward): a
//! [`RegionSource`] says what changed on the screen — a whole picture, a few rectangles, or
//! nothing — and [`stream`] turns that into the same `frame` (base) + `patch` messages patch
//! mode sends, so the console composes them on its canvas.
//!
//! Only what changed is encoded, and encoding runs on a small pool of threads (frames N, N+1,
//! N+2 in parallel) while one thread keeps capturing; the link thread sends the results strictly
//! in order. Sources: the Windows window tracker (`screen_windows::LiveCapture::track`), an
//! incremental RFB client on the Linux Xvnc ([`crate::live_rfb`]), and [`Snapshots`] — any
//! whole-screen grab (macOS, desktop VMs, fallbacks) diffed tile by tile.

use image::RgbaImage;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Raw pixels as a source has them: RGBA (RFB, image grabs) or BGRA (Windows GDI). The
/// encoder threads convert them, so the capture thread does no per-pixel work.
pub struct Frame {
    pub w: u32,
    pub h: u32,
    pub data: Vec<u8>,
    pub bgra: bool,
}

impl From<RgbaImage> for Frame {
    fn from(i: RgbaImage) -> Frame {
        let (w, h) = i.dimensions();
        Frame { w, h, data: i.into_raw(), bgra: false }
    }
}

/// What changed on the screen since the last call.
pub enum Update {
    /// A whole new picture (first call, a resize, a new window layout).
    Full(Frame),
    /// These rectangles (x, y, pixels) of the screen changed.
    Rects(Vec<(u32, u32, Frame)>),
    Same,
}

/// A screen that can say what changed.
pub trait RegionSource: Send {
    fn next(&mut self) -> Result<Update, String>;
}

/// The longest edge of a tile in [`diff_rects`].
const TILE: u32 = 64;

/// The rectangles where `cur` differs from `prev` (same size): changed 64-px tiles, merged
/// into horizontal bands per tile row (a few large rectangles, not hundreds of small ones).
pub fn diff_rects(prev: &RgbaImage, cur: &RgbaImage) -> Vec<(u32, u32, u32, u32)> {
    let (w, h) = cur.dimensions();
    if prev.dimensions() != (w, h) {
        return vec![(0, 0, w, h)];
    }
    let (p, c) = (prev.as_raw(), cur.as_raw());
    let stride = w as usize * 4;
    let mut out: Vec<(u32, u32, u32, u32)> = vec![];
    for ty in (0..h).step_by(TILE as usize) {
        let th = TILE.min(h - ty);
        let mut run: Option<(u32, u32)> = None;
        for tx in (0..w).step_by(TILE as usize) {
            let tw = TILE.min(w - tx);
            let changed = (ty..ty + th).any(|y| {
                let a = y as usize * stride + tx as usize * 4;
                p[a..a + tw as usize * 4] != c[a..a + tw as usize * 4]
            });
            match (changed, run) {
                (true, None) => run = Some((tx, tx + tw)),
                (true, Some((x0, _))) => run = Some((x0, tx + tw)),
                (false, Some((x0, x1))) => {
                    out.push((x0, ty, x1 - x0, th));
                    run = None;
                }
                (false, None) => {}
            }
        }
        if let Some((x0, x1)) = run {
            out.push((x0, ty, x1 - x0, th));
        }
    }
    // Neighbouring rows of the same span become one rectangle.
    let mut merged: Vec<(u32, u32, u32, u32)> = vec![];
    for r in out {
        match merged.iter_mut().rev().find(|m| m.0 == r.0 && m.2 == r.2 && m.1 + m.3 == r.1) {
            Some(m) => m.3 += r.3,
            None => merged.push(r),
        }
    }
    merged
}

/// A whole-screen grab as a region source: each picture is compared with the last one and
/// only the changed tiles go out (a full picture when most of the screen changed).
pub struct Snapshots<F: FnMut() -> Result<image::DynamicImage, String> + Send> {
    grab: F,
    last: Option<RgbaImage>,
}

impl<F: FnMut() -> Result<image::DynamicImage, String> + Send> Snapshots<F> {
    pub fn new(grab: F) -> Self {
        Snapshots { grab, last: None }
    }
}

impl<F: FnMut() -> Result<image::DynamicImage, String> + Send> RegionSource for Snapshots<F> {
    fn next(&mut self) -> Result<Update, String> {
        let cur = (self.grab)()?.to_rgba8();
        let up = match &self.last {
            None => Update::Full(cur.clone().into()),
            Some(prev) => {
                let rects = diff_rects(prev, &cur);
                let area: u64 = rects.iter().map(|r| u64::from(r.2) * u64::from(r.3)).sum();
                if rects.is_empty() {
                    Update::Same
                } else if area * 10 > u64::from(cur.width()) * u64::from(cur.height()) * 7 || prev.dimensions() != cur.dimensions() {
                    Update::Full(cur.clone().into())
                } else {
                    Update::Rects(rects.into_iter().map(|(x, y, w, h)| (x, y, image::imageops::crop_imm(&cur, x, y, w, h).to_image().into())).collect())
                }
            }
        };
        self.last = Some(cur);
        Ok(up)
    }
}

/// One encoded update, ready to send: (header, JPEG) pairs.
type Encoded = Vec<(Value, Vec<u8>)>;

/// JPEG of a frame: straight from its RGBA / BGRA bytes to RGB in one pass, then encoded.
fn jpeg(f: &Frame, quality: u8) -> Result<Vec<u8>, String> {
    let mut rgb = Vec::with_capacity(f.data.len() / 4 * 3);
    for p in f.data.as_chunks::<4>().0 {
        if f.bgra {
            rgb.extend_from_slice(&[p[2], p[1], p[0]]);
        } else {
            rgb.extend_from_slice(&p[..3]);
        }
    }
    let mut out = Vec::with_capacity(rgb.len() / 8);
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality).encode(&rgb, f.w, f.h, image::ExtendedColorType::Rgb8).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Encode one update (`upd` numbers it; every message of it carries the number).
fn encode(upd: u64, up: Update, captured_ms: u64, quality: u8) -> Result<Encoded, String> {
    match up {
        Update::Full(img) => {
            let j = jpeg(&img, quality)?;
            let (w, h) = (img.w, img.h);
            Ok(vec![(json!({"t": "frame", "mode": "patch", "upd": upd, "mime": "image/jpeg", "bytes": j.len(), "width": w, "height": h, "frameWidth": w, "frameHeight": h, "quality": quality, "capturedMs": captured_ms}), j)])
        }
        Update::Rects(rs) => rs
            .into_iter()
            .map(|(x, y, img)| {
                let j = jpeg(&img, quality)?;
                Ok((json!({"t": "patch", "upd": upd, "mime": "image/jpeg", "bytes": j.len(), "x": x, "y": y, "w": img.w, "h": img.h, "capturedMs": captured_ms}), j))
            })
            .collect(),
        Update::Same => Ok(vec![]),
    }
}

/// How many encoder threads: enough for 30–60 fps of 1080p patches, never most of the machine.
pub fn encoders() -> usize {
    std::thread::available_parallelism().map_or(2, |n| (n.get() / 2).clamp(2, 4))
}

/// What the stream needs from its link (the WebSocket in `live_view`).
pub trait Sink {
    /// Viewer messages; `Err` ends the stream. Returns a new (quality, fps) choice, if any.
    fn poll(&mut self) -> Result<Option<(u8, u32)>, Option<String>>;
    fn send(&mut self, meta: &Value, jpeg: &[u8]) -> Result<(), Option<String>>;
    fn text(&mut self, v: &Value) -> Result<(), Option<String>>;
}

/// Run a region stream until the viewer leaves: capture thread → encoder pool → in-order send.
pub fn stream(sink: &mut dyn Sink, id: &str, src: &mut dyn RegionSource, quality: u8, fps: u32) -> Result<(), Option<String>> {
    let stop = AtomicBool::new(false);
    let q = AtomicU8::new(quality);
    let gap_us = std::sync::atomic::AtomicU64::new(seagent_browser::live::frame_gap(fps).as_micros() as u64);
    let n = encoders();
    let (job_tx, job_rx) = sync_channel::<(u64, Result<Update, String>, u64)>(n);
    let job_rx = Mutex::new(job_rx);
    let (res_tx, res_rx) = sync_channel::<(u64, Result<Encoded, String>)>(n * 2);
    std::thread::scope(|sc| {
        let (stop_r, gap_r) = (&stop, &gap_us);
        // Capture: at most one update per frame interval, backing off to 250 ms while still.
        sc.spawn(move || {
            let (mut upd, mut idle) = (0u64, Duration::ZERO);
            while !stop_r.load(Ordering::SeqCst) {
                let t0 = Instant::now();
                let r = src.next();
                let gap = Duration::from_micros(gap_r.load(Ordering::SeqCst));
                let rest = match &r {
                    Ok(Update::Same) => {
                        idle = (idle * 3 / 2).max(gap).min(Duration::from_millis(250));
                        idle
                    }
                    _ => {
                        idle = Duration::ZERO;
                        upd += 1;
                        if job_tx.send((upd, r, crate::live_view::now_ms())).is_err() {
                            break;
                        }
                        gap
                    }
                };
                let until = t0 + rest;
                while Instant::now() < until && !stop_r.load(Ordering::SeqCst) {
                    std::thread::sleep(until.saturating_duration_since(Instant::now()).min(Duration::from_millis(5)));
                }
            }
        });
        for _ in 0..n {
            let (job_rx, res_tx, q) = (&job_rx, res_tx.clone(), &q);
            sc.spawn(move || loop {
                let job = job_rx.lock().unwrap().recv();
                let Ok((upd, r, at)) = job else { break };
                let enc = r.and_then(|up| encode(upd, up, at, q.load(Ordering::SeqCst)));
                if res_tx.send((upd, enc)).is_err() {
                    break;
                }
            });
        }
        drop(res_tx);
        let r = consume(sink, id, &res_rx, &q, &gap_us);
        stop.store(true, Ordering::SeqCst);
        drop(res_rx);
        r
    })
}

fn consume(sink: &mut dyn Sink, id: &str, rx: &Receiver<(u64, Result<Encoded, String>)>, q: &AtomicU8, gap_us: &std::sync::atomic::AtomicU64) -> Result<(), Option<String>> {
    let mut pending: std::collections::BTreeMap<u64, Result<Encoded, String>> = Default::default();
    let (mut next, mut dark) = (1u64, false);
    let mut stats = (Instant::now(), 0u32, 0u64);
    loop {
        if let Some((nq, nf)) = sink.poll()? {
            q.store(nq, Ordering::SeqCst);
            gap_us.store(seagent_browser::live::frame_gap(nf).as_micros() as u64, Ordering::SeqCst);
        }
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok((upd, enc)) => {
                pending.insert(upd, enc);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Err(Some("the desktop capture stopped".into())),
        }
        while let Some(enc) = pending.remove(&next) {
            next += 1;
            match enc {
                Ok(msgs) => {
                    dark = false;
                    stats.1 += 1;
                    for (mut meta, j) in msgs {
                        stats.2 += j.len() as u64;
                        meta["sentMs"] = crate::live_view::now_ms().into();
                        sink.send(&meta, &j)?;
                    }
                }
                Err(e) => {
                    if !dark {
                        dark = true;
                        sink.text(&json!({"t": "nodisplay", "target": id, "reason": e, "fallback": "terminal"}))?;
                    }
                }
            }
        }
        let dt = stats.0.elapsed().as_secs_f64();
        if dt >= 2.0 {
            sink.text(&json!({"t": "stats", "mode": "regions", "fps": (f64::from(stats.1) / dt * 10.0).round() / 10.0, "kbps": (stats.2 as f64 * 8.0 / 1000.0 / dt).round(), "bytesPerSec": (stats.2 as f64 / dt).round(), "encoders": encoders()}))?;
            stats = (Instant::now(), 0, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn img(w: u32, h: u32, v: u8) -> RgbaImage {
        RgbaImage::from_pixel(w, h, image::Rgba([v, v, v, 255]))
    }

    #[test]
    fn diff_finds_changed_tiles_and_merges_them() {
        let a = img(640, 480, 10);
        let mut b = a.clone();
        assert!(diff_rects(&a, &b).is_empty());
        // A 100×150 change at (130, 70): tiles x 128..256, y 64..256 → one merged rectangle.
        for y in 70..220 {
            for x in 130..230 {
                b.put_pixel(x, y, image::Rgba([200, 0, 0, 255]));
            }
        }
        assert_eq!(diff_rects(&a, &b), [(128, 64, 128, 192)]);
        // Two separate areas stay two rectangles; a resize is everything.
        b.put_pixel(600, 470, image::Rgba([0, 0, 0, 255]));
        assert_eq!(diff_rects(&a, &b).len(), 2);
        assert_eq!(diff_rects(&a, &img(320, 240, 10)), [(0, 0, 320, 240)]);
    }

    #[test]
    fn snapshots_send_full_then_rects_then_nothing() {
        let frames = std::sync::Arc::new(Mutex::new(vec![img(256, 256, 1), img(256, 256, 1), {
            let mut x = img(256, 256, 1);
            x.put_pixel(10, 10, image::Rgba([9, 9, 9, 255]));
            x
        }, img(256, 256, 200)]));
        let f2 = frames.clone();
        let mut s = Snapshots::new(move || Ok(image::DynamicImage::ImageRgba8(f2.lock().unwrap().remove(0))));
        assert!(matches!(s.next().unwrap(), Update::Full(_)), "first: the whole picture");
        assert!(matches!(s.next().unwrap(), Update::Same));
        match s.next().unwrap() {
            Update::Rects(r) => assert_eq!(r.iter().map(|(x, y, i)| (*x, *y, i.w, i.h)).collect::<Vec<_>>(), [(0, 0, 64, 64)]),
            _ => panic!("a small change is a patch"),
        }
        assert!(matches!(s.next().unwrap(), Update::Full(_)), "most of the screen changed: a full picture");
    }

    /// Nothing caps a desktop stream below the viewer's choice by design (macOS screencapture,
    /// VMs and the RFB / window-tracker paths share this pipeline): a source that changes on
    /// every call and costs nothing gets ≥ 30 updates a second at 30 fps, and ≥ 55 at 60.
    #[test]
    fn the_pipeline_is_not_capped_below_the_choice() {
        struct Busy(u8);
        impl RegionSource for Busy {
            fn next(&mut self) -> Result<Update, String> {
                self.0 = self.0.wrapping_add(1);
                Ok(if self.0 == 1 { Update::Full(img(320, 200, 0).into()) } else { Update::Rects(vec![(0, 0, img(64, 64, self.0).into())]) })
            }
        }
        struct Count(u32, Instant, Duration);
        impl Sink for Count {
            fn poll(&mut self) -> Result<Option<(u8, u32)>, Option<String>> {
                if self.1.elapsed() > self.2 {
                    return Err(None);
                }
                Ok(None)
            }
            fn send(&mut self, _m: &Value, _j: &[u8]) -> Result<(), Option<String>> {
                self.0 += 1;
                Ok(())
            }
            fn text(&mut self, _v: &Value) -> Result<(), Option<String>> {
                Ok(())
            }
        }
        for (fps, floor) in [(30u32, 30.0), (60, 55.0)] {
            let secs = Duration::from_secs(2);
            let mut sink = Count(0, Instant::now(), secs);
            let _ = stream(&mut sink, "host", &mut Busy(0), 80, fps);
            let rate = f64::from(sink.0) / secs.as_secs_f64();
            assert!(rate >= floor, "{fps} fps chosen: {rate:.1} updates/s");
            assert!(rate <= f64::from(fps) * 1.25, "and paced, not flat out: {rate:.1}");
        }
    }

    /// The pipeline: updates are encoded in parallel but sent in order, each tagged with its
    /// update number; a still screen sends nothing.
    #[test]
    fn stream_encodes_in_parallel_and_sends_in_order() {
        struct Src(u32);
        impl RegionSource for Src {
            fn next(&mut self) -> Result<Update, String> {
                self.0 += 1;
                Ok(match self.0 {
                    1 => Update::Full(img(800, 600, 50).into()),
                    2..=40 if self.0.is_multiple_of(2) => Update::Rects(vec![(64, 64, img(300, 200, self.0 as u8).into()), (500, 400, img(64, 64, 7).into())]),
                    _ => Update::Same,
                })
            }
        }
        struct Rec(Vec<Value>, Instant);
        impl Sink for Rec {
            fn poll(&mut self) -> Result<Option<(u8, u32)>, Option<String>> {
                if self.1.elapsed() > Duration::from_secs(3) {
                    return Err(None);
                }
                Ok(None)
            }
            fn send(&mut self, meta: &Value, jpeg: &[u8]) -> Result<(), Option<String>> {
                assert_eq!(&jpeg[..2], &[0xff, 0xd8]);
                self.0.push(meta.clone());
                Ok(())
            }
            fn text(&mut self, _v: &Value) -> Result<(), Option<String>> {
                Ok(())
            }
        }
        let mut sink = Rec(vec![], Instant::now());
        let r = stream(&mut sink, "host", &mut Src(0), 80, 60);
        assert_eq!(r, Err(None));
        let upds: Vec<u64> = sink.0.iter().map(|m| m["upd"].as_u64().unwrap()).collect();
        assert!(upds.windows(2).all(|w| w[0] <= w[1]), "in order: {upds:?}");
        assert_eq!(sink.0[0]["t"], "frame");
        assert_eq!(sink.0[0]["mode"], "patch");
        assert_eq!(sink.0.iter().filter(|m| m["t"] == "patch").count(), 40, "20 updates × 2 rectangles");
        assert_eq!((sink.0[1]["x"].as_u64(), sink.0[1]["w"].as_u64()), (Some(64), Some(300)));
    }
}
