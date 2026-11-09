//! Live stream of a browser tab for the web console: CDP `Page.startScreencast` JPEG frames,
//! fanned out to every viewer of that tab and **ack-paced** — Chrome sends the next frame only
//! after `Page.screencastFrameAck`, and the ack is sent only once a viewer has taken the
//! current frame and the fps cap allows it. A slow viewer therefore slows Chrome down instead
//! of growing a queue (each viewer only ever holds the newest frame), and a page that does not
//! repaint sends nothing at all.
//!
//! Nothing runs while nobody watches: the screencast starts with the first [`Viewer`] of a
//! page session and stops when the last one is dropped. The browser's idle clock is never
//! touched (watching does not keep an idle browser alive). A recording (`browser record`)
//! and the viewers share one screencast whichever started first: neither restarts or stops it
//! under the other; while a recording runs it acks every frame itself (its own pace) and each
//! viewer takes the newest frame at its fps cap.
//!
//! The engine's event supervisor hands frames to [`Cast::offer`] (`engine::handle_event`).

use crate::engine::{Browser, BLOCKED_BY_DIALOG};
use serde_json::{json, Value};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Chrome keeps up to two screencast frames in flight; more than this unacked means something
/// is off, and the oldest is acked at once rather than stalling the page.
pub const MAX_IN_FLIGHT: usize = 4;

/// Stream limits a viewer asks for (clamped by [`Opts::clamped`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Opts {
    pub max_width: u32,
    pub max_height: u32,
    /// JPEG quality.
    pub quality: u8,
    /// Frames per second at most (the ack pacing enforces it).
    pub fps: u32,
}

impl Default for Opts {
    /// Crisp by default: 30 fps, JPEG 85, up to 1920×1080 device pixels (the console asks for
    /// its real stage size × devicePixelRatio).
    fn default() -> Self {
        Opts { max_width: 1920, max_height: 1080, quality: 85, fps: 30 }
    }
}

/// The highest frame rate a viewer may pick.
pub const MAX_FPS: u32 = 60;

impl Opts {
    /// Caps: 160–3840 px, quality 20–95, 1–[`MAX_FPS`] fps.
    pub fn clamped(self) -> Opts {
        Opts { max_width: self.max_width.clamp(160, 3840), max_height: self.max_height.clamp(160, 3840), quality: self.quality.clamp(20, 95), fps: self.fps.clamp(1, MAX_FPS) }
    }
    /// Shortest gap between two acks.
    pub fn min_gap(&self) -> Duration {
        frame_gap(self.fps)
    }
}

/// The interval between frames for a chosen rate. The choice is a floor ("at least 30 fps"),
/// so streams are paced 10 % faster than it: timer jitter and a busy machine then still land
/// on or above the number the viewer picked instead of just below it.
pub fn frame_gap(fps: u32) -> Duration {
    Duration::from_micros(10_000_000 / (u64::from(fps.max(1)) * 11))
}

/// One screencast frame.
#[derive(Debug, Clone, PartialEq)]
pub struct LiveFrame {
    pub seq: u64,
    pub data: Vec<u8>,
    /// CSS viewport size the frame shows (`metadata.deviceWidth/Height`).
    pub device_width: f64,
    pub device_height: f64,
    pub offset_top: f64,
    pub page_scale: f64,
    /// When Chrome composited the frame (ms since the epoch; 0 when it did not say).
    pub captured_ms: u64,
}

impl LiveFrame {
    /// Parse a `Page.screencastFrame` event's params (the sequence number is set by the cast).
    pub fn from_event(p: &Value) -> Option<(LiveFrame, i64)> {
        let data = seagent_net::crypto::b64_decode(p["data"].as_str()?)?;
        let m = &p["metadata"];
        let f = |k: &str| m[k].as_f64().unwrap_or(0.0);
        let ts = m["timestamp"].as_f64().map_or(0, |t| (t * 1000.0) as u64);
        Some((LiveFrame { seq: 0, data, device_width: f("deviceWidth"), device_height: f("deviceHeight"), offset_top: f("offsetTop"), page_scale: f("pageScaleFactor"), captured_ms: ts }, p["sessionId"].as_i64()?))
    }

    /// The header viewers get before the JPEG bytes.
    pub fn meta(&self) -> Value {
        json!({"t": "frame", "seq": self.seq, "mime": "image/jpeg", "bytes": self.data.len(), "cssWidth": self.device_width, "cssHeight": self.device_height, "offsetTop": self.offset_top, "pageScale": self.page_scale, "capturedMs": self.captured_ms})
    }
}

/// What a viewer must do before it may wait for the next frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Release {
    /// Nothing to ack (no frame pending, or a newer one than this viewer saw).
    Nothing,
    /// Ack this frame now.
    Ack(i64),
    /// The fps cap: wait this long, then ask again.
    Wait(Duration),
}

/// The pacing state of one page's screencast (pure; [`Cast`] adds the lock and the clock).
#[derive(Debug, Default)]
pub struct CastState {
    pub seq: u64,
    pub latest: Option<Arc<LiveFrame>>,
    /// Frames Chrome waits on an ack for, oldest first: (seq, screencast session id). Acks
    /// go out one per fps interval, so the in-flight window cannot raise the rate.
    pub unacked: VecDeque<(u64, i64)>,
    pub last_ack: Option<Instant>,
    /// How long Chrome takes from an ack to the next frame (capture + encode), smoothed: acks
    /// are released that much early, so frames *arrive* at the fps cap instead of cap + lead.
    pub lead: Duration,
    /// An ack went out with nothing else in flight: the next frame's arrival measures the lead.
    lead_probe: Option<Instant>,
    /// What each viewer asks for (by viewer id); the screencast runs at the best of them.
    pub wants: BTreeMap<u64, Opts>,
    next_viewer: u64,
    /// (quality, max width, max height) the running screencast was started with (`None` =
    /// not started by viewers, e.g. a recording's).
    pub running: Option<(u8, u32, u32)>,
    /// Frames received / acked (stats and tests).
    pub frames_in: u64,
    pub acks: u64,
}

impl CastState {
    /// A frame arrived (it replaces the newest one: viewers only ever get the latest). Returns
    /// an ack to send at once only when more than [`MAX_IN_FLIGHT`] frames wait.
    pub fn offer(&mut self, f: LiveFrame, ack_id: i64) -> Option<i64> {
        self.offer_at(f, ack_id, Instant::now())
    }

    /// [`Self::offer`] at a given time (tests).
    pub fn offer_at(&mut self, mut f: LiveFrame, ack_id: i64, now: Instant) -> Option<i64> {
        if let Some(t) = self.lead_probe.take() {
            let took = now.saturating_duration_since(t).min(Duration::from_millis(500));
            self.lead = (self.lead * 3 + took) / 4;
        }
        self.seq += 1;
        self.frames_in += 1;
        f.seq = self.seq;
        self.latest = Some(Arc::new(f));
        self.unacked.push_back((self.seq, ack_id));
        if self.unacked.len() > MAX_IN_FLIGHT {
            self.acks += 1;
            return self.unacked.pop_front().map(|(_, id)| id);
        }
        None
    }

    /// A frame while a recording paces the screencast (it acks every frame itself): store it
    /// for the viewers, never queue an ack.
    pub fn offer_unpaced(&mut self, mut f: LiveFrame) {
        self.seq += 1;
        self.frames_in += 1;
        f.seq = self.seq;
        self.latest = Some(Arc::new(f));
    }

    /// The screencast parameters the viewers need: the highest quality and size any asks for
    /// (each viewer's own fps is applied on delivery).
    pub fn effective(&self) -> Option<(u8, u32, u32)> {
        self.wants.values().fold(None, |acc, o| {
            let (q, w, h) = acc.unwrap_or((0, 0, 0));
            Some((q.max(o.quality), w.max(o.max_width), h.max(o.max_height)))
        })
    }

    /// The parameters to (re)start the screencast with, if they differ from what runs.
    pub fn retune(&mut self) -> Option<(u8, u32, u32)> {
        let e = self.effective()?;
        (self.running != Some(e)).then(|| {
            self.running = Some(e);
            e
        })
    }

    /// A viewer has delivered every frame up to `seen`: may the pending frame be acked yet?
    pub fn release(&mut self, seen: u64, now: Instant, min_gap: Duration) -> Release {
        match self.unacked.front() {
            Some(&(s, id)) if s <= seen => {
                if let Some(t) = self.last_ack {
                    // Early by Chrome's production time (up to a whole interval: a large frame can
                    // take Chrome longer to make than the interval; each viewer's delivery slots
                    // still hold the rate).
                    let due = t + min_gap - self.lead.min(min_gap);
                    if due > now {
                        return Release::Wait(due - now);
                    }
                }
                self.unacked.pop_front();
                if self.unacked.is_empty() {
                    self.lead_probe = Some(now);
                }
                self.last_ack = Some(now);
                self.acks += 1;
                Release::Ack(id)
            }
            _ => Release::Nothing,
        }
    }
}

/// One page session's screencast, shared by its viewers.
pub struct Cast {
    pub page_session: String,
    pub state: Mutex<CastState>,
    cv: Condvar,
}

impl Cast {
    pub fn new(page_session: &str) -> Cast {
        Cast { page_session: page_session.to_string(), state: Mutex::new(CastState::default()), cv: Condvar::new() }
    }

    /// From the CDP I/O thread: store the frame, wake viewers; `Some(id)` = ack that now (a
    /// superseded frame, or one that could not be decoded — Chrome must never stall on it).
    pub fn offer(&self, p: &Value) -> Option<i64> {
        let Some((f, id)) = LiveFrame::from_event(p) else { return p["sessionId"].as_i64() };
        let stale = self.state.lock().unwrap().offer(f, id);
        self.cv.notify_all();
        stale
    }

    /// [`CastState::offer_unpaced`] from the CDP I/O thread (the caller acks the frame).
    pub fn offer_unpaced(&self, p: &Value) {
        if let Some((f, _)) = LiveFrame::from_event(p) {
            self.state.lock().unwrap().offer_unpaced(f);
            self.cv.notify_all();
        }
    }

    /// Hand every pending ack to the caller (a recording takes the screencast's pacing over).
    pub fn take_unacked(&self) -> Vec<i64> {
        self.state.lock().unwrap().unacked.drain(..).map(|(_, id)| id).collect()
    }
}

/// Where a tab's page (its viewport, without the browser's own toolbars) is on the screen, in
/// device pixels, and whether it is the tab the window shows. From the page's own
/// `screenX` / `outer*` / `inner*` (the window frame is symmetric left / right / bottom), so it
/// works the same on every OS; it never touches the idle clock.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OnScreen {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub visible: bool,
}

const GEOMETRY_JS: &str = "JSON.stringify([screenX, screenY, outerWidth, outerHeight, innerWidth, innerHeight, devicePixelRatio, document.visibilityState === 'visible'])";

/// [`OnScreen`] of `target`.
pub fn page_on_screen(b: &Browser, target: &str) -> Result<OnScreen, String> {
    let sid = crate::view::page_session(b, target)?;
    let r = b.conn.call_with("Runtime.evaluate", json!({"expression": GEOMETRY_JS, "returnByValue": true}), Some(&sid), Duration::from_secs(3), &|| None)?;
    let v: Vec<Value> = serde_json::from_str(r["result"]["value"].as_str().ok_or("no page geometry")?).map_err(|e| e.to_string())?;
    on_screen_from(&v).ok_or_else(|| "bad page geometry".into())
}

/// The arithmetic of [`page_on_screen`]: `[screenX, screenY, outerW, outerH, innerW, innerH,
/// dpr, visible]` (CSS px) → device pixels.
pub fn on_screen_from(v: &[Value]) -> Option<OnScreen> {
    let f = |i: usize| v.get(i).and_then(Value::as_f64);
    let (sx, sy, ow, oh, iw, ih, dpr) = (f(0)?, f(1)?, f(2)?, f(3)?, f(4)?, f(5)?, f(6).filter(|d| *d > 0.0).unwrap_or(1.0));
    let border = ((ow - iw) / 2.0).max(0.0);
    let (x, y) = (sx + border, sy + (oh - ih - border).max(0.0));
    Some(OnScreen { x: (x * dpr).round() as i32, y: (y * dpr).round() as i32, width: (iw * dpr).round().max(1.0) as u32, height: (ih * dpr).round().max(1.0) as u32, visible: v.get(7).and_then(Value::as_bool).unwrap_or(false) })
}

/// The tab of `b` its window shows (the visible document), if any.
pub fn visible_page(b: &Browser) -> Option<(String, OnScreen)> {
    let tabs = b.tabs(None).ok()?;
    tabs.iter().filter_map(|t| t["targetId"].as_str()).find_map(|t| page_on_screen(b, t).ok().filter(|g| g.visible).map(|g| (t.to_string(), g)))
}

fn ack(b: &Browser, page_session: &str, id: i64) {
    b.conn.send_nowait("Page.screencastFrameAck", json!({"sessionId": id}), Some(page_session));
}

fn screencast_params((q, w, h): (u8, u32, u32)) -> Value {
    json!({"format": "jpeg", "quality": q, "maxWidth": w, "maxHeight": h, "everyNthFrame": 1})
}

/// A viewer of one tab. Dropping the last viewer stops the screencast.
pub struct Viewer {
    b: Arc<Browser>,
    cast: Arc<Cast>,
    id: u64,
    opts: Opts,
    seen: u64,
    pub target: String,
    /// (url, title, when read): refreshed from the browser at most once a second.
    info: Option<(String, String, Instant)>,
    /// When this viewer may get its next frame: its fps cap also holds while a recording, not
    /// the acks, paces the screencast. Slots follow the previous slot (not the late wake-up),
    /// so coarse OS timers (Windows: 15.6 ms) do not drag the average below the cap.
    next_slot: Option<Instant>,
}

/// Start (or join) the live stream of `target`.
pub fn watch(b: &Arc<Browser>, target: &str, opts: Opts) -> Result<Viewer, String> {
    if b.state.lock().unwrap().pages.get(target).is_some_and(|p| !p.dialogs.is_empty()) {
        return Err(BLOCKED_BY_DIALOG.into());
    }
    let sid = crate::view::page_session(b, target)?;
    let opts = opts.clamped();
    let (cast, id, start) = {
        let mut s = b.state.lock().unwrap();
        let cast = s
            .live
            .entry(sid.clone())
            .or_insert_with(|| {
                // Acks must go out the moment a viewer releases them (see `Conn::low_latency`).
                b.conn.low_latency(true);
                Arc::new(Cast::new(&sid))
            })
            .clone();
        let mut g = cast.state.lock().unwrap();
        g.next_viewer += 1;
        let id = g.next_viewer;
        g.wants.insert(id, opts);
        // A new or a more demanding viewer (re)starts the screencast with what it needs; a
        // running one (the recording's, or other viewers') is re-tuned, never stopped.
        let start = g.retune();
        drop(g);
        (cast, id, start)
    };
    let v = Viewer { b: b.clone(), cast, id, opts, seen: 0, target: target.to_string(), info: None, next_slot: None };
    if let Some(e) = start {
        // Dropping `v` on failure undoes the registration.
        b.conn.call_with("Page.startScreencast", screencast_params(e), Some(&sid), Duration::from_secs(5), &|| None)?;
    }
    Ok(v)
}

impl Viewer {
    pub fn opts(&self) -> Opts {
        self.opts
    }

    /// Change what this viewer asks for (the console's quality / fps choice, or the stream
    /// adapting to a slow link). The screencast is re-tuned in place when the best request
    /// changes; it never stops.
    pub fn retune(&mut self, opts: Opts) {
        self.opts = opts.clamped();
        let start = {
            let mut g = self.cast.state.lock().unwrap();
            g.wants.insert(self.id, self.opts);
            g.retune()
        };
        if let Some(e) = start {
            self.b.conn.send_nowait("Page.startScreencast", screencast_params(e), Some(&self.cast.page_session));
        }
    }

    /// The newest frame this viewer has not seen, waiting at most `timeout`. Taking a frame
    /// releases the one before it (ack-paced at the fps cap); `None` = nothing new in time.
    pub fn next(&mut self, timeout: Duration) -> Option<Arc<LiveFrame>> {
        let deadline = Instant::now() + timeout;
        let gap = self.opts.min_gap();
        let mut g = self.cast.state.lock().unwrap();
        loop {
            let now = Instant::now();
            let mut wake = deadline;
            match g.release(self.seen, now, gap) {
                Release::Ack(id) => {
                    ack(&self.b, &self.cast.page_session, id);
                    continue;
                }
                Release::Wait(d) => wake = wake.min(now + d),
                Release::Nothing => {}
            }
            if g.seq > self.seen {
                match self.next_slot.filter(|due| *due > now + Duration::from_millis(1)) {
                    Some(due) => wake = wake.min(due),
                    None => {
                        self.seen = g.seq;
                        // Late by less than an interval: keep the cadence; later: start afresh.
                        self.next_slot = Some(match self.next_slot {
                            Some(due) if now < due + gap => due + gap,
                            _ => now + gap,
                        });
                        return g.latest.clone();
                    }
                }
            }
            if now >= deadline || self.b.conn.is_closed() {
                return None;
            }
            // A new frame, or the next ack falling due, whichever comes first.
            g = self.cast.cv.wait_timeout(g, wake.saturating_duration_since(now).max(Duration::from_millis(1))).unwrap().0;
        }
    }

    /// The tab is gone (closed, crashed) or the browser connection dropped.
    pub fn ended(&self) -> bool {
        self.b.conn.is_closed() || self.b.state.lock().unwrap().pages.get(&self.target).is_some_and(|p| p.closed)
    }

    /// The tab's URL and title (redacted like everything the view shows), asked of the
    /// browser at most once a second (the page state does not follow every title change).
    pub fn page_info(&mut self) -> (String, String) {
        if let Some((u, t, at)) = &self.info {
            if at.elapsed() < Duration::from_secs(1) {
                return (u.clone(), t.clone());
            }
        }
        let i = self.b.conn.call_with("Target.getTargetInfo", json!({"targetId": self.target}), None, Duration::from_secs(2), &|| None).unwrap_or_default();
        let (u, t) = match i["targetInfo"].as_object() {
            Some(i) => (i.get("url").and_then(Value::as_str).unwrap_or("").to_string(), i.get("title").and_then(Value::as_str).unwrap_or("").to_string()),
            None => self.b.state.lock().unwrap().pages.get(&self.target).map(|p| (p.url.clone(), p.title.clone())).unwrap_or_default(),
        };
        let (u, t) = (crate::policy::redact(&u), crate::policy::redact(&t));
        self.info = Some((u.clone(), t.clone(), Instant::now()));
        (u, t)
    }

    /// (frames received, acks sent) of the shared cast.
    pub fn stats(&self) -> (u64, u64) {
        let g = self.cast.state.lock().unwrap();
        (g.frames_in, g.acks)
    }
}

impl Drop for Viewer {
    fn drop(&mut self) {
        let mut s = self.b.state.lock().unwrap();
        let recording = s.recording.contains_key(&self.cast.page_session);
        let mut g = self.cast.state.lock().unwrap();
        g.wants.remove(&self.id);
        if !g.wants.is_empty() {
            // The others may need less: re-tune down to what they ask for.
            if let Some(e) = g.retune() {
                self.b.conn.send_nowait("Page.startScreencast", screencast_params(e), Some(&self.cast.page_session));
            }
            return;
        }
        if s.live.get(&self.cast.page_session).is_some_and(|c| Arc::ptr_eq(c, &self.cast)) {
            s.live.remove(&self.cast.page_session);
            self.b.conn.low_latency(false);
        }
        // Never strand Chrome on an unacked frame (a recording keeps running on its own acks).
        for (_, id) in g.unacked.drain(..) {
            ack(&self.b, &self.cast.page_session, id);
        }
        drop(g);
        drop(s);
        if !recording {
            self.b.conn.send_nowait("Page.stopScreencast", json!({}), Some(&self.cast.page_session));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manager::{Env, Manager};
    use crate::BrowserConfig;

    fn frame(n: u8) -> LiveFrame {
        LiveFrame { seq: 0, data: vec![0xff, 0xd8, n], device_width: 800.0, device_height: 600.0, offset_top: 0.0, page_scale: 1.0, captured_ms: 0 }
    }

    #[test]
    fn page_geometry_maps_to_device_pixels() {
        // A Windows window at (100, 50): 8 px invisible borders, 87 px of tab strip + toolbar.
        let g = on_screen_from(&serde_json::from_str::<Vec<Value>>("[100, 50, 1416, 908, 1400, 813, 1, true]").unwrap()).unwrap();
        assert_eq!(g, OnScreen { x: 108, y: 137, width: 1400, height: 813, visible: true });
        // A frameless, maximized window on a 2x screen.
        let g = on_screen_from(&serde_json::from_str::<Vec<Value>>("[0, 0, 1280, 800, 1280, 720, 2, false]").unwrap()).unwrap();
        assert_eq!(g, OnScreen { x: 0, y: 160, width: 2560, height: 1440, visible: false });
        assert!(on_screen_from(&[]).is_none());
    }

    #[test]
    fn opts_are_capped() {
        let o = Opts { max_width: 99_999, max_height: 1, quality: 200, fps: 0 }.clamped();
        assert_eq!(o, Opts { max_width: 3840, max_height: 160, quality: 95, fps: 1 });
        assert_eq!(Opts::default(), Opts { max_width: 1920, max_height: 1080, quality: 85, fps: 30 }, "crisp by default");
        assert_eq!(Opts { fps: 10, ..Default::default() }.min_gap(), Duration::from_micros(90_909), "10 % headroom over the chosen rate");
        assert_eq!(Opts { fps: 500, ..Default::default() }.clamped().min_gap(), frame_gap(60), "up to 60 fps");
        assert_eq!(frame_gap(30).as_micros(), 30_303, "30 fps chosen: paced at 33");
    }

    #[test]
    fn acks_wait_for_a_viewer_and_the_fps_cap() {
        let gap = Duration::from_millis(100);
        let t0 = Instant::now();
        let mut s = CastState::default();
        assert_eq!(s.release(0, t0, gap), Release::Nothing, "no frame yet");
        assert_eq!(s.offer_at(frame(1), 11, t0), None);
        // Backpressure: nobody took frame 1, so it is not acked (Chrome sends nothing more).
        assert_eq!(s.release(0, t0, gap), Release::Nothing);
        assert_eq!(s.unacked, [(1, 11)]);
        // A viewer delivered it: first ack goes out at once.
        assert_eq!(s.release(1, t0, gap), Release::Ack(11));
        assert_eq!(s.release(1, t0, gap), Release::Nothing, "acked once");
        // The next frame arrives 10 ms later and is delivered at once: the cap holds the ack.
        s.offer_at(frame(2), 12, t0);
        let t1 = t0 + Duration::from_millis(10);
        assert_eq!(s.release(2, t1, gap), Release::Wait(Duration::from_millis(90)));
        assert_eq!(s.release(2, t0 + gap, gap), Release::Ack(12));
        assert_eq!((s.frames_in, s.acks), (2, 2));
    }

    #[test]
    fn acks_go_out_early_by_chromes_production_time() {
        let gap = Duration::from_millis(33);
        let ms = Duration::from_millis;
        let t0 = Instant::now();
        let mut s = CastState::default();
        s.offer_at(frame(1), 1, t0);
        assert_eq!(s.release(1, t0, gap), Release::Ack(1));
        // Chrome needs 10 ms after each ack to produce the next frame.
        let mut t = t0;
        for i in 2..40 {
            let arrive = t + ms(10);
            s.offer_at(frame(i as u8), i, arrive);
            let due = match s.release(i as u64, arrive, gap) {
                Release::Wait(d) => arrive + d,
                Release::Ack(_) => arrive,
                Release::Nothing => panic!("frame {i} pending"),
            };
            assert!(matches!(s.release(i as u64, due, gap), Release::Ack(_)));
            t = due;
        }
        assert!(s.lead >= ms(9) && s.lead <= ms(10), "learned lead {:?}", s.lead);
        // Frames now arrive one interval apart (ack at +23 ms, frame 10 ms later), not 43 ms.
        let a = t + ms(10);
        s.offer_at(frame(99), 99, a);
        let Release::Wait(d) = s.release(99, a, gap) else { panic!() };
        assert!((ms(22)..=ms(24)).contains(&(d + ms(10))), "ack {:?} after the previous", d + ms(10));
        // A frame that takes Chrome longer than an interval to make: acked as soon as delivered.
        s.lead = ms(500);
        let b = a + d;
        assert_eq!(s.release(99, b, gap), Release::Ack(99));
        s.offer_at(frame(100), 100, b);
        assert_eq!(s.release(100, b, gap), Release::Ack(100));
    }

    #[test]
    fn a_slow_viewer_only_ever_gets_the_newest_frame() {
        let gap = Duration::ZERO;
        let t = Instant::now();
        let mut s = CastState::default();
        s.offer_at(frame(1), 1, t);
        // A fast viewer drains, a slow one has seen nothing.
        assert_eq!(s.release(1, t, gap), Release::Ack(1));
        s.offer_at(frame(2), 2, t);
        assert_eq!(s.release(1, t, gap), Release::Nothing, "a viewer that has not delivered frame 2 cannot release it");
        assert_eq!(s.release(2, t, gap), Release::Ack(2));
        s.offer_at(frame(3), 3, t);
        // One slot, newest wins: memory stays one frame whatever a viewer's speed.
        assert_eq!(s.latest.as_ref().unwrap().seq, 3);
        assert_eq!(s.latest.as_ref().unwrap().data, vec![0xff, 0xd8, 3]);
        // Chrome's in-flight window (two frames) does not raise the rate: the second waits its turn.
        assert_eq!(s.offer_at(frame(4), 4, t), None);
        assert_eq!(s.unacked, [(3, 3), (4, 4)]);
        let gap = Duration::from_millis(100);
        let t = t + Duration::from_secs(1);
        assert_eq!(s.release(4, t, gap), Release::Ack(3));
        assert_eq!(s.release(4, t, gap), Release::Wait(gap), "one ack per interval");
        assert_eq!(s.release(4, t + gap, gap), Release::Ack(4));
        // A runaway window is cut at MAX_IN_FLIGHT: the oldest is acked at once.
        for i in 5..5 + MAX_IN_FLIGHT as i64 {
            assert_eq!(s.offer_at(frame(i as u8), i, t), None);
        }
        assert_eq!(s.offer_at(frame(99), 99, t), Some(5));
        assert_eq!(s.unacked.len(), MAX_IN_FLIGHT);
    }

    #[test]
    fn parses_screencast_events() {
        let p = json!({"data": seagent_net::crypto::b64(b"\xff\xd8JPEG"), "sessionId": 7, "metadata": {"deviceWidth": 1280, "deviceHeight": 720, "offsetTop": 0, "pageScaleFactor": 1, "timestamp": 1700000000.25}});
        let (f, id) = LiveFrame::from_event(&p).unwrap();
        assert_eq!((id, f.data.as_slice(), f.device_width, f.captured_ms), (7, &b"\xff\xd8JPEG"[..], 1280.0, 1_700_000_000_250));
        assert_eq!(f.meta()["bytes"], 6);
        assert!(LiveFrame::from_event(&json!({"data": "x"})).is_none(), "no sessionId");
    }

    /// The fake DevTools endpoint answers `Page.startScreencast` with three frames; the viewer
    /// sees them, acks are paced, and the last viewer stops the screencast.
    #[test]
    fn viewers_share_one_screencast_and_the_last_one_stops_it() {
        let frames: Vec<Value> = (1..=3).map(|i| json!({"method": "Page.screencastFrame", "sessionId": "SP1", "params": {"data": seagent_net::crypto::b64(&[0xff, 0xd8, i]), "sessionId": i, "metadata": {"deviceWidth": 640, "deviceHeight": 480}}})).collect();
        let started = std::sync::atomic::AtomicBool::new(false);
        let f = crate::cdp::fake::start(Arc::new(move |m, p, _| match m {
            "Target.getTargets" => (json!({"targetInfos": [{"targetId": "P1", "type": "page", "url": "https://example.com/", "title": "Example"}]}), vec![]),
            "Target.attachToTarget" => (json!({"sessionId": format!("S{}", p["targetId"].as_str().unwrap())}), vec![]),
            // One frame on the first start and one per ack: Chrome's ack-paced behaviour (a
            // re-tune while running just changes the parameters).
            "Page.startScreencast" if !started.swap(true, std::sync::atomic::Ordering::SeqCst) => (json!({}), vec![frames[0].clone()]),
            "Page.screencastFrameAck" => {
                let n = p["sessionId"].as_i64().unwrap_or(9) as usize;
                (json!({}), frames.get(n).cloned().into_iter().collect())
            }
            _ => (json!({}), vec![]),
        }));
        let cfg = BrowserConfig { backend: "cdp".into(), cdp_url: f.http.clone(), ..Default::default() };
        let env = Env { cfg, home: seagent_core::tmp::scratch_path(format!("seagent-live-{}", std::process::id())), secrets: Arc::new(|s: &str| s.to_string()) };
        let m = Manager::default();
        let b = m.browser(&env, "cdp").unwrap();
        let idle = Instant::now();
        let mut v = watch(&b, "P1", Opts { fps: 30, quality: 60, ..Default::default() }).unwrap();
        let mut w = watch(&b, "P1", Opts { fps: 60, quality: 85, ..Default::default() }).unwrap();
        assert_eq!((v.opts().fps, w.opts().fps), (30, 60), "each viewer keeps its own fps");
        assert!(b.conn.is_low_latency(), "acks go out at once while someone watches");
        let mut got = vec![];
        while let Some(fr) = v.next(Duration::from_secs(3)) {
            got.push(fr.data[2]);
            if got.len() == 3 {
                break;
            }
        }
        assert_eq!(got, [1, 2, 3], "every frame, in order");
        assert_eq!(w.next(Duration::from_secs(1)).unwrap().data[2], 3, "a viewer that was away gets the newest frame only");
        let sent = |m: &str| f.seen.lock().unwrap().iter().filter(|x| x["method"] == m).count();
        let starts: Vec<Value> = f.seen.lock().unwrap().iter().filter(|x| x["method"] == "Page.startScreencast").map(|x| x["params"].clone()).collect();
        assert_eq!(starts.iter().map(|p| p["quality"].as_u64().unwrap()).collect::<Vec<_>>(), [60, 85], "the sharper viewer re-tunes the one screencast");
        assert_eq!(sent("Page.stopScreencast"), 0);
        w.retune(Opts { quality: 85, fps: 60, max_width: 2560, max_height: 1440 });
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(f.seen.lock().unwrap().iter().rfind(|x| x["method"] == "Page.startScreencast").unwrap()["params"]["maxWidth"], 2560, "a bigger viewer re-tunes in place");
        drop(v);
        assert_eq!(sent("Page.stopScreencast"), 0, "another viewer still watches");
        drop(w);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(sent("Page.stopScreencast"), 1, "the last viewer stops it");
        assert!(b.state.lock().unwrap().live.is_empty());
        assert!(!b.conn.is_low_latency(), "no viewer: the connection polls at its idle rate again");
        assert!(b.idle_for() + Duration::from_millis(20) >= idle.elapsed(), "watching does not touch the idle clock");
        let _ = std::fs::remove_dir_all(&env.home);
    }

    /// `browser record` and console viewers share one screencast whichever starts first:
    /// neither restarts nor stops it under the other, the recording keeps every frame while a
    /// viewer watches (it acks them itself), and a viewer keeps its fps cap meanwhile.
    #[test]
    fn recording_and_viewers_share_one_screencast() {
        use std::sync::atomic::{AtomicI64, Ordering};
        let n = Arc::new(AtomicI64::new(0));
        let n2 = n.clone();
        // Chrome-like: one frame on start and one per ack, endlessly (a frame every ~4 ms).
        let next = move || {
            std::thread::sleep(Duration::from_millis(4));
            let i = n2.fetch_add(1, Ordering::SeqCst) + 1;
            json!({"method": "Page.screencastFrame", "sessionId": "SP1", "params": {"data": seagent_net::crypto::b64(&[0xff, 0xd8, (i % 250) as u8]), "sessionId": i, "metadata": {"deviceWidth": 640, "deviceHeight": 480}}})
        };
        let f = crate::cdp::fake::start(Arc::new(move |m, p, _| match m {
            "Target.getTargets" => (json!({"targetInfos": [{"targetId": "P1", "type": "page", "url": "https://example.com/", "title": "Example"}]}), vec![]),
            "Target.attachToTarget" => (json!({"sessionId": format!("S{}", p["targetId"].as_str().unwrap())}), vec![]),
            "Page.startScreencast" | "Page.screencastFrameAck" => (json!({}), vec![next()]),
            _ => (json!({}), vec![]),
        }));
        let d = seagent_core::tmp::TempDir::new("seagent-live-rec");
        let cfg = BrowserConfig { backend: "cdp".into(), cdp_url: f.http.clone(), ..Default::default() };
        let env = Env { cfg, home: d.path().to_path_buf(), secrets: Arc::new(|s: &str| s.to_string()) };
        let m = Manager::default();
        let b = m.browser(&env, "cdp").unwrap();
        let sent = |m: &str| f.seen.lock().unwrap().iter().filter(|x| x["method"] == m).count();
        let rec_frames = |b: &Browser| b.state.lock().unwrap().recording.values().map(|(_, n)| *n).sum::<u64>();
        let take = |v: &mut Viewer, k: usize| (0..k).filter_map(|_| v.next(Duration::from_secs(3))).count();

        // ① viewer first, then a recording joins and leaves.
        let mut v = watch(&b, "P1", Opts { fps: 2, ..Default::default() }).unwrap();
        assert_eq!(take(&mut v, 1), 1);
        crate::manager::start_recording(&env, &b, "P1", "s1");
        assert_eq!(sent("Page.startScreencast"), 1, "the recording joins the viewer's screencast");
        let t0 = Instant::now();
        assert_eq!(take(&mut v, 4), 4);
        let secs = t0.elapsed().as_secs_f64();
        assert!(4.0 / secs <= 2.6, "the viewer's 2 fps cap holds while the recording paces the screencast: {:.1}", 4.0 / secs);
        let recorded = rec_frames(&b) as f64;
        assert!(recorded / secs >= 6.0, "the recording is not held to the viewer's 2 fps: {recorded} frames in {secs:.2} s");
        crate::manager::finish_recordings(&b);
        assert_eq!(sent("Page.stopScreencast"), 0, "stopping the recording leaves the viewer's screencast running");
        assert_eq!(take(&mut v, 3), 3, "the viewer still gets frames (paced by its acks again)");
        drop(v);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(sent("Page.stopScreencast"), 1);

        // ② recording first, then a viewer joins and leaves.
        crate::manager::start_recording(&env, &b, "P1", "s2");
        assert_eq!(sent("Page.startScreencast"), 2);
        let mut v = watch(&b, "P1", Opts::default()).unwrap();
        assert_eq!((sent("Page.startScreencast"), sent("Page.stopScreencast")), (3, 1), "the viewer re-tunes the recording's screencast to its quality, without stopping it");
        assert_eq!(take(&mut v, 3), 3);
        let before = rec_frames(&b);
        drop(v);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(sent("Page.stopScreencast"), 1, "the viewer leaving does not stop the recording");
        assert!(rec_frames(&b) > before, "the recording keeps getting frames");
        assert!(b.state.lock().unwrap().live.is_empty());
        crate::manager::finish_recordings(&b);
        assert_eq!(sent("Page.stopScreencast"), 2);
    }
}
