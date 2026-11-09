//! Real-time live view for the web console: `GET /view/live` (WebSocket) streams what the
//! agent is doing, as it happens, instead of the UI polling `view.*.frame`.
//!
//! `?kind=` picks the stream; the other query parameters are the `view.*` ones:
//!
//! - `browser` (`session`, `key`, `targetId`, `maxWidth`, `quality`, `fps`): CDP
//!   `Page.startScreencast` JPEG frames of the tab, ack-paced (`seagent_browser::live`). A
//!   still page sends nothing; a slow socket slows Chrome down instead of queueing.
//! - `desktop` (`target` = `host` | `vm:<name>`, `maxWidth`, `quality`, `fps`): the Bot Desktop
//!   or a desktop VM, as a base picture plus patches of what changed (`frame` with
//!   `mode: "patch"`, then `{"t":"patch", x, y, w, h}`), composed by the console on a canvas.
//!   With the agent's own browser on the Bot Desktop the page patches are its CDP screencast
//!   frames, forwarded as they are; otherwise [`crate::live_regions`] finds what changed — the
//!   Windows window tracker (dirty windows re-rendered in parallel, never switching the
//!   visible desktop), RFB from the Linux Xvnc ([`crate::live_rfb`]), or a tile diff of whole
//!   grabs (macOS, desktop VMs) — and encodes it on parallel threads. A target without a
//!   display says `{"t":"nodisplay"}` and the console shows the terminal instead.
//! - `terminal` (`session`): the agent's commands as they run — script, output, exit — from
//!   every exec backend, the microVM included (`seagent_tools::exec::live`). Secrets are
//!   redacted (`Vault::redact`), and a secret split across reads is held back until it can be
//!   redacted whole ([`Redacting`]).
//!
//! Server → client: text `{"t":"hello"|"frame"|"term"|"stats"|"nodisplay"|"error"|"end"|
//! "revoked"|"input"}`; each `frame` header is followed by one binary message (the JPEG).
//! Client → server: `{"t":"input", viewer, event}` — the same events and the same lease rule as
//! `view.browser.input` / `view.desktop.input`, and only for a credential that may POST them.
//!
//! Auth: the route sits behind the server's credential check like every `/view/` route
//! (Bearer, the `seagent.token.<t>` subprotocol, or `?token=` on a same-origin upgrade),
//! tenant-bound accounts are refused, a cross-origin upgrade is refused, and the socket closes
//! within a second of the credential being revoked. Nothing is captured while nobody watches.

use crate::identity::Principal;
use crate::server::App;
use seagent_net::httpd::{Request, Response};
use seagent_net::ws::{Message, WebSocket};
use serde_json::{json, Value};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const ROUTE: &str = "/view/live";

/// What a stream is of.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Browser,
    Desktop,
    Terminal,
}

impl Kind {
    pub fn parse(s: Option<&str>) -> Result<Kind, String> {
        match s.unwrap_or("browser") {
            "browser" => Ok(Kind::Browser),
            "desktop" => Ok(Kind::Desktop),
            "terminal" => Ok(Kind::Terminal),
            k => Err(format!("kind `{k}`: use browser, desktop or terminal")),
        }
    }
}

/// Lowest JPEG quality the stream adapts down to before it gives up frame rate instead.
pub const FLOOR_QUALITY: u8 = 50;
const FPS_STEPS: [u32; 9] = [60, 45, 30, 24, 20, 15, 10, 5, 2];

/// Keeps a stream at the quality and fps the viewer chose while the link keeps up. When it
/// does not — sending a frame takes most of the frame interval (the socket is full: a slow
/// link or a viewer that cannot decode fast enough) — it lowers JPEG quality first (down to
/// [`FLOOR_QUALITY`]), then the frame rate; after 3 s of an idle link it climbs back, frame
/// rate first, never above the choice. Nothing changes while the bandwidth is there.
#[derive(Debug, Clone, PartialEq)]
pub struct Adapt {
    pub chosen: (u8, u32),
    pub quality: u8,
    pub fps: u32,
    busy: f64,
    calm: Option<Instant>,
    settle: Option<Instant>,
}

impl Adapt {
    pub fn new(quality: u8, fps: u32) -> Adapt {
        Adapt { chosen: (quality, fps), quality, fps, busy: 0.0, calm: None, settle: None }
    }

    /// The viewer picked another level: go there at once.
    pub fn choose(&mut self, quality: u8, fps: u32) {
        *self = Adapt::new(quality, fps);
    }

    /// After one frame was sent (`send` = how long writing it took): `true` when the quality
    /// or fps changed.
    pub fn sent(&mut self, send: Duration, now: Instant) -> bool {
        let interval = 1.0 / f64::from(self.fps.max(1));
        self.busy = 0.7 * self.busy + 0.3 * (send.as_secs_f64() / interval).min(4.0);
        if self.settle.is_some_and(|t| now < t) {
            return false;
        }
        if self.busy > 0.8 {
            if self.quality > FLOOR_QUALITY {
                self.quality = self.quality.saturating_sub(10).max(FLOOR_QUALITY);
            } else if let Some(f) = FPS_STEPS.iter().find(|f| **f < self.fps) {
                self.fps = *f;
            } else {
                return false;
            }
            (self.busy, self.calm, self.settle) = (0.5, None, Some(now + Duration::from_secs(1)));
            return true;
        }
        if self.busy >= 0.3 || (self.quality, self.fps) == self.chosen {
            self.calm = None;
            return false;
        }
        let since = *self.calm.get_or_insert(now);
        if now.duration_since(since) < Duration::from_secs(3) {
            return false;
        }
        if self.fps < self.chosen.1 {
            self.fps = FPS_STEPS.iter().rev().find(|f| **f > self.fps).map_or(self.chosen.1, |f| (*f).min(self.chosen.1));
        } else {
            self.quality = (self.quality + 10).min(self.chosen.0);
        }
        (self.calm, self.settle) = (Some(now), Some(now + Duration::from_secs(1)));
        true
    }

    pub fn json(&self) -> Value {
        json!({"quality": self.quality, "fpsTarget": self.fps, "chosen": {"quality": self.chosen.0, "fps": self.chosen.1}})
    }
}

/// Frames per second / kbit per second / mean capture-to-send latency over a window.
#[derive(Debug, Default)]
struct Stats {
    since: Option<Instant>,
    frames: u32,
    bytes: u64,
    latency_ms: u64,
    latency_n: u32,
}

impl Stats {
    fn sent(&mut self, bytes: usize, latency_ms: Option<u64>) {
        self.since.get_or_insert_with(Instant::now);
        self.frames += 1;
        self.bytes += bytes as u64;
        if let Some(l) = latency_ms {
            self.latency_ms += l;
            self.latency_n += 1;
        }
    }
    /// Every 2 s: the report, and a fresh window.
    fn report(&mut self) -> Option<Value> {
        let s = self.since?;
        let dt = s.elapsed().as_secs_f64();
        if dt < 2.0 {
            return None;
        }
        let v = json!({"t": "stats", "fps": (f64::from(self.frames) / dt * 10.0).round() / 10.0, "kbps": (self.bytes as f64 * 8.0 / 1000.0 / dt).round(), "bytesPerSec": (self.bytes as f64 / dt).round(), "latencyMs": (self.latency_n > 0).then(|| self.latency_ms / u64::from(self.latency_n))});
        *self = Stats { since: Some(Instant::now()), ..Default::default() };
        Some(v)
    }
}

pub(crate) fn now_ms() -> u64 {
    seagent_browser::util::now_ms()
}

fn q(r: &Request) -> Value {
    r.query.iter().map(|(k, v)| (k.clone(), Value::String(v.clone()))).collect::<serde_json::Map<_, _>>().into()
}

fn num(p: &Value, k: &str, d: u32) -> u32 {
    p[k].as_str().and_then(|x| x.parse::<u32>().ok()).unwrap_or(d)
}

fn s<'a>(p: &'a Value, k: &str) -> Option<&'a str> {
    p[k].as_str().map(str::trim).filter(|x| !x.is_empty())
}

/// `GET /view/live` — called by the server after the credential, tenant and scope checks.
pub fn upgrade(app: &Arc<App>, r: &Request, p: Principal) -> Response {
    if !r.is_upgrade() {
        return Response::json(426, &json!({"error": "GET /view/live is a WebSocket (Upgrade: websocket)"}).to_string()).with_header("upgrade", "websocket");
    }
    // Cross-site WebSocket hijacking: only our own page (or a listed origin) may connect.
    if !app.origin_ok(r) {
        return Response::text(403, "origin not allowed");
    }
    let params = q(r);
    let kind = match Kind::parse(s(&params, "kind")) {
        Ok(k) => k,
        Err(e) => return Response::json(400, &json!({"error": e}).to_string()),
    };
    // Watching is a read; driving the screen is what POST /view/*/input needs.
    let may_input = p.access.permits_http("POST", "/view/browser/input").is_ok();
    let offered: Vec<String> = r.header("sec-websocket-protocol").map(|h| h.split(',').map(|x| x.trim().to_string()).collect()).unwrap_or_default();
    let proto = offered.iter().find(|x| *x == "seagent.live").or_else(|| offered.iter().find(|x| x.starts_with("seagent.token."))).cloned();
    crate::metrics::inc("view_live_streams", &format!("kind=\"{kind:?}\""));
    let app = app.clone();
    Response::upgrade(Box::new(move |sock, head, rest| {
        // Short: checking for viewer messages between frames must not delay the next frame.
        let _ = sock.set_read_timeout(Some(Duration::from_millis(2)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(10)));
        let ws = match &proto {
            Some(pr) => crate::server::accept_with_protocol(sock, &head, rest, pr),
            None => WebSocket::accept(sock, &head, rest),
        };
        let Ok(mut ws) = ws else { return };
        ws.set_max_message(64 * 1024);
        let mut link = Link { ws, app, p, checked: Instant::now(), may_input, kind, params, input_to: Value::Null, tune: None };
        let r = match kind {
            Kind::Browser => browser(&mut link),
            Kind::Desktop => desktop(&mut link),
            Kind::Terminal => terminal(&mut link),
        };
        if let Err(Some(e)) = r {
            let _ = link.text(&json!({"t": "error", "message": e}));
        }
        let _ = link.ws.send(&Message::Close(None));
    }))
}

/// `Err(None)` = the socket is gone (nothing more to say), `Err(Some(m))` = tell the viewer why.
type Flow = Result<(), Option<String>>;

struct Link {
    ws: WebSocket<TcpStream>,
    app: Arc<App>,
    p: Principal,
    checked: Instant,
    may_input: bool,
    kind: Kind,
    params: Value,
    /// Where viewer input goes: the stream's `{key, targetId}` / `{target}`.
    input_to: Value,
    /// A new quality / fps choice from the viewer (`{"t":"tune", quality, fps}`).
    tune: Option<(u8, u32)>,
}

/// The viewer's quality / fps choice from the query or a `tune` message (defaults: 85, 30).
fn choice(q: Option<u64>, fps: Option<u64>) -> (u8, u32) {
    (q.map_or(85, |q| q.clamp(20, 95) as u8), fps.map_or(30, |f| f.clamp(1, u64::from(seagent_browser::live::MAX_FPS)) as u32))
}

impl Link {
    fn text(&mut self, v: &Value) -> Flow {
        self.ws.send_text(&v.to_string()).map_err(|_| None)
    }

    fn frame(&mut self, meta: &Value, jpeg: &[u8]) -> Flow {
        self.text(meta)?;
        self.ws.send(&Message::Binary(jpeg.to_vec())).map_err(|_| None)
    }

    /// Between frames: the credential is still valid, and whatever the viewer sent.
    fn poll(&mut self) -> Flow {
        if self.checked.elapsed() >= Duration::from_secs(1) {
            self.checked = Instant::now();
            if !self.app.still_valid(&self.p) {
                let _ = self.text(&json!({"t": "revoked", "reason": "credential disabled or revoked"}));
                return Err(None);
            }
        }
        loop {
            let m = match self.ws.recv() {
                Ok(None) => return Ok(()),
                Ok(Some(Message::Text(t))) => t,
                Ok(Some(Message::Close(_))) | Err(_) => return Err(None),
                Ok(Some(_)) => continue,
            };
            let v: Value = serde_json::from_str(&m).unwrap_or_default();
            if v["t"] == "tune" {
                self.tune = Some(choice(v["quality"].as_u64(), v["fps"].as_u64()));
            }
            if v["t"] == "input" {
                let r = self.input(&v);
                let reply = match r {
                    Ok(x) => json!({"t": "input", "ok": true, "result": x}),
                    Err(e) => json!({"t": "input", "ok": false, "error": e}),
                };
                self.text(&reply)?;
            }
        }
    }

    /// Viewer input over the stream: the `view.*.input` methods, lease check included.
    fn input(&self, v: &Value) -> Result<Value, String> {
        if !self.may_input {
            return Err("forbidden: this credential may watch but not send input".into());
        }
        let method = match self.kind {
            Kind::Browser => "view.browser.input",
            Kind::Desktop => "view.desktop.input",
            Kind::Terminal => return Err("the terminal stream takes no input".into()),
        };
        let mut p = self.input_to.clone();
        p["viewer"] = v["viewer"].clone();
        p["event"] = v["event"].clone();
        crate::browser_view::rpc(&self.app, method, &p).map_err(|(_, e)| e)
    }
}

// ── browser ──

fn browser(l: &mut Link) -> Flow {
    use seagent_browser::{live, view};
    let m = seagent_browser::manager::global();
    let (b, target) = view::resolve(m, s(&l.params, "session"), s(&l.params, "key"), s(&l.params, "targetId")).map_err(Some)?;
    l.input_to = json!({"key": b.key, "targetId": target});
    let (quality, fps) = choice(l.params["quality"].as_str().and_then(|x| x.parse().ok()), l.params["fps"].as_str().and_then(|x| x.parse().ok()));
    // Full device-pixel resolution: the console sends its stage size × devicePixelRatio.
    let mut o = live::Opts { max_width: num(&l.params, "maxWidth", 1920), max_height: num(&l.params, "maxHeight", 1080), quality, fps }.clamped();
    let mut adapt = Adapt::new(o.quality, o.fps);
    l.text(&json!({"t": "hello", "kind": "browser", "key": b.key, "targetId": target, "input": l.may_input, "fps": o.fps, "quality": o.quality, "maxWidth": o.max_width, "maxHeight": o.max_height}))?;
    // First paint at once (a still page may not repaint for a long time).
    if let Ok(f) = view::capture(&b, &target, o.max_width, o.quality) {
        let meta = json!({"t": "frame", "seq": 0, "mime": f.mime, "bytes": f.data.len(), "cssWidth": f.css_width, "cssHeight": f.css_height, "url": f.url, "title": f.title, "sentMs": now_ms()});
        l.frame(&meta, &f.data)?;
    }
    let mut v = live::watch(&b, &target, o).map_err(Some)?;
    let mut st = Stats::default();
    let mut polled = Instant::now();
    loop {
        // Viewer messages (input, tune) at most every 20 ms while frames flow.
        if polled.elapsed() >= Duration::from_millis(20) {
            l.poll()?;
            polled = Instant::now();
        }
        if let Some((q, f)) = l.tune.take() {
            adapt.choose(q, f);
            o = live::Opts { quality: q, fps: f, ..o };
            v.retune(o);
        }
        if let Some(f) = v.next(Duration::from_millis(60)) {
            let (url, title) = v.page_info();
            let sent = now_ms();
            let mut meta = f.meta();
            meta["url"] = url.into();
            meta["title"] = title.into();
            meta["sentMs"] = sent.into();
            let lat = (f.captured_ms > 0).then(|| sent.saturating_sub(f.captured_ms));
            let t0 = Instant::now();
            l.frame(&meta, &f.data)?;
            st.sent(f.data.len(), lat);
            if adapt.sent(t0.elapsed(), Instant::now()) {
                o = live::Opts { quality: adapt.quality, fps: adapt.fps, ..o };
                v.retune(o);
            }
        } else if v.ended() {
            return l.text(&json!({"t": "end", "reason": "the tab closed or the browser stopped"}));
        }
        if let Some(mut r) = st.report() {
            r["adapt"] = adapt.json();
            l.text(&r)?;
        }
    }
}

// ── desktop ──

/// A cheap change detector for frames: every 7th 8-byte word (a whole 1080p frame in well under a
/// millisecond; a change that misses every sampled word shows up a frame later).
fn frame_hash(b: &[u8]) -> u64 {
    b.as_chunks::<8>().0.iter().step_by(7).fold(0xcbf2_9ce4_8422_2325u64, |h, w| (h ^ u64::from_le_bytes(*w)).wrapping_mul(0x0100_0000_01b3)) ^ b.len() as u64
}

/// Downscale to `max_w` and encode as JPEG.
pub fn to_jpeg(img: image::DynamicImage, max_w: u32, quality: u8) -> Result<(Vec<u8>, u32, u32), String> {
    let img = if img.width() > max_w { img.thumbnail(max_w, u32::MAX) } else { img };
    let rgb = img.to_rgb8();
    let mut out = Vec::with_capacity(rgb.len() / 8);
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality).encode(rgb.as_raw(), rgb.width(), rgb.height(), image::ExtendedColorType::Rgb8).map_err(|e| e.to_string())?;
    Ok((out, rgb.width(), rgb.height()))
}

/// The per-stream capture state: on Windows a worker bound to the Bot Desktop
/// (`LiveCapture`), started with the first frame.
#[derive(Default)]
struct Grabber {
    #[cfg(windows)]
    cap: Option<seagent_browser::control::screen_windows::LiveCapture>,
}

/// One frame of a desktop target for a viewer `max_w` wide.
fn grab_for(app: &App, t: &crate::browser_view::Target, g: &mut Grabber, max_w: u32) -> Result<image::DynamicImage, String> {
    #[cfg(windows)]
    if *t == crate::browser_view::Target::Host {
        let home = app.d.k.paths.data.clone();
        let d = seagent_browser::control::screen::Desktop::new(&home);
        let wd = seagent_browser::control::screen_windows::WinDesktop::new(&home, &d.profile, &d.geometry);
        if wd.running() {
            let cap = g.cap.get_or_insert_with(|| seagent_browser::control::screen_windows::LiveCapture::start(&wd.name()));
            let shot = cap.grab(max_w)?;
            let (w, h) = (shot.width.max(0) as u32, shot.height.max(0) as u32);
            let mut rgba = shot.bgra;
            for px in rgba.chunks_exact_mut(4) {
                px.swap(0, 2);
                px[3] = 255;
            }
            return image::RgbaImage::from_raw(w, h, rgba).map(image::DynamicImage::ImageRgba8).ok_or_else(|| "bad Bot Desktop frame".to_string());
        }
    }
    let _ = (g, max_w);
    grab(app, t)
}

/// One picture of a desktop target.
fn grab(app: &App, t: &crate::browser_view::Target) -> Result<image::DynamicImage, String> {
    use crate::browser_view::Target;
    let home = app.d.k.paths.data.clone();
    let png = match t {
        Target::Vm(n) => crate::browser_view::desktop_vms(app).peek(n)?,
        Target::Host => {
            #[cfg(windows)]
            {
                // The isolated CreateDesktopW desktop: a direct GDI grab of its framebuffer.
                let d = seagent_browser::control::screen::Desktop::new(&home);
                let wd = seagent_browser::control::screen_windows::WinDesktop::new(&home, &d.profile, &d.geometry);
                if wd.running() {
                    let shot = wd.screenshot()?;
                    let (w, h) = (shot.width.max(0) as u32, shot.height.max(0) as u32);
                    let mut rgba = shot.bgra;
                    for px in rgba.chunks_exact_mut(4) {
                        px.swap(0, 2);
                        px[3] = 255;
                    }
                    return image::RgbaImage::from_raw(w, h, rgba).map(image::DynamicImage::ImageRgba8).ok_or_else(|| "bad Bot Desktop frame".to_string());
                }
            }
            // Linux: the Bot Desktop's Xvnc display (its published DISPLAY / XAUTHORITY);
            // macOS / Windows without a Bot Desktop: the session's screen.
            let env = seagent_browser::control::screen::Desktop::new(&home).published_env();
            crate::node::with_env(&env, || crate::computer::screenshot_png(&home))?
        }
    };
    image::load_from_memory(&png).map_err(|e| format!("desktop frame: {e}"))
}

fn desktop(l: &mut Link) -> Flow {
    let t = crate::browser_view::with_app(&l.app, |c| crate::browser_view::target(c, &l.params)).map_err(|(_, e)| Some(e))?;
    l.input_to = json!({"target": t.id()});
    let (quality, fps) = choice(l.params["quality"].as_str().and_then(|x| x.parse().ok()), l.params["fps"].as_str().and_then(|x| x.parse().ok()));
    let max_w = num(&l.params, "maxWidth", 1920).clamp(320, 3840);
    l.text(&json!({"t": "hello", "kind": "desktop", "target": t.id(), "input": l.may_input, "fps": fps, "quality": quality, "maxWidth": max_w}))?;
    // The agent's own browser on the Bot Desktop: its page streams as CDP screencast patches
    // over a base picture of the desktop that is only re-sent when something else changes.
    if t == crate::browser_view::Target::Host {
        if let Some(b) = bot_browser() {
            if let Some((tab, g)) = seagent_browser::live::visible_page(&b) {
                return desktop_patched(l, &t, (quality, fps), b, tab, g);
            }
        }
    }
    // Everything else: only what changed, as patches (the window tracker on Windows, RFB on
    // the Linux Xvnc, a tile diff of whole grabs elsewhere), encoded in parallel.
    let mut src = region_source(&l.app, &t, max_w);
    crate::live_regions::stream(l, &t.id(), &mut *src, quality, fps)
}

/// The region source for a desktop target (see `live_regions`).
fn region_source(app: &Arc<App>, t: &crate::browser_view::Target, max_w: u32) -> Box<dyn crate::live_regions::RegionSource> {
    use crate::browser_view::Target;
    let home = app.d.k.paths.data.clone();
    if *t == Target::Host {
        #[cfg(windows)]
        {
            let d = seagent_browser::control::screen::Desktop::new(&home);
            let wd = seagent_browser::control::screen_windows::WinDesktop::new(&home, &d.profile, &d.geometry);
            if wd.running() {
                return Box::new(WinTrack(seagent_browser::control::screen_windows::LiveCapture::start(&wd.name())));
            }
        }
        #[cfg(unix)]
        if let Some(sock) = seagent_browser::control::screen::Desktop::new(&home).rfb_socket() {
            match crate::live_rfb::Rfb::connect(&sock) {
                Ok(r) => return Box::new(r),
                Err(e) => eprintln!("seagent: live view: {e}; falling back to whole-screen grabs"),
            }
        }
    }
    let (app, t) = (app.clone(), t.clone());
    let mut g = Grabber::default();
    Box::new(crate::live_regions::Snapshots::new(move || grab_for(&app, &t, &mut g, max_w)))
}

/// The Windows Bot Desktop's window tracker as a region source.
#[cfg(windows)]
struct WinTrack(seagent_browser::control::screen_windows::LiveCapture);

#[cfg(windows)]
impl crate::live_regions::RegionSource for WinTrack {
    fn next(&mut self) -> Result<crate::live_regions::Update, String> {
        use crate::live_regions::Update;
        use seagent_browser::control::screen_windows::{Shot, TrackUpdate};
        // BGRA as GDI gives it: the encoder threads convert (no per-pixel work here).
        let rgba = |s: Shot| -> Result<crate::live_regions::Frame, String> { Ok(crate::live_regions::Frame { w: s.width.max(0) as u32, h: s.height.max(0) as u32, data: s.bgra, bgra: true }) };
        Ok(match self.0.track()? {
            TrackUpdate::Full(s) => Update::Full(rgba(s)?),
            TrackUpdate::Rects(rs) => Update::Rects(rs.into_iter().map(|(x, y, s)| Ok((x.max(0) as u32, y.max(0) as u32, rgba(s)?))).collect::<Result<_, String>>()?),
            TrackUpdate::Same => Update::Same,
        })
    }
}

impl crate::live_regions::Sink for Link {
    fn poll(&mut self) -> Result<Option<(u8, u32)>, Option<String>> {
        Link::poll(self)?;
        Ok(self.tune.take())
    }
    fn send(&mut self, meta: &Value, jpeg: &[u8]) -> Result<(), Option<String>> {
        self.frame(meta, jpeg)
    }
    fn text(&mut self, v: &Value) -> Result<(), Option<String>> {
        Link::text(self, v)
    }
}

/// The agent's browser on the desktop the host target shows, if any: launched onto the Bot
/// Desktop (`seagent screen`), or — Linux / macOS, where the host target is the display the
/// headed browser opens on (Xvnc, the login session) — any headed managed browser. (On Windows
/// a headed browser without the Bot Desktop is on the user's own screen, not this target.)
fn bot_browser() -> Option<Arc<seagent_browser::engine::Browser>> {
    seagent_browser::manager::global().browsers().into_iter().find(|b| {
        let i = b.info.lock().unwrap();
        !b.conn.is_closed() && (i.get("bot_desktop") == Some(&Value::Bool(true)) || (cfg!(not(windows)) && i.get("headless") == Some(&Value::Bool(false))))
    })
}

/// May the page at `g` be painted over the desktop picture (no other window covers it)?
fn page_uncovered(app: &App, b: &seagent_browser::engine::Browser, g: &seagent_browser::live::OnScreen) -> bool {
    #[cfg(windows)]
    {
        let home = app.d.k.paths.data.clone();
        let d = seagent_browser::control::screen::Desktop::new(&home);
        let name = seagent_browser::control::screen_windows::WinDesktop::new(&home, &d.profile, &d.geometry).name();
        b.pid.is_some_and(|pid| seagent_browser::control::screen_windows::on_top(&name, pid as u32, (g.x, g.y, g.width as i32, g.height as i32)))
    }
    #[cfg(not(windows))]
    {
        // Xvnc / macOS: the agent's browser is the Bot Desktop's only application window.
        let _ = (app, b, g);
        true
    }
}

/// A hash of the desktop picture outside the page area (sampled rows, in place): it changes
/// only when something other than the page does.
fn hash_outside(img: &image::DynamicImage, g: &seagent_browser::live::OnScreen) -> u64 {
    let (w, h) = (img.width() as usize, img.height() as usize);
    let px = img.as_bytes();
    let bpp = px.len().checked_div(w * h).unwrap_or(4).max(1);
    let (x0, x1) = ((g.x.max(0) as usize).min(w), ((g.x.max(0) as usize) + g.width as usize).min(w));
    let (y0, y1) = ((g.y.max(0) as usize).min(h), ((g.y.max(0) as usize) + g.height as usize).min(h));
    let mut acc = 0xcbf2_9ce4_8422_2325u64;
    for y in (0..h).step_by(2) {
        let row = &px[y * w * bpp..(y + 1) * w * bpp];
        let parts: [&[u8]; 2] = if (y0..y1).contains(&y) { [&row[..x0 * bpp], &row[x1 * bpp..]] } else { [row, &[]] };
        for part in parts {
            acc = (acc ^ frame_hash(part)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    acc
}

/// Bot Desktop stream in patch mode: a base picture of the whole desktop (full size, re-sent
/// only when something outside the page changes; checked every 250 ms by a capture thread)
/// plus the page itself as the browser's own screencast JPEGs, forwarded as they arrive
/// (`{"t":"patch", x, y, w, h}` in screen pixels): no capture or encode per frame, so the page
/// moves at the screencast's 30–60 fps. The console composes them on a canvas.
fn desktop_patched(l: &mut Link, t: &crate::browser_view::Target, (quality, fps): (u8, u32), b: Arc<seagent_browser::engine::Browser>, tab: String, g: seagent_browser::live::OnScreen) -> Flow {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    let app = l.app.clone();
    let stop = AtomicBool::new(false);
    // The base capture's interval: 250 ms after a change, backing off to 1 s while idle.
    let rest = AtomicU64::new(250);
    std::thread::scope(|sc| {
        let (tx, rx) = std::sync::mpsc::sync_channel::<BaseCapture>(1);
        let (stop_p, rest_p, app_p, b_p) = (&stop, &rest, app.clone(), b.clone());
        let mut tab_p = tab.clone();
        sc.spawn(move || {
            let mut grabber = Grabber::default();
            while !stop_p.load(Ordering::SeqCst) {
                let t0 = Instant::now();
                let r = grab_for(&app_p, t, &mut grabber, 3840);
                let took = t0.elapsed();
                // Window moved / resized, tab switched, something on top.
                let geo = match seagent_browser::live::page_on_screen(&b_p, &tab_p) {
                    Ok(g) if g.visible => Some((tab_p.clone(), g)),
                    _ => seagent_browser::live::visible_page(&b_p),
                };
                if let Some((t2, _)) = &geo {
                    tab_p = t2.clone();
                }
                let clear = geo.as_ref().is_some_and(|(_, g)| page_uncovered(&app_p, &b_p, g));
                if tx.send(((r, took), geo, clear)).is_err() {
                    break;
                }
                let until = Instant::now() + Duration::from_millis(rest_p.load(Ordering::SeqCst));
                while Instant::now() < until && !stop_p.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        });
        let r = patched_consume(l, &app, &t.id(), (quality, fps), &b, tab, g, &rx, &rest);
        stop.store(true, Ordering::SeqCst);
        drop(rx);
        r
    })
}

#[allow(clippy::too_many_arguments)]
fn patched_consume(l: &mut Link, app: &App, id: &str, (quality, fps): (u8, u32), b: &Arc<seagent_browser::engine::Browser>, mut tab: String, mut g: seagent_browser::live::OnScreen, rx: &std::sync::mpsc::Receiver<BaseCapture>, rest: &std::sync::atomic::AtomicU64) -> Flow {
    use std::sync::atomic::Ordering;
    use seagent_browser::live;
    let opts = |g: &live::OnScreen, q: u8, f: u32| live::Opts { max_width: g.width, max_height: g.height, quality: q, fps: f }.clamped();
    let mut adapt = Adapt::new(quality, fps);
    let mut v = live::watch(b, &tab, opts(&g, quality, fps)).map_err(Some)?;
    let (mut st, mut last, mut seq, mut base_sent, mut dark) = (Stats::default(), 0u64, 0u64, false, false);
    let mut uncovered = page_uncovered(app, b, &g);
    let mut polled = Instant::now();
    loop {
        if polled.elapsed() >= Duration::from_millis(20) {
            l.poll()?;
            polled = Instant::now();
        }
        if let Some((q, f)) = l.tune.take() {
            adapt.choose(q, f);
            v.retune(opts(&g, q, f));
        }
        // The base picture (when something outside the page changed) and where the page is now.
        if let Ok(((r, took), geo, clear)) = rx.try_recv() {
            match geo {
                Some((nt, ng)) if nt != tab => {
                    v = live::watch(b, &nt, opts(&ng, adapt.quality, adapt.fps)).map_err(Some)?;
                    (tab, g) = (nt, ng);
                }
                Some((_, ng)) => {
                    if (ng.width, ng.height) != (g.width, g.height) {
                        v.retune(opts(&ng, adapt.quality, adapt.fps));
                    }
                    g = ng;
                }
                None => return l.text(&json!({"t": "end", "reason": "the Bot Desktop browser shows no page"})),
            }
            uncovered = clear;
            match r {
                Ok(img) => {
                    dark = false;
                    let h = hash_outside(&img, &g);
                    let changed = h != last || !base_sent;
                    rest.store(if changed { 250 } else { (rest.load(Ordering::SeqCst) * 3 / 2).min(1000) }, Ordering::SeqCst);
                    if changed {
                        last = h;
                        let t0 = Instant::now();
                        let (w0, h0) = (img.width(), img.height());
                        let (jpeg, fw, fh) = to_jpeg(img, 3840, adapt.quality).map_err(Some)?;
                        seq += 1;
                        let meta = json!({"t": "frame", "seq": seq, "mime": "image/jpeg", "bytes": jpeg.len(), "width": w0, "height": h0, "frameWidth": fw, "frameHeight": fh, "quality": adapt.quality, "captureMs": took.as_millis() as u64, "encodeMs": t0.elapsed().as_millis() as u64, "sentMs": now_ms(), "mode": "patch"});
                        l.frame(&meta, &jpeg)?;
                        base_sent = true;
                    }
                }
                Err(e) => {
                    if !dark {
                        dark = true;
                        l.text(&json!({"t": "nodisplay", "target": id, "reason": e, "fallback": "terminal"}))?;
                    }
                }
            }
        }
        // The page, as fast as the screencast delivers it.
        match v.next(Duration::from_millis(10)) {
            Some(f) if base_sent && uncovered => {
                seq += 1;
                let sent = now_ms();
                let meta = json!({"t": "patch", "seq": seq, "mime": "image/jpeg", "bytes": f.data.len(), "x": g.x, "y": g.y, "w": g.width, "h": g.height, "capturedMs": f.captured_ms, "sentMs": sent});
                let s0 = Instant::now();
                l.frame(&meta, &f.data)?;
                st.sent(f.data.len(), (f.captured_ms > 0).then(|| sent.saturating_sub(f.captured_ms)));
                if adapt.sent(s0.elapsed(), Instant::now()) {
                    v.retune(opts(&g, adapt.quality, adapt.fps));
                }
            }
            Some(_) => {}
            None if v.ended() => return l.text(&json!({"t": "end", "reason": "the Bot Desktop browser closed"})),
            None => {}
        }
        if let Some(mut r) = st.report() {
            r["adapt"] = adapt.json();
            r["mode"] = "patch".into();
            l.text(&r)?;
        }
    }
}

/// One captured picture and how long the capture took.
type Captured = (Result<image::DynamicImage, String>, Duration);

/// Patch mode's base capture: the picture, how long it took, and where the browser's visible
/// page is now and whether nothing covers it (looked up on the capture thread, off the
/// thread that forwards the page frames).
type BaseCapture = (Captured, Option<(String, seagent_browser::live::OnScreen)>, bool);

// ── terminal ──

/// Secrets shorter than this are not redacted (the vault's own floor, `MIN_REDACT_LEN`).
const MIN_SECRET: usize = 6;

/// One command's output on its way to the console, redacted without ever letting a secret
/// through in pieces: a secret split across reads (or across a flush) would not match the
/// vault's whole-value replacement, so the tail that could still be the start of a secret is
/// held back (at most the longest secret's length − 1; usually nothing), and a cut never
/// falls inside a secret. UTF-8 characters are never split either.
#[derive(Default)]
pub struct Redacting {
    pending: Vec<u8>,
}

impl Redacting {
    pub fn push(&mut self, b: &[u8]) {
        self.pending.extend_from_slice(b);
    }

    /// The text that is safe to show now, redacted with `redact`; `force` (the command ended)
    /// releases everything.
    pub fn take(&mut self, secrets: &[String], redact: &dyn Fn(&str) -> String, force: bool) -> Option<String> {
        if self.pending.is_empty() {
            return None;
        }
        let p = &self.pending;
        let mut cut = p.len();
        if !force {
            for sec in secrets.iter().map(String::as_bytes).filter(|s| s.len() >= MIN_SECRET) {
                // The longest suffix of the output that is a proper prefix of this secret.
                let held = (1..sec.len().min(p.len() + 1)).rev().find(|&k| p.ends_with(&sec[..k])).unwrap_or(0);
                cut = cut.min(p.len() - held);
                // Never cut through a whole occurrence.
                let mut i = 0;
                while let Some(off) = p[i..].windows(sec.len()).position(|w| w == sec) {
                    let (a, b) = (i + off, i + off + sec.len());
                    if a < cut && cut < b {
                        cut = a;
                    }
                    i = b;
                }
            }
            cut = match std::str::from_utf8(&p[..cut]) {
                Ok(_) => cut,
                Err(e) if e.error_len().is_none() => e.valid_up_to(),
                Err(_) => cut,
            };
        }
        if cut == 0 {
            return None;
        }
        let rest = self.pending.split_off(cut);
        let text = String::from_utf8_lossy(&std::mem::replace(&mut self.pending, rest)).into_owned();
        Some(redact(&text))
    }
}

/// The vault's secret values (to know what may be arriving in pieces).
fn secret_values(v: &seagent_kernel::vault::Vault) -> Vec<String> {
    v.names().iter().map(|n| v.substitute(&format!("{{{{secret:{n}}}}}"))).filter(|x| x.len() >= MIN_SECRET && !x.contains("{{secret:")).collect()
}

fn terminal(l: &mut Link) -> Flow {
    use seagent_tools::exec::live::{self, Event};
    let session = s(&l.params, "session").map(str::to_string);
    let sub = live::subscribe(session.as_deref());
    l.text(&json!({"t": "hello", "kind": "terminal", "session": session}))?;
    let vault = l.app.d.k.vault.clone();
    let redact = |t: &str| vault.redact(t);
    let (mut secrets, mut fetched) = (secret_values(&vault), Instant::now());
    let mut bufs: std::collections::BTreeMap<u64, (String, Redacting)> = Default::default();
    loop {
        l.poll()?;
        if fetched.elapsed() >= Duration::from_secs(5) {
            (secrets, fetched) = (secret_values(&vault), Instant::now());
        }
        let mut out = vec![];
        for e in sub.next(Duration::from_millis(50)) {
            match e {
                Event::Start { cmd, session, backend, script } => out.push(json!({"e": "start", "cmd": cmd, "session": session, "backend": backend, "script": vault.redact(&script)})),
                Event::Out { cmd, session, data } => bufs.entry(cmd).or_insert_with(|| (session, Redacting::default())).1.push(&data),
                Event::Exit { cmd, session, code, signal } => {
                    if let Some((_, mut b)) = bufs.remove(&cmd) {
                        if let Some(t) = b.take(&secrets, &redact, true) {
                            out.push(json!({"e": "out", "cmd": cmd, "session": session, "data": t}));
                        }
                    }
                    out.push(json!({"e": "exit", "cmd": cmd, "session": session, "code": code, "signal": signal}));
                }
                Event::Gap { bytes } => out.push(json!({"e": "gap", "bytes": bytes})),
            }
        }
        for (cmd, (session, b)) in bufs.iter_mut() {
            if let Some(t) = b.take(&secrets, &redact, false) {
                out.push(json!({"e": "out", "cmd": cmd, "session": session, "data": t}));
            }
        }
        if !out.is_empty() {
            l.text(&json!({"t": "term", "events": out, "sentMs": now_ms()}))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AppConfig;
    use seagent_kernel::config::{Config, Paths};
    use seagent_kernel::daemon::Daemon;
    use std::io::{Read as _, Write as _};

    struct NoRes;
    impl seagent_kernel::kernel::Resolver for NoRes {
        fn provider(&self, id: &str) -> Result<Arc<dyn seagent_core::Provider>, String> {
            Err(format!("no provider {id}"))
        }
    }

    fn app(home: &std::path::Path) -> Arc<App> {
        let paths = Paths { data: home.join("data"), config_dir: home.join("cfg"), runtime: home.join("run"), ..Default::default() };
        let (pending, _cell) = seagent_kernel::daemon::pending_approver(Duration::from_secs(1));
        let k = seagent_kernel::kernel::new_kernel(Config::default(), paths, Arc::new(NoRes), vec![], Arc::new(seagent_kernel::vault::Vault::empty()), pending.clone());
        let d = Arc::new(Daemon::new(k, pending));
        let tokens = vec![crate::exposure::TokenConfig { token: "live-ro-token".into(), scope: "read".into(), name: Some("ro".into()), org: String::new(), team: String::new() }];
        let cfg = AppConfig { enabled: true, listen: "127.0.0.1:0".into(), tokens, ..AppConfig::default() };
        Arc::new(App { d, cfg, token: "live-admin-token".into(), host_methods: vec![], routes: vec![] })
    }

    /// The status line a raw WebSocket upgrade of `path` gets.
    fn status(addr: std::net::SocketAddr, path: &str, hs: &[(&str, &str)]) -> String {
        let mut c = TcpStream::connect(addr).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut req = format!("GET {path} HTTP/1.1\r\nhost: {addr}\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n");
        for (k, v) in hs {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        c.write_all(req.as_bytes()).unwrap();
        let mut buf = [0u8; 512];
        let n = c.read(&mut buf).unwrap_or(0);
        String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string()
    }

    fn connect(addr: std::net::SocketAddr, query: &str, token: &str) -> WebSocket<seagent_net::Stream> {
        let auth = format!("Bearer {token}");
        let (ws, _) = WebSocket::connect(&format!("ws://{addr}{ROUTE}?{query}"), &[("authorization", &auth)], Duration::from_secs(10)).unwrap();
        ws.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        ws
    }

    /// Next text message (skipping stats), within 10 s.
    fn next_text(ws: &mut WebSocket<seagent_net::Stream>) -> Value {
        let until = Instant::now() + Duration::from_secs(10);
        while Instant::now() < until {
            if let Ok(Some(Message::Text(t))) = ws.recv() {
                let v: Value = serde_json::from_str(&t).unwrap();
                if v["t"] != "stats" {
                    return v;
                }
            }
        }
        panic!("no message within 10 s");
    }

    #[test]
    fn adapt_keeps_the_choice_drops_quality_then_fps_and_climbs_back() {
        let t = Instant::now();
        let ms = Duration::from_millis;
        let mut a = Adapt::new(85, 30);
        // A link that keeps up: the chosen level holds, however long.
        for i in 0..300 {
            assert!(!a.sent(ms(4), t + ms(33 * i)), "no change while the bandwidth is there");
        }
        assert_eq!((a.quality, a.fps), (85, 30));
        // Sending takes longer than a frame interval: quality first, one step per second...
        let mut now = t + ms(10_000);
        let mut path = vec![];
        for _ in 0..400 {
            now += ms(50);
            if a.sent(ms(45), now) {
                path.push((a.quality, a.fps));
            }
        }
        assert_eq!(&path[..4], &[(75, 30), (65, 30), (55, 30), (50, 30)], "quality first: {path:?}");
        assert_eq!(path[4], (50, 24), "then frame rate: {path:?}");
        assert!(path.iter().all(|(q, _)| *q >= FLOOR_QUALITY));
        // ...and back once the link is idle: frame rate first, never above the choice.
        let mut up = vec![];
        for _ in 0..1000 {
            now += ms(40);
            if a.sent(ms(1), now) {
                up.push((a.quality, a.fps));
            }
        }
        assert_eq!(up.last(), Some(&(85, 30)), "{up:?}");
        let first_q = up.iter().position(|(q, _)| *q > FLOOR_QUALITY).unwrap();
        assert!(up[..first_q].iter().all(|(q, _)| *q == FLOOR_QUALITY) && up[first_q - 1].1 == 30, "fps recovers before quality: {up:?}");
        assert!(up.iter().all(|(q, f)| *q <= 85 && *f <= 30));
        // A new choice applies at once (60 fps picked by the viewer).
        a.choose(85, 60);
        assert_eq!((a.quality, a.fps, a.chosen), (85, 60, (85, 60)));
        assert_eq!(choice(None, None), (85, 30), "defaults: crisp, 30 fps");
        assert_eq!(choice(Some(500), Some(500)), (95, 60), "capped at 95 and 60 fps");
    }

    #[test]
    fn a_secret_split_across_reads_is_still_redacted() {
        let secrets = vec!["tok-s3cr3t-value".to_string(), "hunter22".to_string()];
        let redact = |t: &str| t.replace("tok-s3cr3t-value", "{{secret:API}}").replace("hunter22", "{{secret:PW}}");
        let mut b = Redacting::default();
        // Split mid-secret across two reads (and a line break before it).
        b.push(b"line one\nkey=tok-s3");
        assert_eq!(b.take(&secrets, &redact, false).as_deref(), Some("line one\nkey="), "the possible secret start is held back");
        b.push(b"cr3t-value\ndone");
        assert_eq!(b.take(&secrets, &redact, false).as_deref(), Some("{{secret:API}}\ndone"));
        // Byte by byte: nothing of the secret ever leaves unredacted.
        let mut shown = String::new();
        for c in b"pw: hunter22 ok".iter() {
            b.push(&[*c]);
            shown += &b.take(&secrets, &redact, false).unwrap_or_default();
        }
        assert_eq!(shown, "pw: {{secret:PW}} ok");
        assert!(!shown.contains("hunt"), "{shown}");
        // A tail that only looked like a secret's start is released once it diverges.
        b.push(b"tok-s3x");
        assert_eq!(b.take(&secrets, &redact, false).as_deref(), Some("tok-s3x"));
        // Held at most longest-secret − 1 bytes; the command's end flushes it.
        b.push(b"tok-s3cr3t-valu");
        assert_eq!(b.take(&secrets, &redact, false), None);
        assert_eq!(b.take(&secrets, &redact, true).as_deref(), Some("tok-s3cr3t-valu"));
        // Short secrets (below the vault's floor) hold nothing back; UTF-8 is never split.
        b.push(&"a你".as_bytes()[..2]);
        assert_eq!(b.take(&["abc".into()], &redact, false).as_deref(), Some("a"));
        b.push(&"你".as_bytes()[1..]);
        assert_eq!(b.take(&secrets, &redact, false).as_deref(), Some("你"));
        assert_eq!(b.take(&secrets, &redact, true), None);
    }

    #[test]
    fn the_base_picture_changes_only_outside_the_page() {
        let g = seagent_browser::live::OnScreen { x: 100, y: 80, width: 400, height: 300, visible: true };
        let mut img = image::RgbaImage::from_pixel(800, 600, image::Rgba([20, 20, 20, 255]));
        let h0 = hash_outside(&image::DynamicImage::ImageRgba8(img.clone()), &g);
        for y in 80..380 {
            for x in 100..500 {
                img.put_pixel(x, y, image::Rgba([250, 10, 10, 255]));
            }
        }
        assert_eq!(hash_outside(&image::DynamicImage::ImageRgba8(img.clone()), &g), h0, "the page area is the patches' job");
        for x in 0..800 {
            img.put_pixel(x, 10, image::Rgba([0, 200, 0, 255]));
        }
        assert_ne!(hash_outside(&image::DynamicImage::ImageRgba8(img), &g), h0, "a change outside the page re-sends the base");
    }

    #[test]
    fn jpeg_frames_are_scaled_down() {
        let img = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(1000, 500, image::Rgba([10, 200, 30, 255])));
        let (j, w, h) = to_jpeg(img, 400, 60).unwrap();
        assert_eq!((w, h, &j[..2]), (400, 200, &[0xff, 0xd8][..]));
    }

    /// Only an authenticated, same-origin console may open the stream; a read-only credential
    /// may watch but not drive; the terminal stream carries the session's commands live.
    #[test]
    fn live_stream_needs_a_credential_and_streams_the_terminal() {
        let home = seagent_core::tmp::scratch_path(format!("seagent-live-{}-{}", std::process::id(), seagent_net::crypto::random_token(4)));
        let srv_app = app(&home);
        let srv = crate::server::start(srv_app.clone()).unwrap();
        let addr = srv.local_addr();
        let path = format!("{ROUTE}?kind=terminal&session=lvt-app");
        assert!(status(addr, &path, &[]).contains(" 401"), "no credential");
        assert!(status(addr, &path, &[("authorization", "Bearer nope")]).contains(" 401"), "wrong token");
        assert!(status(addr, &format!("{path}&token=live-admin-token"), &[("origin", "https://evil.example")]).contains(" 403"), "cross-site upgrade");
        assert!(status(addr, &path, &[("authorization", "Bearer live-admin-token"), ("origin", "https://evil.example")]).contains(" 403"), "cross-site upgrade, even with a header token");
        assert!(status(addr, &format!("{path}&token=live-admin-token"), &[]).contains(" 101"), "same-origin ?token= on the upgrade");
        assert!(status(addr, &format!("{ROUTE}?kind=movie"), &[("authorization", "Bearer live-admin-token")]).contains(" 400"));
        assert!(status(addr, &path, &[("sec-websocket-protocol", "seagent.live, seagent.token.live-ro-token")]).contains(" 101"), "subprotocol token");
        // A plain GET is not a stream.
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(format!("GET {ROUTE} HTTP/1.1\r\nhost: {addr}\r\nauthorization: Bearer live-admin-token\r\n\r\n").as_bytes()).unwrap();
        let mut b = [0u8; 64];
        let n = c.read(&mut b).unwrap();
        assert!(String::from_utf8_lossy(&b[..n]).contains(" 426"));

        // The terminal: a command of the watched session, as it runs.
        srv_app.d.k.vault.set("DEPLOY_KEY", "dk_live_7f3a9c2e").unwrap();
        let mut ws = connect(addr, "kind=terminal&session=lvt-app", "live-ro-token");
        assert_eq!(next_text(&mut ws)["t"], "hello");
        // The secret arrives split across two reads: it must still be redacted whole.
        let mut child = seagent_tools::exec::live::tee(Box::new(Chunks(vec![b"building...\nkey=dk_live_7f".to_vec(), b"3a9c2e\ndone\n".to_vec()])), "lvt-app", "vm", "make all");
        let mut other = seagent_tools::exec::live::tee(Box::new(Chunks(vec![b"elsewhere\n".to_vec()])), "lvt-other", "vm", "true");
        let mut buf = [0u8; 64];
        while child.read(&mut buf, Duration::ZERO).unwrap() > 0 {}
        while other.read(&mut buf, Duration::ZERO).unwrap() > 0 {}
        child.try_wait().unwrap();
        let mut events = vec![];
        while !events.iter().any(|e: &Value| e["e"] == "exit") {
            let m = next_text(&mut ws);
            assert_eq!(m["t"], "term", "{m}");
            events.extend(m["events"].as_array().unwrap().iter().cloned());
        }
        assert_eq!((events[0]["e"].as_str(), events[0]["script"].as_str(), events[0]["backend"].as_str()), (Some("start"), Some("make all"), Some("vm")), "{events:?}");
        let text: String = events.iter().filter(|e| e["e"] == "out").map(|e| e["data"].as_str().unwrap()).collect();
        assert_eq!(text, "building...\nkey={{secret:DEPLOY_KEY}}\ndone\n");
        assert!(!text.contains("dk_live"), "no piece of the secret leaks: {text}");
        assert!(events.iter().all(|e| e["session"].is_null() || e["session"] == "lvt-app"), "another session's command stays out: {events:?}");
        // Read scope: watching yes, input no.
        ws.send_text(&json!({"t": "input", "viewer": "viewer-0001", "event": {"type": "click", "x": 0.5, "y": 0.5}}).to_string()).unwrap();
        let r = next_text(&mut ws);
        assert!(r["t"] == "input" && r["ok"] == false && r["error"].as_str().unwrap().contains("may watch but not send input"), "{r}");
        drop(ws);

        // Browser / desktop targets that do not exist say why, then close.
        let mut ws = connect(addr, "kind=browser&session=nope", "live-admin-token");
        let e = next_text(&mut ws);
        assert!(e["t"] == "error" && e["message"].as_str().unwrap().contains("no browser yet"), "{e}");
        let mut ws = connect(addr, "kind=desktop&target=vm:../x", "live-admin-token");
        assert_eq!(next_text(&mut ws)["t"], "error");
        // The admin token may send input: it reaches the lease check of view.desktop.input.
        let mut ws = connect(addr, "kind=desktop&target=host", "live-admin-token");
        let h = next_text(&mut ws);
        assert_eq!((h["t"].as_str(), h["input"].as_bool()), (Some("hello"), Some(true)), "{h}");
        ws.send_text(&json!({"t": "input", "viewer": "viewer-0001", "event": {"type": "click", "x": 1, "y": 1}}).to_string()).unwrap();
        let r = loop {
            let m = next_text(&mut ws);
            if m["t"] == "input" {
                break m;
            }
        };
        assert!(r["ok"] == false && r["error"].as_str().unwrap().contains("Take control first"), "{r}");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Real headless Chromium, end to end through the console route (not run by default):
    /// `SEAGENT_REAL_TESTS=1 [SEAGENT_LIVE_OUT=<dir>] cargo test -p seagent-app real_live_browser -- --ignored --nocapture`.
    /// A page of small text streams at 30 and 60 fps (fps, latency, bytes/s and CPU printed),
    /// frames are full-resolution JPEGs, a viewer holding the lease clicks through the stream,
    /// and frames are saved to `SEAGENT_LIVE_OUT`.
    #[test]
    #[ignore]
    fn real_live_browser_stream() {
        if std::env::var("SEAGENT_REAL_TESTS").ok().as_deref() != Some("1") {
            eprintln!("skipping: set SEAGENT_REAL_TESTS=1 to run real-browser cases");
            return;
        }
        // Frames are kept only where SEAGENT_LIVE_OUT points; otherwise a self-cleaning dir.
        let scratch = seagent_core::tmp::TempDir::new("seagent-live-frames");
        let out = std::env::var_os("SEAGENT_LIVE_OUT").map(std::path::PathBuf::from).unwrap_or_else(|| scratch.path().to_path_buf());
        std::fs::create_dir_all(&out).unwrap();
        let home = seagent_core::tmp::scratch_path(format!("seagent-live-real-{}", std::process::id()));
        let a = app(&home);
        let cfg = seagent_browser::BrowserConfig { backend: "local".into(), enabled: toml::Value::Boolean(true), headless: true, default_profile: format!("live{}", std::process::id()), ..Default::default() };
        let env = seagent_browser::manager::Env { cfg, home: home.join("data"), secrets: Arc::new(|s: &str| s.to_string()) };
        let m = seagent_browser::manager::global();
        let key = format!("profile:{}", env.cfg.default_profile);
        let b = m.browser(&env, &key).unwrap();
        struct Stop(String);
        impl Drop for Stop {
            fn drop(&mut self) {
                seagent_browser::manager::global().stop(&self.0);
            }
        }
        let _stop = Stop(key.clone());
        // A page full of small text (11–13 px) that repaints every animation frame (a clock and
        // a moving bar), so the stream always has a new picture to send.
        let lorem = "The quick brown fox jumps over the lazy dog; 0123456789 — pack my box with five dozen liquor jugs. ".repeat(3);
        let rows: String = (1..=48).map(|i| format!("<p style='margin:0;font:{}px/1.35 Segoe UI,Arial,sans-serif'>{i:02}. {lorem}</p>", 11 + i % 3)).collect();
        let html = format!("<!doctype html><body style='margin:8px;background:#fff;color:#111'><div id=bar style='height:6px;background:#c0362c;width:0'></div><h3 id=clk style='font:600 15px monospace;margin:4px 0'>t</h3>{rows}<script>let n=0;function f(){{n++;clk.textContent='frame '+n+' · '+new Date().toISOString()+' · '+document.title;bar.style.width=(n%600)/6+'%';requestAnimationFrame(f)}}f();onclick=e=>{{document.title='clicked at '+e.clientX+','+e.clientY}}</script>");
        let page = format!("data:text/html;charset=utf-8,{}", seagent_net::urlencode(&html));
        let t = b.new_tab(&page, None).unwrap();
        // The agent's tab: 1280×800 CSS px at DPR 1 (frames come at its device pixels).
        b.page_call(&t, "Emulation.setDeviceMetricsOverride", json!({"width": 1280, "height": 800, "deviceScaleFactor": 1, "mobile": false})).unwrap();
        let srv = crate::server::start(a.clone()).unwrap();
        let addr = srv.local_addr();
        // The console asks for its stage size × devicePixelRatio (a 1280×800 stage at DPR 2).
        let q = |fps: u32| format!("kind=browser&key={}&targetId={t}&fps={fps}&quality=85&maxWidth=2560&maxHeight=1600", seagent_net::urlencode(&key));
        let browser_filter = env.cfg.default_profile.clone();
        let mut meta = Value::Null;
        // ① 30 and 60 fps on small text: real fps, latency, bytes/s, CPU of this process (the
        // daemon side: CDP + WebSocket) and of the browser.
        for want in [30u32, 60] {
            let mut ws = connect(addr, &q(want), "live-admin-token");
            assert_eq!(next_text(&mut ws)["t"], "hello");
            // Let the screencast settle, then measure 5 s.
            let warm = Instant::now();
            while warm.elapsed() < Duration::from_millis(800) {
                let _ = ws.recv();
            }
            let (cpu_me0, cpu_br0) = (cpu_seconds_self(), cpu_seconds_matching(&browser_filter));
            let (mut frames, mut bytes, mut lat, mut last) = (0u32, 0usize, vec![], vec![]);
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(5) {
                match ws.recv() {
                    Ok(Some(Message::Text(x))) => meta = serde_json::from_str(&x).unwrap(),
                    Ok(Some(Message::Binary(jpg))) if meta["t"] == "frame" => {
                        assert_eq!(&jpg[..2], &[0xff, 0xd8], "a JPEG");
                        frames += 1;
                        bytes += jpg.len();
                        if let Some(c) = meta["capturedMs"].as_u64().filter(|c| *c > 0) {
                            lat.push(now_ms().saturating_sub(c));
                        }
                        last = jpg;
                    }
                    _ => {}
                }
            }
            let secs = t0.elapsed().as_secs_f64();
            let (cpu_me, cpu_br) = (cpu_seconds_self() - cpu_me0, cpu_seconds_matching(&browser_filter) - cpu_br0);
            lat.sort_unstable();
            let pct = |p: usize| lat.get((lat.len() * p / 100).min(lat.len().saturating_sub(1))).copied().unwrap_or(0);
            let fps = f64::from(frames) / secs;
            let (w, h) = jpeg_size(&last).unwrap_or((0, 0));
            eprintln!(
                "LIVE browser {want} fps (quality 85, small text): {frames} frames / {secs:.2} s = {fps:.1} fps; latency p50 {} ms, p95 {} ms; {:.0} KB/s ({:.1} KB/frame, {w}x{h}); CPU server {:.0}%, browser {:.0}% (of one core)",
                pct(50), pct(95), bytes as f64 / 1024.0 / secs, bytes as f64 / 1024.0 / f64::from(frames.max(1)), cpu_me / secs * 100.0, cpu_br / secs * 100.0
            );
            std::fs::write(out.join(format!("live-text-{want}fps.jpg")), &last).unwrap();
            assert!(fps >= f64::from(want) * 0.5 && fps <= f64::from(want) * 1.2, "{want} fps asked, {fps:.1} delivered");
            assert_eq!(w, 1280, "frames at the tab's full device-pixel width, not capped");
            drop(ws);
            std::thread::sleep(Duration::from_millis(300));
        }
        let mut ws = connect(addr, &q(30), "live-admin-token");
        assert_eq!(next_text(&mut ws)["t"], "hello");
        // ② input through the stream, gated by the lease.
        ws.send_text(&json!({"t": "input", "viewer": "viewer-live-1", "event": {"type": "click", "x": 0.5, "y": 0.5}}).to_string()).unwrap();
        let r = loop {
            let v = next_text(&mut ws);
            if v["t"] == "input" {
                break v;
            }
        };
        assert!(r["ok"] == false && r["error"].as_str().unwrap().contains("Take control first"), "{r}");
        crate::browser_view::rpc(&a, "view.desktop.takeover", &json!({"viewer": "viewer-live-1", "reason": "live test"})).unwrap();
        ws.send_text(&json!({"t": "input", "viewer": "viewer-live-1", "event": {"type": "click", "x": 0.5, "y": 0.5}}).to_string()).unwrap();
        let t1 = Instant::now();
        let mut clicked = false;
        let mut last_jpg = vec![];
        while t1.elapsed() < Duration::from_secs(5) && !(clicked && !last_jpg.is_empty()) {
            match ws.recv() {
                Ok(Some(Message::Text(x))) => {
                    meta = serde_json::from_str(&x).unwrap();
                    if meta["t"] == "input" {
                        assert_eq!(meta["ok"], true, "{meta}");
                    }
                    clicked |= meta["title"].as_str().is_some_and(|t| t.starts_with("clicked at "));
                }
                Ok(Some(Message::Binary(jpg))) if clicked => last_jpg = jpg,
                _ => {}
            }
        }
        eprintln!("LIVE input: click → title in the stream after {} ms", t1.elapsed().as_millis());
        assert!(clicked, "the click through the stream reached the page (title {})", meta["title"]);
        std::fs::write(out.join("live-99-after-click.jpg"), &last_jpg).unwrap();
        crate::browser_view::rpc(&a, "view.desktop.handback", &json!({"viewer": "viewer-live-1"})).unwrap();
        drop(ws);
        // ③ the viewer picks a lower rate over the open stream (the console's selector).
        let mut ws = connect(addr, &q(30), "live-admin-token");
        ws.send_text(&json!({"t": "tune", "fps": 5, "quality": 70}).to_string()).unwrap();
        let settle = Instant::now();
        while settle.elapsed() < Duration::from_millis(500) {
            let _ = ws.recv();
        }
        let (mut n, t2) = (0u32, Instant::now());
        while t2.elapsed() < Duration::from_secs(3) {
            if let Ok(Some(Message::Binary(_))) = ws.recv() {
                n += 1;
            }
        }
        let fps5 = f64::from(n.saturating_sub(1)) / 3.0;
        eprintln!("LIVE browser at fps=5: {n} frames in 3 s = {fps5:.1} fps");
        assert!((3.0..=6.0).contains(&fps5), "{fps5}");
        drop(ws);
        std::thread::sleep(Duration::from_millis(300));
        assert!(b.state.lock().unwrap().live.is_empty(), "no viewer, no screencast");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn console_streams_with_the_token_in_a_subprotocol_never_the_url() {
        let body = |path: &str| match crate::ui::serve(path).body {
            seagent_net::httpd::Body::Bytes(b) => String::from_utf8(b).unwrap(),
            _ => panic!("bytes"),
        };
        let js = body("/ui/live_view.js");
        for needle in ["/view/live?", "seagent.live", "seagent.token.", "kind: 'terminal'", "kind: 'browser'", "kind: 'desktop'", "lvPollFrame", "devicePixelRatio", "t: 'tune'", "fps: 60", "q: 85, fps: 30"] {
            assert!(js.contains(needle), "live_view.js lacks {needle}");
        }
        assert!(!js.contains("token="), "a token in a URL leaks into history and logs");
        let index = body("/");
        let (w, l) = (index.find("src=\"/ui/work.js\"").unwrap(), index.find("src=\"/ui/live_view.js\"").unwrap());
        assert!(w < l, "live_view.js loads after work.js (it wraps its functions)");
        assert!(index.contains("/ui/live_view.css"));
        let csp = crate::ui::serve("/").headers.into_iter().find(|(k, _)| k == "content-security-policy").unwrap().1;
        assert!(csp.contains("img-src 'self' data: blob:"), "frames are shown from blob: URLs: {csp}");
    }

    /// The real Bot Desktop streamed through the console route (not run by default):
    /// `SEAGENT_REAL_TESTS=1 [SEAGENT_LIVE_OUT=<dir>] cargo test -p seagent-app real_live_bot_desktop -- --ignored --nocapture`.
    /// Starts this OS's Bot Desktop (Windows: the isolated CreateDesktopW desktop, never made
    /// active; Linux: Xvnc + Xfce; macOS: the login session), puts a browser window with an
    /// animated page of small text on it, and measures the desktop stream at 30 fps.
    #[test]
    #[ignore]
    fn real_live_bot_desktop() {
        if std::env::var("SEAGENT_REAL_TESTS").ok().as_deref() != Some("1") {
            eprintln!("skipping: set SEAGENT_REAL_TESTS=1 to run real-desktop cases");
            return;
        }
        let scratch = seagent_core::tmp::TempDir::new("seagent-live-desk-frames");
        let out = std::env::var_os("SEAGENT_LIVE_OUT").map(std::path::PathBuf::from).unwrap_or_else(|| scratch.path().to_path_buf());
        std::fs::create_dir_all(&out).unwrap();
        let home = seagent_core::tmp::TempDir::new("seagent-live-desk");
        let a = app(home.path());
        let data = home.path().join("data");
        let desk = seagent_browser::control::screen::Desktop::new(&data);
        #[cfg(windows)]
        if seagent_browser::control::screen_windows::desktop_names().iter().any(|n| n == "seagent-default") {
            eprintln!("skipping: a seagent Bot Desktop (seagent-default) already runs on this window station");
            return;
        }
        if let Err(e) = desk.start() {
            eprintln!("skipping: no Bot Desktop on this host: {e}");
            return;
        }
        struct StopDesk(seagent_browser::control::screen::Desktop);
        impl Drop for StopDesk {
            fn drop(&mut self) {
                self.0.stop();
            }
        }
        let _desk = StopDesk(desk);
        let exe = seagent_browser::launch::find_executable("").expect("a Chromium-family browser");
        let lorem = "The quick brown fox jumps over the lazy dog 0123456789. ".repeat(4);
        let rows: String = (1..=40).map(|i| format!("<p style='margin:0;font:12px/1.4 Segoe UI,Arial,sans-serif'>{i:02}. {lorem}</p>")).collect();
        let html = format!("<!doctype html><body style='margin:10px;background:#fff;color:#111'><h2 id=c style='font:600 22px monospace'>desktop</h2>{rows}<script>let n=0;setInterval(()=>{{c.textContent='Bot Desktop live · frame '+(++n)+' · '+new Date().toISOString()}},33)</script>");
        let url = format!("data:text/html;charset=utf-8,{}", seagent_net::urlencode(&html));
        let profile = home.path().join("edge-profile");
        // InPrivate / incognito: never a signed-in profile (no account details in a frame).
        let args = [format!("--user-data-dir={}", profile.display()), "--inprivate".into(), "--incognito".into(), "--no-first-run".into(), "--no-default-browser-check".into(), "--window-position=0,0".into(), "--window-size=1400,900".into(), format!("--app={url}")];
        #[cfg(windows)]
        let pid = {
            let q = seagent_browser::control::screen_windows::WinDesktop::new(&data, "default", "1440x900").qualified();
            let line = std::iter::once(format!("\"{}\"", exe.display())).chain(args.iter().map(|a| format!("\"{a}\""))).collect::<Vec<_>>().join(" ");
            seagent_browser::control::screen_windows::spawn_on_desktop(&q, &line).unwrap()
        };
        #[cfg(not(windows))]
        let pid = {
            let env = seagent_browser::control::screen::Desktop::new(&data).published_env();
            std::process::Command::new(&exe).args(&args).envs(env).spawn().unwrap().id()
        };
        // The browser this test started, with its process tree, on every exit path.
        struct Kill(u32);
        impl Drop for Kill {
            fn drop(&mut self) {
                seagent_core::proc::kill_group(self.0 as i32, Duration::from_secs(2));
            }
        }
        let _child = Kill(pid);
        std::thread::sleep(Duration::from_secs(4));
        // Where the time goes: one grab (capture + compose), then JPEG encoding at two widths.
        let t = crate::browser_view::Target::Host;
        let mut gr = Grabber::default();
        let (mut g_ms, mut e_full, mut e_1280) = (vec![], vec![], vec![]);
        for _ in 0..8 {
            let t0 = Instant::now();
            let img = grab_for(&a, &t, &mut gr, 1920).unwrap();
            g_ms.push(t0.elapsed().as_millis());
            let t1 = Instant::now();
            let _ = to_jpeg(img.clone(), 3840, 85).unwrap();
            e_full.push(t1.elapsed().as_millis());
            let t2 = Instant::now();
            let _ = to_jpeg(img, 1280, 85).unwrap();
            e_1280.push(t2.elapsed().as_millis());
        }
        let med = |v: &mut Vec<u128>| {
            v.sort_unstable();
            v[v.len() / 2]
        };
        eprintln!("LIVE Bot Desktop stages (median of 8): grab {} ms, JPEG full size {} ms, JPEG at 1280 wide {} ms", med(&mut g_ms), med(&mut e_full), med(&mut e_1280));
        let srv = crate::server::start(a.clone()).unwrap();
        // End the timing run's capture worker before the stream starts its own.
        let _ = std::mem::take(&mut gr);
        let mut ws = connect(srv.local_addr(), "kind=desktop&target=host&fps=30&quality=85&maxWidth=1920", "live-admin-token");
        let h = next_text(&mut ws);
        assert_eq!(h["t"], "hello", "{h}");
        let (cpu0, t0) = (cpu_seconds_self(), Instant::now());
        let (mut upds, mut bytes, mut caps, mut meta, mut last_upd, mut comp) = (0u32, 0usize, vec![], Value::Null, 0u64, None::<image::RgbaImage>);
        while t0.elapsed() < Duration::from_secs(6) {
            match ws.recv() {
                Ok(Some(Message::Text(x))) => {
                    let v: Value = serde_json::from_str(&x).unwrap();
                    assert_ne!(v["t"], "nodisplay", "{v}");
                    if v["t"] == "frame" || v["t"] == "patch" {
                        meta = v;
                    }
                }
                Ok(Some(Message::Binary(j))) => {
                    bytes += j.len();
                    let pic = image::load_from_memory(&j).unwrap().to_rgba8();
                    if meta["t"] == "frame" {
                        comp = Some(pic);
                    } else if let Some(c) = comp.as_mut() {
                        image::imageops::replace(c, &pic, meta["x"].as_i64().unwrap_or(0), meta["y"].as_i64().unwrap_or(0));
                    }
                    let upd = meta["upd"].as_u64().unwrap_or(0);
                    if upd != last_upd {
                        upds += 1;
                        if let Some(c) = meta["capturedMs"].as_u64() {
                            caps.push(now_ms().saturating_sub(c));
                        }
                        last_upd = upd;
                    }
                }
                _ => {}
            }
        }
        let secs = t0.elapsed().as_secs_f64();
        let cpu = (cpu_seconds_self() - cpu0) / secs * 100.0;
        caps.sort_unstable();
        eprintln!(
            "LIVE Bot Desktop full-frame, busy browser window without CDP ({}): {upds} screen updates / {secs:.1} s = {:.1} fps; capture→receive p50 {} ms, p95 {} ms; {:.2} MB/s; server CPU {cpu:.0}%",
            std::env::consts::OS,
            f64::from(upds) / secs,
            caps.get(caps.len() / 2).copied().unwrap_or(0),
            caps.get(caps.len() * 95 / 100).copied().unwrap_or(0),
            bytes as f64 / 1e6 / secs,
        );
        if let Some(c) = comp {
            image::DynamicImage::ImageRgba8(c).to_rgb8().save(out.join(format!("live-bot-desktop-{}.jpg", std::env::consts::OS))).unwrap();
        }
        assert!(upds >= 10, "the desktop streamed: {upds} updates");
    }

    /// The Bot Desktop with the agent's own browser on it, streamed in patch mode (not run by
    /// default): `SEAGENT_REAL_TESTS=1 [SEAGENT_LIVE_OUT=<dir>] cargo test -p seagent-app
    /// real_live_bot_desktop_patched -- --ignored --nocapture`. The browser is launched by the
    /// manager onto the Bot Desktop (never made the visible desktop); a busy page of small text
    /// is measured at 30 and 60 fps, then an idle page.
    #[test]
    #[ignore]
    fn real_live_bot_desktop_patched() {
        if std::env::var("SEAGENT_REAL_TESTS").ok().as_deref() != Some("1") {
            eprintln!("skipping: set SEAGENT_REAL_TESTS=1 to run real-desktop cases");
            return;
        }
        let scratch = seagent_core::tmp::TempDir::new("seagent-live-patch-frames");
        let out = std::env::var_os("SEAGENT_LIVE_OUT").map(std::path::PathBuf::from).unwrap_or_else(|| scratch.path().to_path_buf());
        std::fs::create_dir_all(&out).unwrap();
        let home = seagent_core::tmp::TempDir::new("seagent-live-patch");
        let a = app(home.path());
        let data = home.path().join("data");
        let desk = seagent_browser::control::screen::Desktop::new(&data);
        #[cfg(windows)]
        if seagent_browser::control::screen_windows::desktop_names().iter().any(|n| n == "seagent-default") {
            eprintln!("skipping: a seagent Bot Desktop (seagent-default) already runs on this window station");
            return;
        }
        if let Err(e) = desk.start() {
            eprintln!("skipping: no Bot Desktop on this host: {e}");
            return;
        }
        struct StopDesk(seagent_browser::control::screen::Desktop);
        impl Drop for StopDesk {
            fn drop(&mut self) {
                self.0.stop();
            }
        }
        let _desk = StopDesk(desk);
        // The agent's browser, headed on the Bot Desktop (InPrivate: no signed-in account).
        let profile = format!("botlive{}", std::process::id());
        let cfg = seagent_browser::BrowserConfig { backend: "local".into(), enabled: toml::Value::Boolean(true), headless: false, default_profile: profile.clone(), extra_args: vec!["--inprivate".into(), "--incognito".into()], ..Default::default() };
        let env = seagent_browser::manager::Env { cfg, home: data.clone(), secrets: Arc::new(|s: &str| s.to_string()) };
        let key = format!("profile:{profile}");
        let b = seagent_browser::manager::global().browser(&env, &key).expect("the agent's browser on the Bot Desktop");
        struct Stop(String);
        impl Drop for Stop {
            fn drop(&mut self) {
                seagent_browser::manager::global().stop(&self.0);
            }
        }
        let _stop = Stop(key.clone());
        assert_eq!(b.info.lock().unwrap().get("bot_desktop"), Some(&Value::Bool(true)), "launched onto the Bot Desktop");
        let lorem = "The quick brown fox jumps over the lazy dog 0123456789 - pack my box with five dozen liquor jugs. ".repeat(2);
        let rows: String = (1..=50).map(|i| format!("<p style='margin:0;font:12px/1.35 Segoe UI,Arial,sans-serif'>{i:02}. {lorem}</p>")).collect();
        let busy = format!("<!doctype html><title>busy</title><body style='margin:8px;background:#fff;color:#111'><div id=bar style='height:6px;background:#c0362c;width:0'></div><h3 id=clk style='font:600 16px monospace;margin:4px 0'>t</h3>{rows}<script>let n=0;function f(){{n++;clk.textContent='Bot Desktop page - frame '+n+' - '+new Date().toISOString();bar.style.width=(n%600)/6+'%';requestAnimationFrame(f)}}f()</script>");
        let idle = format!("<!doctype html><title>idle</title><body style='margin:8px;background:#fff;color:#111'>{rows}");
        let url = |h: &str| format!("data:text/html;charset=utf-8,{}", seagent_net::urlencode(h));
        let tab = b.tabs(None).unwrap()[0]["targetId"].as_str().unwrap().to_string();
        let win = b.call("Browser.getWindowForTarget", json!({"targetId": tab})).unwrap();
        let _ = b.call("Browser.setWindowBounds", json!({"windowId": win["windowId"], "bounds": {"left": 0, "top": 0, "width": 1700, "height": 1040, "windowState": "normal"}}));
        b.page_call(&tab, "Page.navigate", json!({"url": url(&busy)})).unwrap();
        std::thread::sleep(Duration::from_secs(3));
        let srv = crate::server::start(a.clone()).unwrap();
        // Returns (fps, the base picture, the last patch and its header).
        let measure = |fps: u32, secs: u64, label: &str| -> (f64, Vec<u8>, (Value, Vec<u8>)) {
            let mut ws = connect(srv.local_addr(), &format!("kind=desktop&target=host&fps={fps}&quality=85&maxWidth=1920"), "live-admin-token");
            let h = next_text(&mut ws);
            assert_eq!(h["t"], "hello", "{h}");
            // Every header is paired with the binary after it, warm-up included.
            let (warm, total) = (Duration::from_millis(1500), Duration::from_millis(1500 + secs * 1000));
            let start = Instant::now();
            let (mut t0, mut cpu0, mut br0) = (None::<Instant>, 0.0, 0.0);
            let (mut patches, mut bases, mut bytes, mut lat, mut meta, mut base, mut patch, mut mode) = (0u32, 0u32, 0usize, vec![], Value::Null, vec![], (Value::Null, vec![]), String::new());
            while start.elapsed() < total {
                if t0.is_none() && start.elapsed() >= warm {
                    (t0, cpu0, br0) = (Some(Instant::now()), cpu_seconds_self(), cpu_seconds_matching(&profile));
                }
                match ws.recv() {
                    Ok(Some(Message::Text(x))) => {
                        let v: Value = serde_json::from_str(&x).unwrap();
                        if v["t"] == "frame" || v["t"] == "patch" {
                            meta = v;
                        } else if v["t"] == "stats" {
                            mode = v["mode"].as_str().unwrap_or("full").to_string();
                        }
                    }
                    Ok(Some(Message::Binary(j))) => {
                        let counting = t0.is_some();
                        if meta["t"] == "patch" {
                            if counting {
                                patches += 1;
                                bytes += j.len();
                                if let Some(c) = meta["capturedMs"].as_u64().filter(|c| *c > 0) {
                                    lat.push(now_ms().saturating_sub(c));
                                }
                            }
                            patch = (meta.clone(), j);
                        } else if meta["t"] == "frame" {
                            if counting {
                                bases += 1;
                                bytes += j.len();
                            }
                            base = j;
                        }
                        meta = Value::Null;
                    }
                    _ => {}
                }
            }
            let s = t0.map_or(1.0, |t| t.elapsed().as_secs_f64());
            let (cpu, br) = ((cpu_seconds_self() - cpu0) / s * 100.0, (cpu_seconds_matching(&profile) - br0) / s * 100.0);
            lat.sort_unstable();
            let pct = |p: usize| lat.get((lat.len() * p / 100).min(lat.len().saturating_sub(1))).copied().unwrap_or(0);
            let fps_real = f64::from(patches) / s;
            eprintln!("LIVE Bot Desktop patch mode ({label}, cap {fps}): {patches} page patches + {bases} base pictures in {s:.1} s = {fps_real:.1} fps; latency p50 {} ms, p95 {} ms; {:.2} MB/s; CPU server {cpu:.0}%, browser {br:.0}%; stats mode {mode}", pct(50), pct(95), bytes as f64 / 1e6 / s);
            (fps_real, base, patch)
        };
        let (f30, base, (pm, patch)) = measure(30, 10, "busy page");
        // What the console shows: the base picture with the page patch drawn at its place.
        let mut comp = image::load_from_memory(&base).expect("a base picture").to_rgba8();
        let page = image::load_from_memory(&patch).expect("a page patch").to_rgba8();
        let (px, py) = (pm["x"].as_i64().unwrap(), pm["y"].as_i64().unwrap());
        eprintln!("LIVE Bot Desktop composition: base {}x{}, page patch {}x{} at ({px}, {py})", comp.width(), comp.height(), page.width(), page.height());
        image::imageops::overlay(&mut comp, &page, px, py);
        image::DynamicImage::ImageRgba8(comp).to_rgb8().save(out.join("bot-desktop-patch-composed.jpg")).unwrap();
        std::fs::write(out.join("bot-desktop-patch-base.jpg"), &base).unwrap();
        let (f60, _, _) = measure(60, 6, "busy page");
        b.page_call(&tab, "Page.navigate", json!({"url": url(&idle)})).unwrap();
        std::thread::sleep(Duration::from_secs(2));
        let (idle_fps, _, _) = measure(30, 5, "idle page");
        assert!(f30 >= 27.0, "a busy page streams at the 30 fps cap: {f30:.1}");
        assert!(f60 > f30, "60 fps asked: {f60:.1}");
        assert!(idle_fps < 2.0, "an idle desktop sends (almost) nothing: {idle_fps:.1}");
    }

    /// A busy non-browser window on the Bot Desktop — a text editor scrolling text — streamed
    /// through the full-frame path at 1080p (not run by default): `SEAGENT_REAL_TESTS=1
    /// [SEAGENT_LIVE_OUT=<dir>] cargo test -p seagent-app real_live_bot_desktop_editor --
    /// --ignored --nocapture`. Windows: a WinForms editor on the isolated desktop (window
    /// tracker); Linux: xterm scrolling on the Xvnc Bot Desktop (RFB).
    #[test]
    #[ignore]
    fn real_live_bot_desktop_editor() {
        if std::env::var("SEAGENT_REAL_TESTS").ok().as_deref() != Some("1") {
            eprintln!("skipping: set SEAGENT_REAL_TESTS=1 to run real-desktop cases");
            return;
        }
        let scratch = seagent_core::tmp::TempDir::new("seagent-live-editor-frames");
        let out = std::env::var_os("SEAGENT_LIVE_OUT").map(std::path::PathBuf::from).unwrap_or_else(|| scratch.path().to_path_buf());
        std::fs::create_dir_all(&out).unwrap();
        let home = seagent_core::tmp::TempDir::new("seagent-live-editor");
        let a = app(home.path());
        let data = home.path().join("data");
        let desk = seagent_browser::control::screen::Desktop::new(&data);
        if let Err(e) = desk.start() {
            eprintln!("skipping: no Bot Desktop on this host: {e}");
            return;
        }
        struct StopDesk(seagent_browser::control::screen::Desktop);
        impl Drop for StopDesk {
            fn drop(&mut self) {
                self.0.stop();
            }
        }
        let _desk = StopDesk(desk);
        #[cfg(windows)]
        let pid = {
            let ps = "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; $f=New-Object Windows.Forms.Form; $f.Text='seagent editor'; $f.StartPosition='Manual'; $f.Left=40; $f.Top=30; $f.Width=1600; $f.Height=980; $t=New-Object Windows.Forms.TextBox; $t.Multiline=$true; $t.ScrollBars='Vertical'; $t.Dock='Fill'; $t.Font=New-Object Drawing.Font('Consolas',11); $f.Controls.Add($t); $script:n=0; $tm=New-Object Windows.Forms.Timer; $tm.Interval=15; $tm.Add_Tick({ $script:n++; $t.AppendText(('{0:D6}  the quick brown fox jumps over the lazy dog 0123456789 - pack my box with five dozen liquor jugs  {1}' -f $script:n, [DateTime]::Now.ToString('HH:mm:ss.fff')) + [Environment]::NewLine) }); $tm.Start(); [Windows.Forms.Application]::Run($f)";
            let q = seagent_browser::control::screen_windows::WinDesktop::new(&data, "default", "1440x900").qualified();
            let line = format!("powershell.exe -NoProfile -NonInteractive -Command \"{}\"", ps.replace('"', "\\\""));
            seagent_browser::control::screen_windows::spawn_on_desktop_flags(&q, &line, 0x0800_0000).unwrap()
        };
        #[cfg(not(windows))]
        let pid = {
            let env = seagent_browser::control::screen::Desktop::new(&data).published_env();
            match std::process::Command::new("xterm").args(["-geometry", "200x60+20+20", "-e", "sh", "-c", "i=0; while :; do i=$((i+1)); echo \"$i  the quick brown fox jumps over the lazy dog 0123456789 $(date +%T.%N)\"; sleep 0.015; done"]).envs(env).spawn() {
                Ok(c) => c.id(),
                Err(e) => {
                    eprintln!("skipping: no xterm on this host: {e}");
                    return;
                }
            }
        };
        struct Kill(u32);
        impl Drop for Kill {
            fn drop(&mut self) {
                seagent_core::proc::kill_group(self.0 as i32, Duration::from_secs(2));
                #[cfg(windows)]
                let _ = std::process::Command::new("taskkill").args(["/T", "/F", "/PID", &self.0.to_string()]).output();
            }
        }
        let _editor = Kill(pid);
        std::thread::sleep(Duration::from_secs(5));
        let srv = crate::server::start(a.clone()).unwrap();
        let mut ws = connect(srv.local_addr(), "kind=desktop&target=host&fps=30&quality=85&maxWidth=1920", "live-admin-token");
        assert_eq!(next_text(&mut ws)["t"], "hello");
        let (warm, total) = (Duration::from_millis(1500), Duration::from_millis(11_500));
        let start = Instant::now();
        let (mut t0, mut cpu0) = (None::<Instant>, 0.0);
        let (mut meta, mut comp, mut upds, mut bytes, mut lat, mut last_upd) = (Value::Null, None::<image::RgbaImage>, 0u32, 0usize, vec![], 0u64);
        while start.elapsed() < total {
            if t0.is_none() && start.elapsed() >= warm {
                (t0, cpu0) = (Some(Instant::now()), cpu_seconds_self());
            }
            match ws.recv() {
                Ok(Some(Message::Text(x))) => {
                    let v: Value = serde_json::from_str(&x).unwrap();
                    assert_ne!(v["t"], "nodisplay", "{v}");
                    if v["t"] == "frame" || v["t"] == "patch" {
                        meta = v;
                    }
                }
                Ok(Some(Message::Binary(j))) => {
                    let pic = image::load_from_memory(&j).unwrap().to_rgba8();
                    if meta["t"] == "frame" {
                        comp = Some(pic);
                    } else if let Some(c) = comp.as_mut() {
                        image::imageops::replace(c, &pic, meta["x"].as_i64().unwrap(), meta["y"].as_i64().unwrap());
                    }
                    let upd = meta["upd"].as_u64().unwrap_or(0);
                    if t0.is_some() {
                        bytes += j.len();
                        if upd != last_upd {
                            upds += 1;
                            if let Some(c) = meta["capturedMs"].as_u64() {
                                lat.push(now_ms().saturating_sub(c));
                            }
                        }
                    }
                    last_upd = upd;
                    meta = Value::Null;
                }
                _ => {}
            }
        }
        let s = t0.map_or(1.0, |t| t.elapsed().as_secs_f64());
        let cpu = (cpu_seconds_self() - cpu0) / s * 100.0;
        lat.sort_unstable();
        let pct = |p: usize| lat.get((lat.len() * p / 100).min(lat.len().saturating_sub(1))).copied().unwrap_or(0);
        let fps = f64::from(upds) / s;
        let size = comp.as_ref().map(|c| c.dimensions()).unwrap_or_default();
        eprintln!("LIVE Bot Desktop full-frame, busy editor ({}): {upds} screen updates in {s:.1} s = {fps:.1} fps; capture→receive p50 {} ms, p95 {} ms; {:.2} MB/s; server CPU {cpu:.0}%; screen {}x{}; {} encoders", std::env::consts::OS, pct(50), pct(95), bytes as f64 / 1e6 / s, size.0, size.1, crate::live_regions::encoders());
        if let Some(c) = comp {
            image::DynamicImage::ImageRgba8(c).to_rgb8().save(out.join(format!("bot-desktop-editor-{}.jpg", std::env::consts::OS))).unwrap();
        }
        assert!(fps >= 30.0, "a busy window streams at ≥ 30 fps: {fps:.1}");
    }

    /// Width × height of a baseline/progressive JPEG (its SOF marker).
    fn jpeg_size(j: &[u8]) -> Option<(u32, u32)> {
        let mut i = 2;
        while i + 9 < j.len() {
            if j[i] != 0xff {
                return None;
            }
            let (m, len) = (j[i + 1], usize::from(u16::from_be_bytes([j[i + 2], j[i + 3]])));
            if matches!(m, 0xc0..=0xc3) {
                return Some((u32::from(u16::from_be_bytes([j[i + 7], j[i + 8]])), u32::from(u16::from_be_bytes([j[i + 5], j[i + 6]]))));
            }
            i += 2 + len;
        }
        None
    }

    /// CPU seconds this process has used (test-only measurement; shells out to the OS tool).
    fn cpu_seconds_self() -> f64 {
        cpu_query(&format!("pid:{}", std::process::id()))
    }

    /// CPU seconds of every browser process whose command line names `needle` (the profile).
    fn cpu_seconds_matching(needle: &str) -> f64 {
        cpu_query(needle)
    }

    #[cfg(windows)]
    fn cpu_query(what: &str) -> f64 {
        let ps = match what.strip_prefix("pid:") {
            Some(pid) => format!("(Get-Process -Id {pid}).TotalProcessorTime.TotalSeconds"),
            None => format!("$t=0; Get-CimInstance Win32_Process | Where-Object {{ $_.CommandLine -like '*{what}*' -and $_.ProcessId -ne $PID }} | ForEach-Object {{ $t += ($_.KernelModeTime + $_.UserModeTime) / 1e7 }}; $t"),
        };
        let o = std::process::Command::new("powershell").args(["-NoProfile", "-Command", &ps]).output().unwrap();
        String::from_utf8_lossy(&o.stdout).trim().replace(',', ".").parse().unwrap_or(0.0)
    }

    #[cfg(not(windows))]
    fn cpu_query(what: &str) -> f64 {
        // `ps` cputime is [[dd-]hh:]mm:ss; sum it over the matching processes.
        let args: Vec<String> = match what.strip_prefix("pid:") {
            Some(pid) => vec!["-o".into(), "time=".into(), "-p".into(), pid.into()],
            None => vec!["-eo".into(), "time=,args=".into()],
        };
        let o = std::process::Command::new("ps").args(&args).output().unwrap();
        String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter(|l| what.starts_with("pid:") || (l.contains(what) && !l.contains(" ps ")))
            .filter_map(|l| l.split_whitespace().next())
            .map(|t| t.replace('-', ":").split(':').fold(0.0, |acc, x| acc * 60.0 + x.parse::<f64>().unwrap_or(0.0)))
            .sum()
    }

    struct Chunks(Vec<Vec<u8>>);
    impl seagent_core::exec::ExecChild for Chunks {
        fn pid(&self) -> Option<u32> {
            None
        }
        fn read(&mut self, buf: &mut [u8], _t: Duration) -> std::io::Result<usize> {
            if self.0.is_empty() {
                return Ok(0);
            }
            let c = self.0.remove(0);
            buf[..c.len()].copy_from_slice(&c);
            Ok(c.len())
        }
        fn write_stdin(&mut self, _d: &[u8]) -> std::io::Result<()> {
            Ok(())
        }
        fn close_stdin(&mut self) {}
        fn try_wait(&mut self) -> std::io::Result<Option<seagent_core::exec::ExitInfo>> {
            Ok(self.0.is_empty().then_some(seagent_core::exec::ExitInfo { code: Some(0), signal: None }))
        }
        fn kill(&mut self, _f: bool) {}
    }
}
