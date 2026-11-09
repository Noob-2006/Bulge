//! Real-time live view for the web console: `GET /view/live` (WebSocket) streams what the
//! agent is doing, as it happens, instead of the UI polling `view.*.frame`.
//!
//! `?kind=` picks the stream; the other query parameters are the `view.*` ones:
//!
//! - `browser` (`session`, `key`, `targetId`, `maxWidth`, `quality`, `fps`): CDP
//!   `Page.startScreencast` JPEG frames of the tab, ack-paced (`seagent_browser::live`). A
//!   still page sends nothing; a slow socket slows Chrome down instead of queueing.
//! - `desktop` (`target` = `host` | `vm:<name>`, `maxWidth`, `quality`, `fps`): the Bot Desktop
//!   (Linux: the Xvnc display; Windows: a GDI grab of the CreateDesktopW desktop, or the
//!   primary screen; macOS: the login session) or a desktop VM (QMP `screendump`), re-encoded
//!   as JPEG, sent only when the picture changed, at an adaptive rate ([`Pace`]). A target
//!   without a display says `{"t":"nodisplay"}` and the console shows the terminal instead.
//! - `terminal` (`session`): the agent's commands as they run — script, output, exit — from
//!   every exec backend, the microVM included (`seagent_tools::exec::live`). Secrets are
//!   redacted (`Vault::redact`) on whole lines.
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

/// Adaptive pacing of polled frame sources (desktops): never faster than the fps cap, never
/// more than half the time spent capturing, and backing off (to 1 s) while nothing changes.
#[derive(Debug, Clone, PartialEq)]
pub struct Pace {
    pub min: Duration,
    pub max: Duration,
    pub interval: Duration,
}

impl Pace {
    pub fn new(fps: u32) -> Pace {
        let min = Duration::from_millis(1000 / u64::from(fps.clamp(1, 15)));
        Pace { min, max: Duration::from_secs(1).max(min), interval: min }
    }
    /// The wait before the next capture, given how long this one took and whether it changed.
    pub fn after(&mut self, took: Duration, changed: bool) -> Duration {
        let floor = self.min.max(took * 2);
        self.interval = if changed { floor } else { (self.interval.max(floor) * 3 / 2).min(self.max.max(floor)) };
        self.interval.saturating_sub(took)
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
        let v = json!({"t": "stats", "fps": (f64::from(self.frames) / dt * 10.0).round() / 10.0, "kbps": (self.bytes as f64 * 8.0 / 1000.0 / dt).round(), "latencyMs": (self.latency_n > 0).then(|| self.latency_ms / u64::from(self.latency_n))});
        *self = Stats { since: Some(Instant::now()), ..Default::default() };
        Some(v)
    }
}

fn now_ms() -> u64 {
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
        let _ = sock.set_read_timeout(Some(Duration::from_millis(15)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(10)));
        let ws = match &proto {
            Some(pr) => crate::server::accept_with_protocol(sock, &head, rest, pr),
            None => WebSocket::accept(sock, &head, rest),
        };
        let Ok(mut ws) = ws else { return };
        ws.set_max_message(64 * 1024);
        let mut link = Link { ws, app, p, checked: Instant::now(), may_input, kind, params, input_to: Value::Null };
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
    let o = live::Opts { max_width: num(&l.params, "maxWidth", 1280), max_height: num(&l.params, "maxHeight", 1280), quality: num(&l.params, "quality", 60).min(100) as u8, fps: num(&l.params, "fps", 15) }.clamped();
    l.text(&json!({"t": "hello", "kind": "browser", "key": b.key, "targetId": target, "input": l.may_input, "fps": o.fps, "quality": o.quality}))?;
    // First paint at once (a still page may not repaint for a long time).
    if let Ok(f) = view::capture(&b, &target, o.max_width, o.quality) {
        let meta = json!({"t": "frame", "seq": 0, "mime": f.mime, "bytes": f.data.len(), "cssWidth": f.css_width, "cssHeight": f.css_height, "url": f.url, "title": f.title, "sentMs": now_ms()});
        l.frame(&meta, &f.data)?;
    }
    let mut v = live::watch(&b, &target, o).map_err(Some)?;
    let mut st = Stats::default();
    loop {
        l.poll()?;
        if let Some(f) = v.next(Duration::from_millis(60)) {
            let (url, title) = v.page_info();
            let sent = now_ms();
            let mut meta = f.meta();
            meta["url"] = url.into();
            meta["title"] = title.into();
            meta["sentMs"] = sent.into();
            let lat = (f.captured_ms > 0).then(|| sent.saturating_sub(f.captured_ms));
            l.frame(&meta, &f.data)?;
            st.sent(f.data.len(), lat);
        } else if v.ended() {
            return l.text(&json!({"t": "end", "reason": "the tab closed or the browser stopped"}));
        }
        if let Some(r) = st.report() {
            l.text(&r)?;
        }
    }
}

// ── desktop ──

fn fnv(b: &[u8]) -> u64 {
    b.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, x| (h ^ u64::from(*x)).wrapping_mul(0x0100_0000_01b3))
}

/// Downscale to `max_w` and encode as JPEG.
pub fn to_jpeg(img: image::DynamicImage, max_w: u32, quality: u8) -> Result<(Vec<u8>, u32, u32), String> {
    let img = if img.width() > max_w { img.thumbnail(max_w, u32::MAX) } else { img };
    let rgb = img.to_rgb8();
    let mut out = Vec::with_capacity(rgb.len() / 8);
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, quality).encode(rgb.as_raw(), rgb.width(), rgb.height(), image::ExtendedColorType::Rgb8).map_err(|e| e.to_string())?;
    Ok((out, rgb.width(), rgb.height()))
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
    let (max_w, quality, fps) = (num(&l.params, "maxWidth", 1600).clamp(320, 2560), num(&l.params, "quality", 60).clamp(20, 90) as u8, num(&l.params, "fps", 5));
    l.text(&json!({"t": "hello", "kind": "desktop", "target": t.id(), "input": l.may_input, "fps": fps.clamp(1, 15)}))?;
    let app = l.app.clone();
    desktop_loop(l, &t.id(), (max_w, quality, fps), &mut || grab(&app, &t))
}

/// The desktop stream over any frame source: changed pictures only, paced by [`Pace`]; a
/// source without a picture sends `nodisplay` once and is retried every 2 s.
fn desktop_loop(l: &mut Link, id: &str, (max_w, quality, fps): (u32, u8, u32), grab: &mut dyn FnMut() -> Result<image::DynamicImage, String>) -> Flow {
    let mut pace = Pace::new(fps);
    let mut last = 0u64;
    let mut seq = 0u64;
    let mut dark = false;
    let mut st = Stats::default();
    loop {
        l.poll()?;
        let t0 = Instant::now();
        let wait = match grab() {
            Ok(img) => {
                dark = false;
                let h = fnv(img.as_bytes());
                if h == last {
                    pace.after(t0.elapsed(), false)
                } else {
                    last = h;
                    let (w0, h0) = (img.width(), img.height());
                    let (jpeg, w, hh) = to_jpeg(img, max_w, quality).map_err(Some)?;
                    seq += 1;
                    let meta = json!({"t": "frame", "seq": seq, "mime": "image/jpeg", "bytes": jpeg.len(), "width": w0, "height": h0, "frameWidth": w, "frameHeight": hh, "sentMs": now_ms()});
                    let took = t0.elapsed();
                    l.frame(&meta, &jpeg)?;
                    st.sent(jpeg.len(), Some(took.as_millis() as u64));
                    pace.after(took, true)
                }
            }
            Err(e) => {
                // No display here (a headless server without a Bot Desktop, a stopped VM): the
                // console shows the live terminal instead; keep looking every 2 s.
                if !dark {
                    dark = true;
                    l.text(&json!({"t": "nodisplay", "target": id, "reason": e, "fallback": "terminal"}))?;
                }
                Duration::from_secs(2)
            }
        };
        if let Some(r) = st.report() {
            l.text(&r)?;
        }
        let until = Instant::now() + wait;
        while Instant::now() < until {
            l.poll()?;
            std::thread::sleep(until.saturating_duration_since(Instant::now()).min(Duration::from_millis(25)));
        }
    }
}

// ── terminal ──

/// Line-buffered, redacted text of one command's output (a secret split across two reads is
/// still caught; a partial line is flushed after [`LineBuf::FLUSH`]).
#[derive(Default)]
pub struct LineBuf {
    pending: Vec<u8>,
    since: Option<Instant>,
}

impl LineBuf {
    pub const FLUSH: Duration = Duration::from_millis(150);

    pub fn push(&mut self, b: &[u8]) {
        if self.pending.is_empty() {
            self.since = Some(Instant::now());
        }
        self.pending.extend_from_slice(b);
    }

    /// The text ready to show: complete lines, or everything once it waited `FLUSH` (or grew
    /// past 16 KiB) — never splitting a UTF-8 character.
    pub fn take(&mut self, force: bool) -> Option<String> {
        if self.pending.is_empty() {
            return None;
        }
        let old = force || self.since.is_some_and(|t| t.elapsed() >= Self::FLUSH) || self.pending.len() > 16 * 1024;
        let cut = if old {
            match std::str::from_utf8(&self.pending) {
                Ok(_) => self.pending.len(),
                Err(e) if e.error_len().is_none() && !force => e.valid_up_to(),
                Err(_) => self.pending.len(),
            }
        } else {
            self.pending.iter().rposition(|c| *c == b'\n').map_or(0, |i| i + 1)
        };
        if cut == 0 {
            return None;
        }
        let rest = self.pending.split_off(cut);
        let text = String::from_utf8_lossy(&std::mem::replace(&mut self.pending, rest)).into_owned();
        self.since = (!self.pending.is_empty()).then(Instant::now);
        Some(text)
    }
}

fn terminal(l: &mut Link) -> Flow {
    use seagent_tools::exec::live::{self, Event};
    let session = s(&l.params, "session").map(str::to_string);
    let sub = live::subscribe(session.as_deref());
    l.text(&json!({"t": "hello", "kind": "terminal", "session": session}))?;
    let vault = l.app.d.k.vault.clone();
    let mut bufs: std::collections::BTreeMap<u64, (String, LineBuf)> = Default::default();
    loop {
        l.poll()?;
        let mut out = vec![];
        for e in sub.next(Duration::from_millis(50)) {
            match e {
                Event::Start { cmd, session, backend, script } => out.push(json!({"e": "start", "cmd": cmd, "session": session, "backend": backend, "script": vault.redact(&script)})),
                Event::Out { cmd, session, data } => bufs.entry(cmd).or_insert_with(|| (session, LineBuf::default())).1.push(&data),
                Event::Exit { cmd, session, code, signal } => {
                    if let Some((_, mut b)) = bufs.remove(&cmd) {
                        if let Some(t) = b.take(true) {
                            out.push(json!({"e": "out", "cmd": cmd, "session": session, "data": vault.redact(&t)}));
                        }
                    }
                    out.push(json!({"e": "exit", "cmd": cmd, "session": session, "code": code, "signal": signal}));
                }
                Event::Gap { bytes } => out.push(json!({"e": "gap", "bytes": bytes})),
            }
        }
        for (cmd, (session, b)) in bufs.iter_mut() {
            if let Some(t) = b.take(false) {
                out.push(json!({"e": "out", "cmd": cmd, "session": session, "data": vault.redact(&t)}));
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
    fn pace_caps_fps_backs_off_when_still_and_leaves_half_the_time_idle() {
        let mut p = Pace::new(5);
        assert_eq!(p.min, Duration::from_millis(200));
        assert_eq!(p.after(Duration::from_millis(50), true), Duration::from_millis(150), "fps cap: 200 ms per frame");
        // Nothing changes: back off ×1.5 up to 1 s.
        let waits: Vec<u128> = (0..6).map(|_| p.after(Duration::ZERO, false).as_millis()).collect();
        assert_eq!(waits, [300, 450, 675, 1000, 1000, 1000]);
        assert_eq!(p.after(Duration::ZERO, true), Duration::from_millis(200), "a change resets the rate");
        // A capture that takes 400 ms: at most every 800 ms (≤ 50 % of the time capturing).
        assert_eq!(p.after(Duration::from_millis(400), true), Duration::from_millis(400));
        assert_eq!(Pace::new(1000).min, Duration::from_millis(66), "capped at 15 fps");
    }

    #[test]
    fn line_buffer_keeps_lines_and_characters_whole() {
        let mut b = LineBuf::default();
        b.push(b"tok=s3c");
        assert_eq!(b.take(false), None, "a partial line waits (a secret is redacted whole)");
        b.push(b"r3t\nnext");
        assert_eq!(b.take(false).as_deref(), Some("tok=s3cr3t\n"));
        assert_eq!(b.take(true).as_deref(), Some("next"));
        // "你" is three bytes: a flush never cuts it in half.
        b.push(&"a你".as_bytes()[..2]);
        b.since = Some(Instant::now() - LineBuf::FLUSH);
        assert_eq!(b.take(false).as_deref(), Some("a"));
        b.push(&"你".as_bytes()[1..]);
        assert_eq!(b.take(true).as_deref(), Some("你"));
        assert_eq!(b.take(true), None);
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
        let srv = crate::server::start(app(&home)).unwrap();
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
        let mut ws = connect(addr, "kind=terminal&session=lvt-app", "live-ro-token");
        assert_eq!(next_text(&mut ws)["t"], "hello");
        let mut child = seagent_tools::exec::live::tee(Box::new(Chunks(vec![b"building...\n".to_vec(), b"done\n".to_vec()])), "lvt-app", "vm", "make all");
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
        assert_eq!(text, "building...\ndone\n");
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

    /// The desktop stream over a scripted source: only changed pictures go out (JPEG, scaled),
    /// a missing display says `nodisplay` once, and the loop ends when the viewer leaves. Same
    /// code path on every OS (the per-OS part is only where `grab` gets its pixels).
    #[test]
    fn desktop_stream_sends_changes_only_and_reports_a_missing_display() {
        let home = seagent_core::tmp::scratch_path(format!("seagent-live-desk-{}-{}", std::process::id(), seagent_net::crypto::random_token(4)));
        let a = app(&home);
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let srv = std::thread::spawn(move || {
            let (mut sock, _) = l.accept().unwrap();
            let (head, rest) = seagent_net::ws::read_head(&mut sock, 1 << 16).unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(15))).unwrap();
            let ws = WebSocket::accept(sock, &head, rest).unwrap();
            let p = Principal { kind: "token".into(), name: "t".into(), access: crate::identity::Access::Scope(crate::exposure::Scope::Read), ip: String::new(), tenant: Default::default() };
            let mut link = Link { ws, app: a, p, checked: Instant::now(), may_input: false, kind: Kind::Desktop, params: json!({}), input_to: json!({"target": "host"}) };
            let px = |c: u8| image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(1280, 800, image::Rgba([c, c, c, 255])));
            let mut n = 0;
            let mut src = move || {
                n += 1;
                match n {
                    1..=3 => Ok(px(10)),
                    4 => Ok(px(200)),
                    5 => Err("no display: the Bot Desktop is not running".to_string()),
                    6 => Err("still none".to_string()),
                    _ => Ok(px(90)),
                }
            };
            desktop_loop(&mut link, "host", (640, 50, 15), &mut src)
        });
        let (mut ws, _) = WebSocket::connect(&format!("ws://{addr}/"), &[], Duration::from_secs(5)).unwrap();
        ws.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let mut got = vec![];
        let t0 = Instant::now();
        while got.len() < 7 && t0.elapsed() < Duration::from_secs(20) {
            match ws.recv() {
                Ok(Some(Message::Text(t))) => {
                    let v: Value = serde_json::from_str(&t).unwrap();
                    if v["t"] != "stats" {
                        got.push(v);
                    }
                }
                Ok(Some(Message::Binary(b))) => got.push(json!({"jpeg": b.len(), "soi": b[..2] == [0xff, 0xd8]})),
                _ => {}
            }
        }
        let kinds: Vec<String> = got.iter().map(|v| v["t"].as_str().map_or("jpeg".into(), str::to_string)).collect();
        assert_eq!(kinds, ["frame", "jpeg", "frame", "jpeg", "nodisplay", "frame", "jpeg"], "{got:?}");
        assert_eq!((got[0]["width"].as_u64(), got[0]["frameWidth"].as_u64(), got[0]["frameHeight"].as_u64()), (Some(1280), Some(640), Some(400)), "scaled to maxWidth");
        assert_eq!(got[1]["soi"], true);
        assert_eq!((got[0]["seq"].as_u64(), got[2]["seq"].as_u64()), (Some(1), Some(2)), "three identical captures: one frame");
        assert!(got[4]["reason"].as_str().unwrap().contains("no display") && got[4]["fallback"] == "terminal");
        let _ = ws.send(&Message::Close(None));
        drop(ws);
        assert_eq!(srv.join().unwrap(), Err(None), "the loop ends when the viewer leaves");
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Real headless Chromium, end to end through the console route (not run by default):
    /// `SEAGENT_REAL_TESTS=1 [SEAGENT_LIVE_OUT=<dir>] cargo test -p seagent-app real_live_browser -- --ignored --nocapture`.
    /// An animated page streams at the fps cap, frames are real JPEGs, a viewer holding the
    /// lease clicks through the stream, and a few frames are saved to `SEAGENT_LIVE_OUT`.
    #[test]
    #[ignore]
    fn real_live_browser_stream() {
        if std::env::var("SEAGENT_REAL_TESTS").ok().as_deref() != Some("1") {
            eprintln!("skipping: set SEAGENT_REAL_TESTS=1 to run real-browser cases");
            return;
        }
        let out = std::env::var_os("SEAGENT_LIVE_OUT").map(std::path::PathBuf::from).unwrap_or_else(|| std::env::temp_dir().join("seagent-live-frames"));
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
        let page = "data:text/html,<body style='margin:0;background:%23222'><canvas id=c width=1000 height=600></canvas><script>let n=0;const x=c.getContext('2d');function f(){n++;x.fillStyle='hsl('+(n*3%25360)+',70%25,45%25)';x.fillRect(0,0,1000,600);x.fillStyle='%23fff';x.font='bold 72px sans-serif';x.fillText('seagent live '+n,40,140);x.fillText(document.title,40,260);requestAnimationFrame(f)}f();onclick=e=>{document.title='clicked at '+e.clientX+','+e.clientY}</script>";
        let t = b.new_tab(page, None).unwrap();
        let srv = crate::server::start(a.clone()).unwrap();
        let addr = srv.local_addr();
        let q = |fps: u32| format!("kind=browser&key={}&targetId={t}&fps={fps}&quality=60&maxWidth=1000", seagent_net::urlencode(&key));
        // ① 15 fps cap over 4 s, frame dump, capture-to-receive latency.
        let mut ws = connect(addr, &q(15), "live-admin-token");
        assert_eq!(next_text(&mut ws)["t"], "hello");
        let (mut frames, mut lat, mut meta, mut first) = (0u32, vec![], Value::Null, None::<Instant>);
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(4) {
            match ws.recv() {
                Ok(Some(Message::Text(x))) => meta = serde_json::from_str(&x).unwrap(),
                Ok(Some(Message::Binary(jpg))) if meta["t"] == "frame" => {
                    assert_eq!(&jpg[..2], &[0xff, 0xd8], "a JPEG");
                    assert_eq!(meta["bytes"].as_u64(), Some(jpg.len() as u64));
                    if meta["seq"].as_u64() == Some(0) {
                        std::fs::write(out.join("live-00-first-paint.jpg"), &jpg).unwrap();
                        continue;
                    }
                    first.get_or_insert_with(Instant::now);
                    frames += 1;
                    if let Some(c) = meta["capturedMs"].as_u64().filter(|c| *c > 0) {
                        lat.push(now_ms().saturating_sub(c));
                    }
                    if [1, 10, 30].contains(&frames) {
                        std::fs::write(out.join(format!("live-{frames:02}.jpg")), &jpg).unwrap();
                    }
                }
                _ => {}
            }
        }
        let secs = first.map_or(1.0, |f| f.elapsed().as_secs_f64());
        let fps = f64::from(frames) / secs;
        lat.sort_unstable();
        let p50 = lat.get(lat.len() / 2).copied().unwrap_or(0);
        let p95 = lat.get(lat.len() * 95 / 100).copied().unwrap_or(0);
        eprintln!("LIVE browser: {frames} frames in {secs:.2}s = {fps:.1} fps (cap 15); capture→receive latency p50 {p50} ms, p95 {p95} ms; frames in {}", out.display());
        assert!(frames >= 20, "an animated page streams: {frames} frames");
        assert!(fps <= 17.0, "the 15 fps cap holds: {fps:.1}");
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
        // ③ a lower cap is honoured by the ack pacing.
        let mut ws = connect(addr, &q(5), "live-admin-token");
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
        for needle in ["/view/live?", "seagent.live", "seagent.token.", "kind: 'terminal'", "kind: 'browser'", "kind: 'desktop'", "lvPollFrame"] {
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
