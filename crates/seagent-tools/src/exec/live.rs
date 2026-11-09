//! Live terminal of the agent's commands for the web console: every command the shell / job
//! tools start ([`super::spawn_tool`]) is wrapped in a [`Tee`] that copies its output, as it
//! arrives, to the console viewers watching that session. The same wrapper covers every
//! backend — the microVM (Firecracker, QEMU + WHPX / HVF, VirtualBox, vfkit), the OS sandbox
//! (bwrap, AppContainer, Seatbelt), containers, SSH, the in-process WASM interpreter — so
//! the terminal view is the substitute wherever no framebuffer exists.
//!
//! Costs nothing when nobody watches: [`watching`] is one relaxed atomic load per read and
//! nothing is copied, formatted or kept. Each viewer has a bounded queue
//! ([`QUEUE_BYTES`]); when a viewer falls behind, the oldest output is dropped and the viewer
//! is told how much (`Event::Gap`) — a command never blocks on a slow console.

use seagent_core::exec::{ExecChild, ExitInfo};
use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;

/// Output a viewer may have queued before the oldest is dropped.
pub const QUEUE_BYTES: usize = 512 * 1024;
/// The command line shown in a `Start` event is cut to this many characters.
const SCRIPT_CHARS: usize = 2000;

static WATCHERS: AtomicUsize = AtomicUsize::new(0);
static NEXT_CMD: AtomicU64 = AtomicU64::new(1);
/// Bumped by every new subscription: a running command re-announces itself to newcomers.
static GEN: AtomicU64 = AtomicU64::new(1);
static SUBS: Mutex<Vec<Weak<Sub>>> = Mutex::new(Vec::new());

/// Is any console watching any session's terminal?
#[inline]
pub fn watching() -> bool {
    WATCHERS.load(Ordering::Relaxed) > 0
}

/// One thing a terminal viewer sees.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Start { cmd: u64, session: String, backend: String, script: String },
    Out { cmd: u64, session: String, data: Vec<u8> },
    Exit { cmd: u64, session: String, code: Option<i32>, signal: Option<i32> },
    /// This viewer fell behind and `bytes` of output were dropped.
    Gap { bytes: u64 },
}

impl Event {
    fn session(&self) -> Option<&str> {
        match self {
            Event::Start { session, .. } | Event::Out { session, .. } | Event::Exit { session, .. } => Some(session),
            Event::Gap { .. } => None,
        }
    }
    fn size(&self) -> usize {
        match self {
            Event::Out { data, .. } => data.len(),
            Event::Start { script, .. } => script.len() + 64,
            _ => 64,
        }
    }
}

#[derive(Default)]
struct Queue {
    items: VecDeque<Event>,
    bytes: usize,
    dropped: u64,
}

struct Sub {
    /// `None` = every session.
    session: Option<String>,
    cap: usize,
    q: Mutex<Queue>,
    cv: Condvar,
}

impl Sub {
    fn push(&self, e: &Event) {
        if self.session.as_deref().is_some_and(|s| e.session() != Some(s)) {
            return;
        }
        let mut q = self.q.lock().unwrap();
        q.bytes += e.size();
        q.items.push_back(e.clone());
        // Drop the oldest output (never a Start/Exit marker) until the queue fits again.
        while q.bytes > self.cap {
            let Some(i) = q.items.iter().position(|x| matches!(x, Event::Out { .. })) else { break };
            if let Some(Event::Out { data, .. }) = q.items.remove(i) {
                q.bytes -= data.len();
                q.dropped += data.len() as u64;
            }
        }
        drop(q);
        self.cv.notify_all();
    }
}

/// A viewer's subscription; dropping it stops the copying (when it was the last one).
pub struct Subscription(Arc<Sub>);

/// Watch the terminal of `session` (`None` = all sessions).
pub fn subscribe(session: Option<&str>) -> Subscription {
    subscribe_with(session, QUEUE_BYTES)
}

/// [`subscribe`] with a custom queue bound (tests).
pub fn subscribe_with(session: Option<&str>, cap: usize) -> Subscription {
    let s = Arc::new(Sub { session: session.map(str::to_string), cap: cap.max(1024), q: Mutex::default(), cv: Condvar::new() });
    let mut subs = SUBS.lock().unwrap();
    subs.retain(|w| w.strong_count() > 0);
    subs.push(Arc::downgrade(&s));
    GEN.fetch_add(1, Ordering::SeqCst);
    WATCHERS.fetch_add(1, Ordering::SeqCst);
    Subscription(s)
}

impl Subscription {
    /// Everything queued, waiting at most `timeout` for the first item. A `Gap` comes first
    /// when output was dropped since the last call.
    pub fn next(&self, timeout: Duration) -> Vec<Event> {
        let mut q = self.0.q.lock().unwrap();
        if q.items.is_empty() && q.dropped == 0 {
            q = self.0.cv.wait_timeout(q, timeout).unwrap().0;
        }
        let mut out = Vec::with_capacity(q.items.len() + 1);
        if q.dropped > 0 {
            out.push(Event::Gap { bytes: std::mem::take(&mut q.dropped) });
        }
        out.extend(q.items.drain(..));
        q.bytes = 0;
        out
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        WATCHERS.fetch_sub(1, Ordering::SeqCst);
        SUBS.lock().unwrap().retain(|w| w.strong_count() > 0 && !std::ptr::eq(w.as_ptr(), Arc::as_ptr(&self.0)));
    }
}

fn publish(e: Event) {
    let subs: Vec<Arc<Sub>> = SUBS.lock().unwrap().iter().filter_map(Weak::upgrade).collect();
    for s in subs {
        s.push(&e);
    }
}

/// A command whose output also goes to the console's live terminal while someone watches.
pub struct Tee {
    inner: Box<dyn ExecChild>,
    cmd: u64,
    session: String,
    backend: String,
    script: String,
    /// The subscription generation the `Start` marker last went out for (0 = never): a viewer
    /// that joins mid-command still gets one before the output (viewers dedupe by `cmd`).
    announced: u64,
    exited: bool,
}

/// Wrap `child` for the live terminal.
pub fn tee(child: Box<dyn ExecChild>, session: &str, backend: &str, script: &str) -> Box<dyn ExecChild> {
    let mut t = Tee { inner: child, cmd: NEXT_CMD.fetch_add(1, Ordering::Relaxed), session: session.to_string(), backend: backend.to_string(), script: script.chars().take(SCRIPT_CHARS).collect(), announced: 0, exited: false };
    if watching() {
        t.announce();
    }
    Box::new(t)
}

impl Tee {
    fn announce(&mut self) {
        let g = GEN.load(Ordering::SeqCst);
        if self.announced != g {
            self.announced = g;
            publish(Event::Start { cmd: self.cmd, session: self.session.clone(), backend: self.backend.clone(), script: self.script.clone() });
        }
    }
}

impl ExecChild for Tee {
    fn pid(&self) -> Option<u32> {
        self.inner.pid()
    }
    fn read(&mut self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        let n = self.inner.read(buf, timeout)?;
        if n > 0 && watching() {
            self.announce();
            publish(Event::Out { cmd: self.cmd, session: self.session.clone(), data: buf[..n].to_vec() });
        }
        Ok(n)
    }
    fn write_stdin(&mut self, data: &[u8]) -> io::Result<()> {
        self.inner.write_stdin(data)
    }
    fn close_stdin(&mut self) {
        self.inner.close_stdin()
    }
    fn try_wait(&mut self) -> io::Result<Option<ExitInfo>> {
        let r = self.inner.try_wait()?;
        if let Some(st) = &r {
            if !self.exited && self.announced != 0 && watching() {
                publish(Event::Exit { cmd: self.cmd, session: self.session.clone(), code: st.code, signal: st.signal });
            }
            self.exited = true;
        }
        Ok(r)
    }
    fn kill(&mut self, force: bool) {
        self.inner.kill(force)
    }
    fn resize(&mut self, rows: u16, cols: u16) -> io::Result<()> {
        self.inner.resize(rows, cols)
    }
    fn is_pty(&self) -> bool {
        self.inner.is_pty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A child that yields scripted chunks, then exits 3.
    struct Script(VecDeque<Vec<u8>>);
    impl ExecChild for Script {
        fn pid(&self) -> Option<u32> {
            Some(42)
        }
        fn read(&mut self, buf: &mut [u8], _t: Duration) -> io::Result<usize> {
            let Some(c) = self.0.pop_front() else { return Ok(0) };
            buf[..c.len()].copy_from_slice(&c);
            Ok(c.len())
        }
        fn write_stdin(&mut self, _d: &[u8]) -> io::Result<()> {
            Ok(())
        }
        fn close_stdin(&mut self) {}
        fn try_wait(&mut self) -> io::Result<Option<ExitInfo>> {
            Ok(self.0.is_empty().then_some(ExitInfo { code: Some(3), signal: None }))
        }
        fn kill(&mut self, _f: bool) {}
    }

    fn child(chunks: &[&[u8]]) -> Box<dyn ExecChild> {
        Box::new(Script(chunks.iter().map(|c| c.to_vec()).collect()))
    }

    fn run(c: &mut Box<dyn ExecChild>) -> Vec<u8> {
        let mut out = vec![];
        let mut buf = [0u8; 1024];
        while let Ok(n) = c.read(&mut buf, Duration::ZERO) {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert!(c.try_wait().unwrap().is_some());
        out
    }

    // One test owns the global hub (the counters are process-wide).
    #[test]
    fn tee_streams_to_watchers_only_and_drops_the_oldest_for_slow_ones() {
        // Nobody watches: output is untouched, nothing is queued anywhere.
        let mut c = tee(child(&[b"a", b"b"]), "lvt-quiet", "local", "echo ab");
        assert_eq!(run(&mut c), b"ab");
        assert_eq!(c.pid(), Some(42));

        let all = subscribe(None);
        let mine = subscribe(Some("lvt-1"));
        assert!(watching());
        let mut c = tee(child(&[b"hello ", b"world\n"]), "lvt-1", "vm:firecracker", "echo hello world");
        let mut other = tee(child(&[b"x"]), "lvt-2", "bwrap", "echo x");
        assert_eq!(run(&mut c), b"hello world\n", "the command's own output is unchanged");
        run(&mut other);
        let ev = mine.next(Duration::from_secs(1));
        assert!(matches!(&ev[0], Event::Start { session, backend, script, .. } if session == "lvt-1" && backend == "vm:firecracker" && script == "echo hello world"), "{ev:?}");
        let text: Vec<u8> = ev.iter().filter_map(|e| if let Event::Out { data, .. } = e { Some(data.clone()) } else { None }).flatten().collect();
        assert_eq!(text, b"hello world\n");
        assert!(matches!(ev.last(), Some(Event::Exit { code: Some(3), .. })), "{ev:?}");
        assert!(ev.iter().all(|e| e.session() == Some("lvt-1")), "only the watched session");
        let ev = all.next(Duration::from_secs(1));
        assert!(ev.iter().any(|e| e.session() == Some("lvt-2")) && ev.iter().any(|e| e.session() == Some("lvt-1")));
        drop(all);

        // A slow viewer: bounded queue, oldest output dropped, the gap reported, markers kept.
        let slow = subscribe_with(Some("lvt-3"), 1024);
        let chunk = vec![b'z'; 400];
        let chunks: Vec<&[u8]> = (0..10).map(|_| chunk.as_slice()).collect();
        let mut c = tee(child(&chunks), "lvt-3", "local", "yes z");
        run(&mut c);
        let ev = slow.next(Duration::from_secs(1));
        let Event::Gap { bytes } = ev[0] else { panic!("{ev:?}") };
        let kept: usize = ev.iter().map(|e| if let Event::Out { data, .. } = e { data.len() } else { 0 }).sum();
        assert_eq!(bytes as usize + kept, 4000, "every byte is either delivered or counted as dropped");
        assert!(kept <= 1024);
        assert!(ev.iter().any(|e| matches!(e, Event::Start { .. })) && ev.iter().any(|e| matches!(e, Event::Exit { .. })));
        assert!(slow.next(Duration::from_millis(10)).is_empty());

        // A viewer that joins mid-command still gets a Start marker before the output.
        let mut c = tee(child(&[b"1", b"2"]), "lvt-4", "local", "seq 2");
        drop(mine);
        drop(slow);
        assert!(!watching(), "the last viewer left");
        let mut buf = [0u8; 8];
        c.read(&mut buf, Duration::ZERO).unwrap();
        let late = subscribe(Some("lvt-4"));
        run(&mut c);
        let ev = late.next(Duration::from_secs(1));
        assert!(matches!(&ev[..], [Event::Start { .. }, Event::Out { data, .. }, Event::Exit { .. }] if data == b"2"), "{ev:?}");
        drop(late);
        assert!(!watching());
    }
}
