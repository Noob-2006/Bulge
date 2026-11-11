//! Desktop: the app owns the local daemon it started (or found) at boot, so it watches it.
//!
//! Every [`Policy::poll`] the App Server's `GET /health` is checked. When it stops answering —
//! the setup wizard's "finish" restarts the daemon with the new configuration, the tray's
//! "Restart service", a crash — the window shows a short "restarting…" screen (the app's own
//! splash, never the WebView's "127.0.0.1 refused the connection"), the daemon's own restart
//! helper gets [`Policy::grace`] to bring it back, and after that the app runs
//! `seagent daemon start` itself (again every [`Policy::retry`]; `daemon start` serialises with
//! the helper, so there is never a second daemon). As soon as it answers again the window goes
//! back to the wizard or the console with a fresh login. After [`Policy::give_up`] the splash
//! shows the error with Retry / Copy details, while the watch goes on.
//!
//! The decision is the pure [`Watch`] state machine; [`run`] drives it against a [`Host`]
//! (the Tauri app in `boot.rs`, a fake in the tests), so all of it is tested without a window.

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy)]
pub struct Policy {
    pub poll: Duration,
    /// Down this long → the "restarting…" screen (a blip shorter than this is not shown).
    pub show_after: Duration,
    /// Down this long → the app starts the daemon itself.
    pub grace: Duration,
    /// Between two starts of our own.
    pub retry: Duration,
    /// Down this long → the error screen (the watch and the retries go on).
    pub give_up: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { poll: Duration::from_millis(700), show_after: Duration::from_millis(1200), grace: Duration::from_secs(6), retry: Duration::from_secs(20), give_up: Duration::from_secs(120) }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    ShowRestarting,
    Start,
    Reopen,
    GiveUp,
}

#[derive(Debug)]
pub struct Watch {
    p: Policy,
    down_since: Option<Instant>,
    shown: bool,
    last_start: Option<Instant>,
    gave_up: bool,
}

impl Watch {
    pub fn new(p: Policy) -> Watch {
        Watch { p, down_since: None, shown: false, last_start: None, gave_up: false }
    }

    /// One health observation at `now` → what to do.
    pub fn step(&mut self, healthy: bool, now: Instant) -> Vec<Action> {
        if healthy {
            let was_shown = std::mem::take(&mut self.shown) || std::mem::take(&mut self.gave_up);
            self.down_since = None;
            self.last_start = None;
            self.gave_up = false;
            // Only a window that left the page needs to go back; a blip it never noticed doesn't.
            return if was_shown { vec![Action::Reopen] } else { vec![] };
        }
        let since = *self.down_since.get_or_insert(now);
        let down = now.saturating_duration_since(since);
        let mut out = vec![];
        if !self.shown && down >= self.p.show_after {
            self.shown = true;
            out.push(Action::ShowRestarting);
        }
        if down >= self.p.grace && !self.last_start.is_some_and(|t| now.saturating_duration_since(t) < self.p.retry) {
            self.last_start = Some(now);
            out.push(Action::Start);
        }
        if !self.gave_up && down >= self.p.give_up {
            self.gave_up = true;
            out.push(Action::GiveUp);
        }
        out
    }
}

/// What the supervisor acts on.
pub trait Host {
    fn healthy(&mut self) -> bool;
    fn show_restarting(&mut self);
    fn start_daemon(&mut self) -> Result<(), String>;
    /// Back to the wizard (setup pending) or the console.
    fn reopen(&mut self);
    fn give_up(&mut self, why: String);
    /// The app is quitting / stopping the agent on purpose: stop watching.
    fn stopped(&self) -> bool;
    fn log(&mut self, line: String);
}

/// Watch until [`Host::stopped`].
pub fn run(h: &mut dyn Host, p: Policy) {
    let mut w = Watch::new(p);
    let mut last_err = String::new();
    while !h.stopped() {
        let ok = h.healthy();
        if h.stopped() {
            return;
        }
        for a in w.step(ok, Instant::now()) {
            match a {
                Action::ShowRestarting => {
                    h.log("supervisor: the agent stopped answering; waiting for it to come back".into());
                    h.show_restarting();
                }
                Action::Start => {
                    h.log("supervisor: starting the agent (seagent daemon start)".into());
                    if let Err(e) = h.start_daemon() {
                        h.log(format!("supervisor: daemon start: {e}"));
                        last_err = e;
                    }
                }
                Action::Reopen => {
                    h.log("supervisor: the agent answers again; reopening the console".into());
                    h.reopen();
                }
                Action::GiveUp => h.give_up(if last_err.is_empty() { "the background service stopped and did not come back".into() } else { last_err.clone() }),
            }
        }
        std::thread::sleep(p.poll);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    fn at(t0: Instant, ms: u64) -> Instant {
        t0 + Duration::from_millis(ms)
    }

    #[test]
    fn a_requested_restart_shows_the_restarting_screen_then_reopens() {
        let p = Policy::default();
        let mut w = Watch::new(p);
        let t0 = Instant::now();
        assert!(w.step(true, t0).is_empty());
        assert!(w.step(false, at(t0, 100)).is_empty(), "one missed poll is not shown");
        assert_eq!(w.step(false, at(t0, 1400)), vec![Action::ShowRestarting]);
        assert!(w.step(false, at(t0, 3000)).is_empty(), "the daemon's own helper gets the grace period");
        assert_eq!(w.step(true, at(t0, 3500)), vec![Action::Reopen]);
        assert!(w.step(true, at(t0, 4000)).is_empty());
        // A blip the window never showed needs no reload.
        assert!(w.step(false, at(t0, 5000)).is_empty());
        assert!(w.step(true, at(t0, 5600)).is_empty());
    }

    #[test]
    fn a_daemon_that_stays_down_is_started_by_the_app_retried_and_reported() {
        let p = Policy::default();
        let mut w = Watch::new(p);
        let t0 = Instant::now();
        w.step(false, t0);
        assert_eq!(w.step(false, at(t0, 1300)), vec![Action::ShowRestarting]);
        assert_eq!(w.step(false, at(t0, 6100)), vec![Action::Start]);
        assert!(w.step(false, at(t0, 10_000)).is_empty(), "not again before the retry interval");
        assert_eq!(w.step(false, at(t0, 26_200)), vec![Action::Start]);
        let late = w.step(false, at(t0, 120_500));
        assert!(late.contains(&Action::GiveUp) && late.contains(&Action::Start), "{late:?}");
        assert!(!w.step(false, at(t0, 121_000)).contains(&Action::GiveUp), "reported once");
        assert_eq!(w.step(true, at(t0, 125_000)), vec![Action::Reopen], "and the window comes back when it does");
    }

    /// A tiny App Server stand-in: answers `GET /health` with 200 while `up`.
    fn server(up: Arc<AtomicBool>) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let mut s = s;
                if !up.load(Ordering::SeqCst) {
                    // Like a stopped daemon: the connection is refused / reset.
                    drop(s);
                    continue;
                }
                let mut b = [0u8; 512];
                let _ = s.read(&mut b);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\n{\"ok\":true}");
            }
        });
        base
    }

    struct Fake {
        base: String,
        up: Arc<AtomicBool>,
        /// What `daemon start` does: bring the server back (or fail).
        start_works: bool,
        events: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
    }

    impl Host for Fake {
        fn healthy(&mut self) -> bool {
            crate::agent::health(&self.base, Duration::from_millis(300))
        }
        fn show_restarting(&mut self) {
            self.events.lock().unwrap().push("restarting".into());
        }
        fn start_daemon(&mut self) -> Result<(), String> {
            self.events.lock().unwrap().push("start".into());
            if self.start_works {
                self.up.store(true, Ordering::SeqCst);
                Ok(())
            } else {
                Err("seagentd exited during startup".into())
            }
        }
        fn reopen(&mut self) {
            self.events.lock().unwrap().push("reopen".into());
            self.stop.store(true, Ordering::SeqCst);
        }
        fn give_up(&mut self, why: String) {
            self.events.lock().unwrap().push(format!("give-up: {why}"));
            self.stop.store(true, Ordering::SeqCst);
        }
        fn stopped(&self) -> bool {
            self.stop.load(Ordering::SeqCst)
        }
        fn log(&mut self, _: String) {}
    }

    fn fast() -> Policy {
        Policy { poll: Duration::from_millis(50), show_after: Duration::from_millis(150), grace: Duration::from_millis(900), retry: Duration::from_millis(300), give_up: Duration::from_millis(2500) }
    }

    fn fake(start_works: bool) -> (Fake, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
        let up = Arc::new(AtomicBool::new(true));
        let events = Arc::new(Mutex::new(vec![]));
        (Fake { base: server(up.clone()), up: up.clone(), start_works, events: events.clone(), stop: Arc::new(AtomicBool::new(false)) }, up, events)
    }

    #[test]
    fn the_supervisor_restarts_a_dead_daemon_and_reopens_the_console() {
        let (mut h, up, events) = fake(true);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            up.store(false, Ordering::SeqCst); // the daemon exits and nobody brings it back
        });
        run(&mut h, fast());
        t.join().unwrap();
        assert_eq!(*events.lock().unwrap(), ["restarting", "start", "reopen"]);
    }

    #[test]
    fn a_daemon_that_comes_back_by_itself_is_not_started_twice() {
        let (mut h, up, events) = fake(true);
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            up.store(false, Ordering::SeqCst);
            // The wizard's restart helper: back within the grace period.
            std::thread::sleep(Duration::from_millis(300));
            up.store(true, Ordering::SeqCst);
        });
        run(&mut h, fast());
        t.join().unwrap();
        assert_eq!(*events.lock().unwrap(), ["restarting", "reopen"]);
    }

    #[test]
    fn a_daemon_that_cannot_start_ends_on_the_error_screen() {
        let (mut h, up, events) = fake(false);
        up.store(false, Ordering::SeqCst);
        run(&mut h, fast());
        let ev = events.lock().unwrap().clone();
        assert_eq!(ev.first().map(String::as_str), Some("restarting"));
        assert!(ev.iter().filter(|e| *e == "start").count() >= 2, "retried: {ev:?}");
        assert_eq!(ev.last().map(String::as_str), Some("give-up: seagentd exited during startup"), "{ev:?}");
    }
}
