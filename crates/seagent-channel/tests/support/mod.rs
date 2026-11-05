//! Shared helpers for the opt-in "real service" integration tests.
//!
//! Every test in `tests/real_*.rs` talks to a server that the operator starts
//! (see `tests/real/run.sh`). Nothing here starts, signals or kills a process,
//! and nothing touches `$HOME`/`$SEAGENT_HOME`: the address comes from an env var,
//! and when it is unset the test reports `skipped` and passes.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// `host:port` from `var`, or `None` (caller prints "skipped").
pub fn addr(var: &str) -> Option<(String, u16)> {
    let v = std::env::var(var).ok()?;
    let v = v.trim();
    let (h, p) = v.rsplit_once(':')?;
    Some((h.trim_matches(['[', ']']).to_string(), p.parse().ok()?))
}

/// Announce a skip so the log explains why nothing ran.
pub fn skipped(what: &str, var: &str) {
    eprintln!("skipped: {what} (set {var} to run against a real server)");
}

/// A scratch directory under the build TMPDIR, removed on drop.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(tag: &str) -> Scratch {
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| ".".into());
        let mut p = PathBuf::from(base);
        p.push(format!("seagent-real-{tag}-{}-{}", std::process::id(), Instant::now().elapsed().as_nanos()));
        let _ = std::fs::create_dir_all(&p);
        Scratch(p)
    }
    pub fn path(&self) -> &PathBuf {
        &self.0
    }
    pub fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A minimal line client for servers we test against (IRC). This is the peer,
/// not the code under test: it is allowed to be dumb.
pub struct LineClient {
    r: BufReader<TcpStream>,
    w: TcpStream,
    pub seen: Vec<String>,
}

impl LineClient {
    pub fn connect(host: &str, port: u16) -> std::io::Result<LineClient> {
        let s = TcpStream::connect((host, port))?;
        s.set_read_timeout(Some(Duration::from_millis(200)))?;
        s.set_nodelay(true)?;
        let w = s.try_clone()?;
        Ok(LineClient { r: BufReader::new(s), w, seen: Vec::new() })
    }

    pub fn send(&mut self, line: &str) -> std::io::Result<()> {
        self.w.write_all(format!("{line}\r\n").as_bytes())?;
        self.w.flush()
    }

    /// Read lines until `pred` matches or `timeout` passes; answers PING.
    pub fn until(&mut self, timeout: Duration, mut pred: impl FnMut(&str) -> bool) -> Option<String> {
        let end = Instant::now() + timeout;
        let mut buf = String::new();
        while Instant::now() < end {
            buf.clear();
            match self.r.read_line(&mut buf) {
                Ok(0) => return None,
                Ok(_) => {
                    let line = buf.trim_end_matches(['\r', '\n']).to_string();
                    if let Some(rest) = line.strip_prefix("PING ") {
                        let _ = self.send(&format!("PONG {rest}"));
                    }
                    self.seen.push(line.clone());
                    if pred(&line) {
                        return Some(line);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => return None,
            }
        }
        None
    }

    /// Wait for a line starting with `nick`'s PRIVMSG to `target`.
    pub fn privmsg(&mut self, from: &str, target: &str, timeout: Duration) -> Option<String> {
        let from = from.to_string();
        let target = target.to_string();
        self.until(timeout, |l| {
            let rest = l.split_once(" PRIVMSG ").map(|(p, r)| (p.trim_start_matches(':'), r));
            matches!(rest, Some((nick, r)) if nick.split('!').next() == Some(from.as_str()) && r.split(' ').next() == Some(target.as_str()))
        })
    }
}

/// Poll `chan` until `f` is true or `timeout` passes, returning everything seen.
pub fn poll_until(
    chan: &dyn seagent_channel::Channel,
    timeout: Duration,
    mut f: impl FnMut(&[seagent_channel::Inbound]) -> bool,
) -> Vec<seagent_channel::Inbound> {
    let cancel = seagent_core::Cancel::new();
    let end = Instant::now() + timeout;
    let mut all = Vec::new();
    while Instant::now() < end {
        if let Ok(batch) = chan.poll(&cancel) {
            if !batch.is_empty() {
                all.extend(batch);
                if f(&all) {
                    break;
                }
            }
        }
    }
    all
}
