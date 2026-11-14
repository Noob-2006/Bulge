//! Many commands over the desktop VM's one agent channel.
//!
//! The microVM pool runs one command at a time per VM (`pool::ExecGate`), so it reads the
//! channel inline. A desktop VM is shared by every session and tool call of the daemon, so
//! here one reader thread owns the channel and hands each [`GuestMsg`] to the command whose
//! `id` it carries; senders take a mutex so two frames never interleave on the stream. Ids
//! start at a time-derived value, so a frame the guest still had in flight for a previous
//! connection (an `Exit` written while the host was away) cannot be mistaken for a new
//! command's.

use crate::channel::Channel;
use crate::proto::{GuestMsg, HostMsg};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Largest stdin chunk per frame (base64 of it stays far below `MAX_FRAME`).
const STDIN_CHUNK: usize = 1 << 20;

struct Shared {
    chan: Arc<Channel>,
    send: Mutex<()>,
    routes: Mutex<HashMap<u64, Sender<GuestMsg>>>,
    next: AtomicU64,
    dead: Mutex<Option<String>>,
    stop: AtomicBool,
    hello: Mutex<Option<GuestMsg>>,
    /// The agent of this connection was seen (its Hello or an answer): a later Hello is a restart.
    greeted: AtomicBool,
}

/// The multiplexed agent channel of one running desktop VM.
pub struct Mux {
    s: Arc<Shared>,
}

impl std::fmt::Debug for Mux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mux").field("alive", &self.alive()).field("commands", &self.s.routes.lock().unwrap().len()).finish()
    }
}

/// How one command ended, with its merged output (see [`Mux::run`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutput {
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub output: Vec<u8>,
}

impl Mux {
    /// Take over `chan` (connected, authenticated where it needs it) whose `Hello` is still
    /// queued, and start its reader thread.
    pub fn new(chan: Channel) -> Arc<Mux> {
        Mux::start(chan, None, false)
    }

    /// [`Mux::new`] for a channel whose greeting the caller already read (`hello`, or `None`
    /// when the agent answered a Ping instead).
    pub fn with_greeting(chan: Channel, hello: Option<GuestMsg>) -> Arc<Mux> {
        Mux::start(chan, hello, true)
    }

    fn start(chan: Channel, hello: Option<GuestMsg>, greeted: bool) -> Arc<Mux> {
        let start = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(1) & ((1 << 52) - 1);
        let s = Arc::new(Shared {
            chan: Arc::new(chan),
            send: Mutex::new(()),
            routes: Mutex::new(HashMap::new()),
            next: AtomicU64::new(start.max(1)),
            dead: Mutex::new(None),
            stop: AtomicBool::new(false),
            hello: Mutex::new(hello),
            greeted: AtomicBool::new(greeted),
        });
        let r = s.clone();
        std::thread::Builder::new().name("seagent-dvm-mux".into()).spawn(move || reader(r)).ok();
        Arc::new(Mux { s })
    }

    /// Still connected (the reader has not seen the channel fail).
    pub fn alive(&self) -> bool {
        self.s.dead.lock().unwrap().is_none()
    }

    /// Why the channel stopped, if it did.
    pub fn error(&self) -> Option<String> {
        self.s.dead.lock().unwrap().clone()
    }

    /// The guest's latest `Hello` (agent version, uid, kernel), once the reader saw it.
    pub fn hello(&self) -> Option<GuestMsg> {
        self.s.hello.lock().unwrap().clone()
    }

    /// Register a fresh command id; its frames arrive on the receiver.
    pub fn open(&self) -> Result<(u64, Receiver<GuestMsg>), String> {
        if let Some(e) = self.error() {
            return Err(e);
        }
        let id = self.s.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = channel();
        self.s.routes.lock().unwrap().insert(id, tx);
        Ok((id, rx))
    }

    /// Forget `id` (its command finished or its owner went away).
    pub fn close(&self, id: u64) {
        self.s.routes.lock().unwrap().remove(&id);
    }

    pub fn send(&self, m: &HostMsg) -> Result<(), String> {
        if let Some(e) = self.error() {
            return Err(e);
        }
        let _g = self.s.send.lock().unwrap();
        self.s.chan.send(m)
    }

    /// Send `data` as the stdin of `id`, in frame-sized chunks.
    pub fn send_stdin(&self, id: u64, data: &[u8]) -> Result<(), String> {
        for c in data.chunks(STDIN_CHUNK) {
            self.send(&HostMsg::Stdin { id, data: B64.encode(c) })?;
        }
        Ok(())
    }

    /// Commands in flight.
    pub fn in_flight(&self) -> usize {
        self.s.routes.lock().unwrap().len()
    }

    /// Run `script` to completion (bash, as the desktop user, in `cwd` or the in-VM workspace),
    /// feeding `stdin` when given; SIGKILLed after `timeout`.
    pub fn run(&self, script: &str, cwd: Option<&str>, env: &[(String, String)], stdin: Option<&[u8]>, timeout: Duration) -> Result<RunOutput, String> {
        let (id, rx) = self.open()?;
        let r = self.run_on(id, &rx, script, cwd, env, stdin, timeout);
        self.close(id);
        r
    }

    #[allow(clippy::too_many_arguments)]
    fn run_on(&self, id: u64, rx: &Receiver<GuestMsg>, script: &str, cwd: Option<&str>, env: &[(String, String)], stdin: Option<&[u8]>, timeout: Duration) -> Result<RunOutput, String> {
        self.send(&HostMsg::Exec { id, script: script.into(), cwd: cwd.map(str::to_string), env: env.to_vec(), login: false, stdin: stdin.is_some(), pty: None, timeout_secs: 0 })?;
        if let Some(d) = stdin {
            self.send_stdin(id, d)?;
            self.send(&HostMsg::Eof { id })?;
        }
        let deadline = Instant::now() + timeout;
        let mut output = Vec::new();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                let _ = self.send(&HostMsg::Signal { id, force: true });
                return Err(format!("command timed out after {}s in the desktop VM", timeout.as_secs()));
            }
            match rx.recv_timeout(left) {
                Ok(GuestMsg::Out { data, .. }) => output.extend(B64.decode(data).unwrap_or_default()),
                Ok(GuestMsg::Exit { code, signal, .. }) => return Ok(RunOutput { code, signal, output }),
                Ok(GuestMsg::Err { message, .. }) => return Err(format!("desktop VM agent: {message}")),
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Err(self.error().unwrap_or_else(|| "the desktop VM channel closed".into())),
            }
        }
    }

    /// Stop the reader and close the channel (commands in flight see it closed; the guest
    /// agent kills them and waits for the next connection). The VMM serves one connection at
    /// a time, so the old one must be gone before a new one can be greeted.
    pub fn shutdown(&self) {
        self.s.stop.store(true, Ordering::SeqCst);
        fail(&self.s, "the desktop VM channel was closed by seagent".into());
        let _g = self.s.send.lock().unwrap();
        self.s.chan.shutdown();
    }
}

impl Drop for Mux {
    fn drop(&mut self) {
        self.s.stop.store(true, Ordering::SeqCst);
    }
}

/// Mark the channel dead and drop every route (their receivers see `Disconnected`).
fn fail(s: &Shared, why: String) {
    let mut d = s.dead.lock().unwrap();
    if d.is_none() {
        *d = Some(why);
    }
    drop(d);
    s.routes.lock().unwrap().clear();
}

fn reader(s: Arc<Shared>) {
    loop {
        if s.stop.load(Ordering::SeqCst) {
            return;
        }
        match s.chan.recv(Duration::from_millis(500)) {
            Ok(Some(m)) => dispatch(&s, m),
            Ok(None) => {}
            Err(e) => {
                fail(&s, format!("desktop VM channel: {e}"));
                return;
            }
        }
    }
}

fn dispatch(s: &Shared, m: GuestMsg) {
    match &m {
        GuestMsg::Hello { .. } => {
            // A Hello after the first one means the agent started over (its service was
            // restarted): whatever was running under the old one is gone.
            *s.hello.lock().unwrap() = Some(m.clone());
            if s.greeted.swap(true, Ordering::SeqCst) {
                let routes: Vec<(u64, Sender<GuestMsg>)> = s.routes.lock().unwrap().drain().collect();
                for (id, tx) in routes {
                    let _ = tx.send(GuestMsg::Err { id, message: "the agent in the desktop VM restarted; the command was lost".into() });
                }
            }
        }
        // The desktop VM has its own network: nothing in it needs the daemon's broker.
        GuestMsg::Broker { id, .. } => {
            let _g = s.send.lock().unwrap();
            let _ = s.chan.send(&HostMsg::BrokerReply { id: *id, ok: false, payload: serde_json::json!({"error": "the desktop VM has no seagent broker (it has its own network)"}) });
        }
        _ => {
            let Some(id) = m.id() else { return };
            let tx = s.routes.lock().unwrap().get(&id).cloned();
            if let Some(tx) = tx {
                let end = matches!(m, GuestMsg::Exit { .. });
                if tx.send(m).is_err() || end {
                    // The owner is gone, or the command is over: no more frames for it.
                    s.routes.lock().unwrap().remove(&id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{Stream, Transport};
    use crate::proto::{decode, encode};
    use std::io::{Read, Write};

    /// A fake guest agent: runs `echo`-like scripts (`say <text> <code>`), streams the text in
    /// two chunks with a pause, answers Ping; replies interleave across commands.
    fn fake_guest(s: Stream) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let w = Arc::new(Mutex::new(s.try_clone().unwrap()));
            let put = {
                let w = w.clone();
                move |m: GuestMsg| {
                    let _ = w.lock().unwrap().write_all(&encode(&m).unwrap());
                }
            };
            put(GuestMsg::Hello { version: 1, agent: "fake".into(), kernel: "k".into(), cid: None, transport: "virtio-serial".into(), uid: 1000, nonce: None });
            let mut r = s;
            let mut buf = Vec::new();
            let mut chunk = [0u8; 65536];
            let mut stdin: HashMap<u64, Vec<u8>> = HashMap::new();
            loop {
                let n = match r.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                buf.extend_from_slice(&chunk[..n]);
                let (frames, used) = decode::<HostMsg>(&buf).unwrap();
                buf.drain(..used);
                for f in frames {
                    match f {
                        HostMsg::Exec { id, script, stdin: false, .. } => {
                            let put = put.clone();
                            std::thread::spawn(move || {
                                let mut it = script.split_whitespace().skip(1);
                                let (text, code) = (it.next().unwrap_or("").to_string(), it.next().and_then(|c| c.parse().ok()).unwrap_or(0));
                                let (a, b) = text.split_at(text.len() / 2);
                                put(GuestMsg::Out { id, data: B64.encode(a) });
                                std::thread::sleep(Duration::from_millis(30));
                                put(GuestMsg::Out { id, data: B64.encode(b) });
                                put(GuestMsg::Exit { id, code: Some(code), signal: None });
                            });
                        }
                        HostMsg::Exec { id, stdin: true, .. } => {
                            stdin.insert(id, vec![]);
                        }
                        HostMsg::Stdin { id, data } => stdin.entry(id).or_default().extend(B64.decode(data).unwrap()),
                        HostMsg::Eof { id } => {
                            // `cat`: echo stdin back.
                            let got = stdin.remove(&id).unwrap_or_default();
                            put(GuestMsg::Out { id, data: B64.encode(&got) });
                            put(GuestMsg::Exit { id, code: Some(0), signal: None });
                        }
                        HostMsg::Ping { id } => put(GuestMsg::Pong { id }),
                        _ => {}
                    }
                }
            }
        })
    }

    #[test]
    fn concurrent_commands_get_their_own_output_and_exit_codes() {
        let (host, guest) = Stream::pair().unwrap();
        let _g = fake_guest(guest);
        let mux = Mux::new(Channel::from_stream(host, Transport::Serial).unwrap());
        let threads: Vec<_> = (0..8)
            .map(|i| {
                let m = mux.clone();
                std::thread::spawn(move || m.run(&format!("say hello-from-{i} {i}"), None, &[], None, Duration::from_secs(10)).unwrap())
            })
            .collect();
        for (i, t) in threads.into_iter().enumerate() {
            let out = t.join().unwrap();
            assert_eq!(String::from_utf8(out.output).unwrap(), format!("hello-from-{i}"));
            assert_eq!(out.code, Some(i as i32));
        }
        assert_eq!(mux.in_flight(), 0, "finished commands leave no route behind");
        assert!(matches!(mux.hello(), Some(GuestMsg::Hello { uid: 1000, .. })));
        // stdin larger than one frame chunk arrives whole.
        let big: Vec<u8> = (0..(STDIN_CHUNK * 2 + 77)).map(|i| (i % 251) as u8).collect();
        let out = mux.run("cat", None, &[], Some(&big), Duration::from_secs(10)).unwrap();
        assert_eq!(out.output, big);
    }

    #[test]
    fn ids_are_unique_and_a_dead_channel_fails_every_waiter() {
        let (host, guest) = Stream::pair().unwrap();
        let mux = Mux::new(Channel::from_stream(host, Transport::Serial).unwrap());
        let (a, _ra) = mux.open().unwrap();
        let (b, rb) = mux.open().unwrap();
        assert_ne!(a, b);
        assert!(a > 1_000_000, "ids start from the clock, not from 1: {a}");
        drop(guest);
        let t0 = Instant::now();
        assert!(rb.recv_timeout(Duration::from_secs(5)).is_err(), "the waiter is released");
        assert!(t0.elapsed() < Duration::from_secs(4));
        assert!(!mux.alive());
        assert!(mux.open().unwrap_err().contains("closed"), "{:?}", mux.error());
        assert!(mux.run("say x 0", None, &[], None, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn a_restarted_agent_fails_the_commands_of_the_old_one() {
        let (host, mut guest) = Stream::pair().unwrap();
        let mux = Mux::new(Channel::from_stream(host, Transport::Serial).unwrap());
        let hello = GuestMsg::Hello { version: 1, agent: "fake".into(), kernel: "k".into(), cid: None, transport: "virtio-serial".into(), uid: 1000, nonce: None };
        guest.write_all(&encode(&hello).unwrap()).unwrap();
        let (id, rx) = mux.open().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        // A stray frame for an id nobody owns is dropped quietly.
        guest.write_all(&encode(&GuestMsg::Exit { id: 7, code: Some(0), signal: None }).unwrap()).unwrap();
        guest.write_all(&encode(&hello).unwrap()).unwrap();
        match rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            GuestMsg::Err { id: got, message } => {
                assert_eq!(got, id);
                assert!(message.contains("restarted"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert!(mux.alive(), "the channel itself is fine");
    }
}
