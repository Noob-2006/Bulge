//! The `remote` channel run by `bulge channels serve`: stays connected to the
//! relay as the host, and turns paired devices' messages into chat messages.
//! (Built only with the `channel` feature, so the relay and the device client
//! do not carry the chat-app dependencies.)
//!
//! Replies are delivered at least once: each is numbered per device and kept
//! until the device acknowledges it, and everything unacknowledged is sent
//! again when the device reconnects (the device drops numbers it has seen).

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bulge_channel_api::{Channel, ChannelError, Inbound};
use futures::future::BoxFuture;
use tokio::sync::mpsc;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::frame::Duplex;
use crate::host::{Device, HostIdentity, find_device, load, redeem, token_secret};
use crate::noise::{self, Secure};
use crate::wire::{Control, Opening, Wire, parse_control, recv_control, send_control};
use crate::{hex, now_secs, tunnel, unhex};

/// Unacknowledged replies kept per device (oldest dropped, with a log line).
const OUTBOX_LIMIT: usize = 100;
/// Text per reply message (characters); JSON escaping must stay within a
/// Noise message.
const TEXT_LIMIT: usize = 4000;

/// Timeouts, shortened in tests.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// Keepalive interval on idle connections.
    pub ping: Duration,
    /// A connection silent this long is dropped.
    pub idle: Duration,
    /// Time allowed for each handshake step.
    pub step: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self { ping: Duration::from_secs(30), idle: Duration::from_secs(120), step: Duration::from_secs(15) }
    }
}

/// Replies for one device not yet acknowledged.
#[derive(Default)]
struct Mailbox {
    next_id: u64,
    unacked: VecDeque<(u64, String)>,
}

struct Shared {
    channel: String,
    dir: PathBuf,
    identity: HostIdentity,
    timing: Timing,
    /// device public key → (session number, outgoing messages).
    sessions: Mutex<HashMap<String, (u64, mpsc::Sender<Wire>)>>,
    /// device → the newest message number taken from it.
    taken: Mutex<HashMap<String, u64>>,
    /// The command list sent to each device when it connects.
    commands: Mutex<Vec<crate::wire::CommandEntry>>,
    mail: Mutex<HashMap<String, Mailbox>>,
    inbound: mpsc::Sender<Inbound>,
    next: AtomicU64,
}

impl Shared {
    fn session(&self, device: &str) -> Option<mpsc::Sender<Wire>> {
        self.sessions.lock().ok().and_then(|s| s.get(device).map(|(_, tx)| tx.clone()))
    }

    /// Number and keep a reply; returns it as a wire message.
    fn post(&self, device: &str, text: String) -> Option<Wire> {
        let mut mail = self.mail.lock().ok()?;
        let mailbox = mail.entry(device.to_owned()).or_default();
        // Ids grow across restarts of the host too (they start from the
        // clock), so a device never mistakes a new reply for one it has seen.
        let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0);
        mailbox.next_id = (mailbox.next_id + 1).max(now_ms);
        let id = mailbox.next_id;
        if mailbox.unacked.len() >= OUTBOX_LIMIT {
            mailbox.unacked.pop_front();
            eprintln!("{}: device {}… has {OUTBOX_LIMIT} unacknowledged replies; the oldest was dropped", self.channel, &device[..12]);
        }
        mailbox.unacked.push_back((id, text.clone()));
        Some(Wire::Reply { id, text })
    }

    fn acknowledge(&self, device: &str, upto: u64) {
        if let Ok(mut mail) = self.mail.lock()
            && let Some(mailbox) = mail.get_mut(device)
        {
            mailbox.unacked.retain(|(id, _)| *id > upto);
        }
    }

    fn unacked(&self, device: &str) -> Vec<Wire> {
        self.mail.lock().ok().and_then(|mail| mail.get(device).map(|m| m.unacked.iter().map(|(id, text)| Wire::Reply { id: *id, text: text.clone() }).collect())).unwrap_or_default()
    }
}

/// The `remote` channel: messages from paired devices through the relay.
pub struct RemoteChannel {
    name: String,
    inbound: tokio::sync::Mutex<mpsc::Receiver<Inbound>>,
    shared: Arc<Shared>,
}

impl RemoteChannel {
    /// Load the identity from `dir` and stay connected to the relay.
    pub fn start(account: &str, dir: &Path, timing: Timing) -> Result<Self, String> {
        let identity = load(dir)?;
        let name = format!("remote:{account}");
        let (tx, rx) = mpsc::channel(64);
        let shared = Arc::new(Shared {
            channel: name.clone(),
            dir: dir.to_path_buf(),
            identity,
            timing,
            sessions: Mutex::new(HashMap::new()),
            taken: Mutex::new(HashMap::new()),
            commands: Mutex::new(Vec::new()),
            mail: Mutex::new(HashMap::new()),
            inbound: tx,
            next: AtomicU64::new(1),
        });
        tokio::spawn(control_loop(shared.clone()));
        Ok(Self { name, inbound: tokio::sync::Mutex::new(rx), shared })
    }
}

impl Channel for RemoteChannel {
    fn name(&self) -> &str {
        &self.name
    }

    fn text_limit(&self) -> usize {
        TEXT_LIMIT
    }

    fn authenticates_senders(&self) -> bool {
        true
    }

    fn register_commands<'a>(&'a self, commands: &'a [bulge_channel_api::commands::Command]) -> BoxFuture<'a, Result<(), ChannelError>> {
        let list = commands.iter().map(|c| crate::wire::CommandEntry { name: c.name.to_owned(), summary: c.summary.to_owned() }).collect();
        if let Ok(mut stored) = self.shared.commands.lock() {
            *stored = list;
        }
        Box::pin(async { Ok(()) })
    }

    fn poll(&self) -> BoxFuture<'_, Result<Vec<Inbound>, ChannelError>> {
        Box::pin(async move {
            let mut rx = self.inbound.lock().await;
            match timeout(Duration::from_secs(25), rx.recv()).await {
                Ok(Some(first)) => {
                    let mut batch = vec![first];
                    while let Ok(more) = rx.try_recv() {
                        batch.push(more);
                    }
                    Ok(batch)
                }
                Ok(None) => Err(ChannelError::Other { channel: self.name.clone(), message: "stopped".into() }),
                Err(_) => Ok(Vec::new()),
            }
        })
    }

    fn send(&self, chat_id: &str, text: &str) -> BoxFuture<'_, Result<(), ChannelError>> {
        let (chat_id, text) = (chat_id.to_owned(), text.to_owned());
        Box::pin(async move {
            // Kept until acknowledged; if the device is offline (or the send
            // races a disconnect) it goes out when the device reconnects.
            if let Some(reply) = self.shared.post(&chat_id, text)
                && let Some(tx) = self.shared.session(&chat_id)
            {
                let _ = tx.send(reply).await;
            }
            Ok(())
        })
    }

    fn typing(&self, chat_id: &str) -> BoxFuture<'_, ()> {
        let session = self.shared.session(chat_id);
        Box::pin(async move {
            if let Some(tx) = session {
                let _ = tx.try_send(Wire::Typing);
            }
        })
    }
}

async fn connect_relay(shared: &Shared) -> Result<Duplex, String> {
    tunnel::connect(&shared.identity.relay, &shared.identity.relay_key, shared.timing.step).await.map_err(String::from)
}

async fn control_loop(shared: Arc<Shared>) {
    let mut backoff = 1u64;
    loop {
        if let Err(error) = control_once(&shared, &mut backoff).await {
            eprintln!("{}: {error}; reconnecting in {backoff}s", shared.channel);
        }
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

/// One control connection: prove the id, then open a session per `Incoming`.
async fn control_once(shared: &Arc<Shared>, backoff: &mut u64) -> Result<(), String> {
    let step = shared.timing.step;
    let mut link = connect_relay(shared).await?;
    send_control(&link, &Control::Host { id: shared.identity.id() }).await?;
    let nonce = match recv_control(&mut link, step).await? {
        Control::Challenge { nonce } => unhex::<32>(&nonce)?,
        Control::Error { message } => return Err(format!("relay refused this host: {message}")),
        other => return Err(format!("unexpected {other:?} from relay")),
    };
    send_control(&link, &Control::Proof { sig: shared.identity.prove(&nonce) }).await?;
    match recv_control(&mut link, step).await? {
        Control::Ok => {}
        Control::Error { message } => return Err(format!("relay refused this host: {message}")),
        other => return Err(format!("unexpected {other:?} from relay")),
    }
    eprintln!("{}: online at relay {}", shared.channel, shared.identity.relay);
    *backoff = 1;
    let mut ping = tokio::time::interval(shared.timing.ping);
    ping.tick().await;
    loop {
        tokio::select! {
            frame = timeout(shared.timing.idle, link.recv()) => match frame {
                Ok(Some(Ok(bytes))) => match parse_control(&bytes)? {
                    Control::Incoming { sid } => {
                        let shared = shared.clone();
                        tokio::spawn(async move {
                            if let Err(error) = relayed_session(&shared, sid).await {
                                eprintln!("{}: session: {error}", shared.channel);
                            }
                        });
                    }
                    Control::Pong => {}
                    other => return Err(format!("unexpected {other:?} from relay")),
                },
                Ok(Some(Err(error))) => return Err(error),
                Ok(None) => return Err("relay closed the connection".into()),
                Err(_) => return Err("relay went quiet".into()),
            },
            _ = ping.tick() => send_control(&link, &Control::Ping).await?,
        }
    }
}

/// Accept a session the relay announced, then serve it.
async fn relayed_session(shared: &Arc<Shared>, sid: String) -> Result<(), String> {
    let mut link = connect_relay(shared).await?;
    send_control(&link, &Control::Accept { sid }).await?;
    match recv_control(&mut link, shared.timing.step).await? {
        Control::Ok => {}
        other => return Err(format!("relay: {other:?}")),
    }
    serve_link(shared, link).await
}

async fn send_wire(link: &Duplex, secure: &mut Secure, message: &Wire) -> Result<(), String> {
    link.send(secure.seal(message)?).await
}

enum Admission {
    Pairing { token: String, name: Option<String> },
    Paired(Device),
}

/// One device connection, over any transport: the Noise handshake with both
/// keys checked, then either a pairing or a chat session.
async fn serve_link(shared: &Arc<Shared>, mut link: Duplex) -> Result<(), String> {
    let step = shared.timing.step;
    let mut handshake = noise::responder(shared.identity.noise())?;
    let first = link.recv_within(step).await?;
    let opening: Opening = serde_json::from_slice(&noise::read_handshake(&mut handshake, &first)?).map_err(|e| format!("bad opening: {e}"))?;
    let device_key: [u8; 32] = handshake.get_remote_static().and_then(|k| k.try_into().ok()).ok_or("no device key")?;
    let now = now_secs();
    // Key one: the device's static key is paired (or it presents a live
    // pairing token). Anything else is closed without a reply.
    let (admission, psk) = match opening.pair {
        Some(token) => match token_secret(&shared.dir, &token, now)? {
            Some(secret) => (Admission::Pairing { token, name: opening.name }, Zeroizing::new(secret)),
            None => return Err(format!("refused device {}…: unknown or expired pairing link", &hex(&device_key)[..12])),
        },
        None => match find_device(&shared.dir, &hex(&device_key))? {
            Some(device) => {
                let psk = Zeroizing::new(unhex::<32>(&device.psk)?);
                (Admission::Paired(device), psk)
            }
            None => return Err(format!("refused device {}…: not paired", &hex(&device_key)[..12])),
        },
    };
    handshake.set_psk(2, psk.as_slice()).map_err(|e| format!("noise: {e}"))?;
    link.send(noise::write_handshake(&mut handshake, &[])?).await?;
    let mut secure = Secure::new(handshake)?;
    // Key two: the device's first message decrypts only if it holds the PSK.
    match secure.open::<Wire>(&link.recv_within(step).await?) {
        Ok(Wire::Hello) => {}
        Ok(other) => return Err(format!("expected hello, got {other:?}")),
        Err(_) => return Err(format!("refused device {}…: wrong pre-shared key", &hex(&device_key)[..12])),
    }

    match admission {
        Admission::Pairing { token, name } => match redeem(&shared.dir, &token, name.as_deref(), &device_key, now_secs()) {
            Ok(device) => {
                eprintln!("{}: paired a new device \"{}\"", shared.channel, device.name);
                send_wire(&link, &mut secure, &Wire::Paired { name: device.name, psk: device.psk }).await
            }
            Err(message) => send_wire(&link, &mut secure, &Wire::Error { message }).await,
        },
        Admission::Paired(device) => serve_device(shared, device, secure, link).await,
    }
}

/// The device asked for a direct path: open a QUIC endpoint, tell the device
/// where and which certificate (inside the authenticated session), and serve
/// the direct connection — which must pass the same two-key handshake.
fn offer_direct(shared: Arc<Shared>, name: String, candidates: Vec<String>, to_device: mpsc::Sender<Wire>) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
    // A named, boxed future: serving the direct link leads back into
    // `serve_device`, which spawns this, so the types must not be inferred.
    Box::pin(async move {
        let attempt = async {
            let device = crate::direct::parse_candidates(&candidates);
            if device.is_empty() {
                return Err("the device offered no addresses".to_string());
            }
            let prepared = crate::direct::prepare(&shared.identity.relay, shared.timing.step).await?;
            let ours = prepared.candidates.iter().map(ToString::to_string).collect();
            let (cert, accept) = crate::direct::listen(prepared, device, shared.timing.step)?;
            to_device.send(Wire::Punch { candidates: ours, cert: Some(cert) }).await.map_err(|_| "the session ended".to_string())?;
            accept.await
        };
        match attempt.await {
            Ok(link) => {
                eprintln!("{}: device \"{name}\" has a direct path", shared.channel);
                if let Err(error) = serve_link(&shared, link).await {
                    eprintln!("{}: direct session: {error}", shared.channel);
                }
            }
            Err(error) => eprintln!("{}: device \"{name}\": no direct path ({error}); staying on the relay", shared.channel),
        }
    })
}

async fn serve_device(shared: &Arc<Shared>, device: Device, mut secure: Secure, mut link: Duplex) -> Result<(), String> {
    let number = shared.next.fetch_add(1, Ordering::SeqCst);
    let (tx, mut rx) = mpsc::channel::<Wire>(64);
    let to_device = tx.clone();
    if let Ok(mut sessions) = shared.sessions.lock() {
        // A newer connection from the same device (or the same device moving
        // to a direct path) replaces the old one.
        sessions.insert(device.public.clone(), (number, tx));
    }
    eprintln!("{}: device \"{}\" connected", shared.channel, device.name);
    let mut message_id = 0u64;
    let mut direct_offered = false;
    let mut result = Ok(());
    let list = shared.commands.lock().map(|c| c.clone()).unwrap_or_default();
    if !list.is_empty() {
        result = send_wire(&link, &mut secure, &Wire::Commands { list }).await;
    }
    for reply in shared.unacked(&device.public) {
        if result.is_err() {
            break;
        }
        if let Err(error) = send_wire(&link, &mut secure, &reply).await {
            result = Err(error);
            break;
        }
    }
    while result.is_ok() {
        tokio::select! {
            frame = timeout(shared.timing.idle, link.recv()) => {
                let message = match frame {
                    Ok(Some(frame)) => frame.and_then(|bytes| secure.open::<Wire>(&bytes)),
                    Ok(None) => break,
                    Err(_) => Err("the device went quiet".into()),
                };
                match message {
                    Ok(Wire::Msg { id, text }) => {
                        // A revoked device is cut off at its next message.
                        if find_device(&shared.dir, &device.public)?.is_none() {
                            let _ = send_wire(&link, &mut secure, &Wire::Error { message: "this device was removed from bulge".into() }).await;
                            result = Err(format!("device \"{}\" was revoked", device.name));
                            break;
                        }
                        // Re-sent after a reconnect: confirm again, run once.
                        let fresh = shared.taken.lock().map(|mut taken| {
                            let last = taken.entry(device.public.clone()).or_insert(0);
                            let fresh = id > *last;
                            *last = (*last).max(id);
                            fresh
                        }).unwrap_or(false);
                        result = send_wire(&link, &mut secure, &Wire::Received { id }).await;
                        if !fresh {
                            continue;
                        }
                        message_id += 1;
                        let inbound = Inbound {
                            channel: shared.channel.clone(),
                            chat_id: device.public.clone(),
                            sender_id: device.public.clone(),
                            sender_name: device.name.clone(),
                            is_group: false,
                            mentioned: true,
                            text,
                            message_id: format!("{number}-{message_id}"),
                            attachments: Vec::new(),
                        };
                        if shared.inbound.send(inbound).await.is_err() {
                            break;
                        }
                    }
                    Ok(Wire::Ack { id }) => shared.acknowledge(&device.public, id),
                    // One direct attempt per session (each opens a socket).
                    Ok(Wire::Punch { candidates, cert: None }) if !direct_offered => {
                        direct_offered = true;
                        tokio::spawn(offer_direct(shared.clone(), device.name.clone(), candidates, to_device.clone()));
                    }
                    Ok(Wire::Punch { .. }) => {}
                    Ok(Wire::Ping) => result = send_wire(&link, &mut secure, &Wire::Pong).await,
                    Ok(Wire::Pong | Wire::Unknown) => {}
                    Ok(other) => result = Err(format!("unexpected {other:?} from device")),
                    Err(error) => result = Err(error),
                }
            }
            out = rx.recv() => match out {
                Some(message) => result = send_wire(&link, &mut secure, &message).await,
                None => break,
            },
        }
    }
    if let Ok(mut sessions) = shared.sessions.lock()
        && sessions.get(&device.public).is_some_and(|(n, _)| *n == number)
    {
        sessions.remove(&device.public);
    }
    eprintln!("{}: device \"{}\" disconnected", shared.channel, device.name);
    result
}
