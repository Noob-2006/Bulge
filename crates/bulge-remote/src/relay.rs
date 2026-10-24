//! The relay: a blind meeting point for hosts and devices that both dial out.
//!
//! Every connection first runs the relay tunnel handshake ([`crate::tunnel`]),
//! pinned to the relay's static key. A host then keeps a control connection
//! open after proving it owns its id. A device dials that id; the relay tells
//! the host (`Incoming`), the host opens a second connection (`Accept`), and
//! the relay passes frames between the two until either side goes quiet or
//! closes. Those frames are the device↔host Noise session: the relay never
//! holds a key that can read them.
//!
//! Abuse limits: a relay serves only the host ids it was told to (unless
//! explicitly run open), caps connections overall and per source address,
//! caps sessions per host, and times out silent connections.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::timeout;

use crate::frame::Duplex;
use crate::noise::Keypair;
use crate::wire::{Control, HOST_PROOF_CONTEXT, parse_control, recv_control, send_control};
use crate::{hex, random, tunnel, unhex};

#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Host ids allowed to register; `None` serves any host (an open relay).
    pub allow_hosts: Option<HashSet<String>>,
    pub max_connections: usize,
    pub max_per_address: usize,
    pub max_sessions_per_host: usize,
    /// A connection (control or session) silent this long is closed.
    pub idle: Duration,
    /// Time allowed for each step of a handshake with the relay.
    pub step: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            allow_hosts: Some(HashSet::new()),
            max_connections: 1024,
            max_per_address: 32,
            max_sessions_per_host: 16,
            idle: Duration::from_secs(120),
            step: Duration::from_secs(15),
        }
    }
}

/// How a host's accepting connection is handed to the waiting device: its
/// link, plus the signal it waits on until the session ends.
type Handover = oneshot::Sender<(Duplex, oneshot::Sender<()>)>;

struct HostSlot {
    conn: u64,
    incoming: mpsc::Sender<String>,
    sessions: Arc<AtomicUsize>,
}

pub struct Relay {
    config: RelayConfig,
    keys: Keypair,
    hosts: Mutex<HashMap<String, HostSlot>>,
    /// Live sessions per host id; kept across the host re-registering, so
    /// reconnecting does not reset the cap.
    session_counts: Mutex<HashMap<String, Arc<AtomicUsize>>>,
    /// Sessions waiting for the host: the host's link, and a signal its
    /// accepting connection waits on (so it keeps its connection slot until
    /// the session ends).
    pending: Mutex<HashMap<String, Handover>>,
    per_address: Mutex<HashMap<IpAddr, usize>>,
    connections: Arc<Semaphore>,
    next_conn: AtomicU64,
}

/// Decrements the per-address count when a connection ends.
struct AddressGuard<'a> {
    relay: &'a Relay,
    ip: IpAddr,
}

impl Drop for AddressGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut map) = self.relay.per_address.lock()
            && let Some(count) = map.get_mut(&self.ip)
        {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Counts a live session against its host's cap.
struct SessionGuard(Arc<AtomicUsize>);

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    private: String,
    public: String,
}

/// The relay's static key at `path`, created (mode 600) on first run.
pub fn load_or_create_key(path: &std::path::Path) -> Result<Keypair, String> {
    let file = match crate::store::read::<KeyFile>(path)? {
        Some(file) => file,
        None => {
            let keys = crate::noise::generate_keypair()?;
            let file = KeyFile { private: hex(keys.private.as_slice()), public: hex(&keys.public) };
            crate::store::write(path, &file)?;
            file
        }
    };
    Ok(Keypair { private: zeroize::Zeroizing::new(unhex::<32>(&file.private)?), public: unhex::<32>(&file.public)? })
}

fn host_proof_message(nonce: &[u8]) -> Vec<u8> {
    [HOST_PROOF_CONTEXT, nonce].concat()
}

impl Relay {
    pub fn new(config: RelayConfig, keys: Keypair) -> Arc<Self> {
        let connections = Arc::new(Semaphore::new(config.max_connections));
        Arc::new(Self {
            config,
            keys,
            hosts: Mutex::new(HashMap::new()),
            session_counts: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            per_address: Mutex::new(HashMap::new()),
            connections,
            next_conn: AtomicU64::new(1),
        })
    }

    /// The key clients pin (hex).
    pub fn public_key(&self) -> String {
        hex(&self.keys.public)
    }

    /// Accept connections forever.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<(), String> {
        loop {
            let (stream, addr) = listener.accept().await.map_err(|e| format!("accept: {e}"))?;
            let Ok(permit) = self.connections.clone().try_acquire_owned() else {
                eprintln!("relay: connection limit reached; dropped {addr}");
                continue;
            };
            let ip = addr.ip();
            let admitted = self.per_address.lock().map(|mut map| {
                let count = map.entry(ip).or_insert(0);
                if *count >= self.config.max_per_address {
                    false
                } else {
                    *count += 1;
                    true
                }
            });
            if !admitted.unwrap_or(false) {
                eprintln!("relay: too many connections from {ip}; dropped");
                continue;
            }
            let relay = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _guard = AddressGuard { relay: &relay, ip };
                let result = match tunnel::accept(stream, &relay.keys, relay.config.step).await {
                    Ok(link) => relay.handle(link).await,
                    Err(error) => Err(error),
                };
                if let Err(error) = result {
                    eprintln!("relay: {addr}: {error}");
                }
            });
        }
    }

    async fn handle(&self, mut link: Duplex) -> Result<(), String> {
        match recv_control(&mut link, self.config.step).await? {
            Control::Host { id } => self.host(link, id).await,
            Control::Dial { id } => self.dial(link, id).await,
            Control::Accept { sid } => self.accept(link, sid).await,
            other => Err(format!("unexpected greeting {other:?}")),
        }
    }

    async fn refuse(link: &Duplex, message: &str) -> Result<(), String> {
        let _ = send_control(link, &Control::Error { message: message.into() }).await;
        Err(message.into())
    }

    /// A host's control connection: prove the id, then relay `Incoming`s.
    async fn host(&self, mut link: Duplex, id: String) -> Result<(), String> {
        if let Some(allowed) = &self.config.allow_hosts
            && !allowed.contains(&id)
        {
            return Self::refuse(&link, "this relay does not serve that host id").await;
        }
        let Ok(key) = unhex::<32>(&id).and_then(|bytes| VerifyingKey::from_bytes(&bytes).map_err(|e| e.to_string())) else {
            return Self::refuse(&link, "the host id is not an ed25519 public key").await;
        };
        let nonce = random::<32>()?;
        send_control(&link, &Control::Challenge { nonce: hex(&nonce) }).await?;
        let Control::Proof { sig } = recv_control(&mut link, self.config.step).await? else {
            return Self::refuse(&link, "expected a proof").await;
        };
        let verified = unhex::<64>(&sig).ok().map(|bytes| key.verify_strict(&host_proof_message(&nonce), &Signature::from_bytes(&bytes)).is_ok());
        if verified != Some(true) {
            return Self::refuse(&link, "the proof does not verify").await;
        }

        let conn = self.next_conn.fetch_add(1, Ordering::SeqCst);
        let (incoming_tx, mut incoming_rx) = mpsc::channel::<String>(16);
        {
            let mut hosts = self.hosts.lock().map_err(|_| "poisoned")?;
            // A newer proven connection replaces an older one (the host
            // reconnected); dropping the old sender ends the old loop.
            let sessions = self.session_counts.lock().map_err(|_| "poisoned")?.entry(id.clone()).or_default().clone();
            hosts.insert(id.clone(), HostSlot { conn, incoming: incoming_tx, sessions });
        }
        eprintln!("relay: host {}… online", &id[..12]);
        send_control(&link, &Control::Ok).await?;

        let result = loop {
            tokio::select! {
                sid = incoming_rx.recv() => match sid {
                    Some(sid) => send_control(&link, &Control::Incoming { sid }).await?,
                    None => break Ok(()),
                },
                frame = timeout(self.config.idle, link.recv()) => match frame {
                    Ok(Some(Ok(bytes))) => match parse_control(&bytes)? {
                        Control::Ping => send_control(&link, &Control::Pong).await?,
                        other => break Err(format!("unexpected {other:?} from host")),
                    },
                    Ok(Some(Err(error))) => break Err(error),
                    Ok(None) => break Ok(()),
                    Err(_) => break Err("host went quiet".into()),
                },
            }
        };
        if let Ok(mut hosts) = self.hosts.lock()
            && hosts.get(&id).is_some_and(|slot| slot.conn == conn)
        {
            hosts.remove(&id);
        }
        eprintln!("relay: host {}… offline", &id[..12]);
        result
    }

    /// A device asks for a host: wait for the host's `Accept`, then pass frames.
    async fn dial(&self, link: Duplex, id: String) -> Result<(), String> {
        let slot = self.hosts.lock().map_err(|_| "poisoned")?.get(&id).map(|slot| (slot.incoming.clone(), slot.sessions.clone()));
        let Some((incoming, sessions)) = slot else {
            return Self::refuse(&link, "that host is not online").await;
        };
        if sessions.fetch_add(1, Ordering::SeqCst) >= self.config.max_sessions_per_host {
            sessions.fetch_sub(1, Ordering::SeqCst);
            return Self::refuse(&link, "that host has too many sessions").await;
        }
        let _session = SessionGuard(sessions);
        let sid = hex(&random::<16>()?);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().map_err(|_| "poisoned")?.insert(sid.clone(), tx);
        let host_link = async {
            incoming.send_timeout(sid.clone(), self.config.step).await.map_err(|_| "the host is not answering")?;
            timeout(self.config.step, rx).await.map_err(|_| "the host did not accept in time")?.map_err(|_| "the host did not accept")
        }
        .await;
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&sid);
        }
        let (host_link, _session_over) = match host_link {
            Ok(pair) => pair,
            Err(message) => return Self::refuse(&link, message).await,
        };
        send_control(&link, &Control::Ok).await?;
        pass(link, host_link, self.config.idle).await;
        // Dropping `_session_over` releases the host side's connection.
        Ok(())
    }

    /// The host's side of a session announced by `Incoming`.
    async fn accept(&self, link: Duplex, sid: String) -> Result<(), String> {
        let waiting = self.pending.lock().map_err(|_| "poisoned")?.remove(&sid);
        let Some(deliver) = waiting else {
            return Self::refuse(&link, "no device is waiting for that session").await;
        };
        send_control(&link, &Control::Ok).await?;
        // The dialing task owns the session from here; this connection keeps
        // its slot (connection cap, per-address count) until it ends.
        let (over_tx, over_rx) = oneshot::channel::<()>();
        if deliver.send((link, over_tx)).is_ok() {
            let _ = over_rx.await;
        }
        Ok(())
    }
}

/// Answer STUN requests on the relay's UDP port: tell each sender the
/// address its datagram came from (for direct connections). Answers are never
/// larger than requests.
pub async fn serve_stun(socket: tokio::net::UdpSocket) -> Result<(), String> {
    let mut buf = [0u8; crate::wire::STUN_LEN + 1];
    loop {
        let (len, from) = socket.recv_from(&mut buf).await.map_err(|e| format!("udp: {e}"))?;
        if let Some(answer) = crate::wire::stun_answer(&buf[..len], from) {
            let _ = socket.send_to(&answer, from).await;
        }
    }
}

/// Pass frames both ways until either side closes, errs, or both are silent
/// for `idle` (any frame restarts the wait).
async fn pass(mut a: Duplex, mut b: Duplex, idle: Duration) {
    loop {
        tokio::select! {
            frame = a.recv() => match frame {
                Some(Ok(bytes)) => if b.send(bytes).await.is_err() { return },
                _ => return,
            },
            frame = b.recv() => match frame {
                Some(Ok(bytes)) => if a.send(bytes).await.is_err() { return },
                _ => return,
            },
            () = tokio::time::sleep(idle) => return,
        }
    }
}
