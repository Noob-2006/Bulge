//! The device side: redeem a pairing link, remember hosts, and open sessions.
//!
//! Files in `~/.bulge/remote/` on the device (mode 600):
//! * `device.json` — this device's Noise static keypair.
//! * `hosts.json` — paired hosts: name, relay and its pinned key, host id,
//!   host Noise key, PSK.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::frame::Duplex;
use crate::link::PairLink;
use crate::noise::{self, Keypair, Secure};
use crate::wire::{Control, Opening, Wire, recv_control, send_control};
use crate::{Failure, hex, store, tunnel, unhex};

const STEP: Duration = Duration::from_secs(15);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceFile {
    noise_private: String,
    noise_public: String,
}

/// A host this device is paired with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownHost {
    /// What the user calls this host on this device.
    pub name: String,
    /// The name the host lists this device under.
    pub device_name: String,
    pub relay: String,
    pub relay_key: String,
    pub host: String,
    pub key: String,
    psk: String,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hosts {
    hosts: Vec<KnownHost>,
}

fn hosts_path(dir: &Path) -> PathBuf {
    dir.join("hosts.json")
}

/// This device's keypair, created on first use.
pub fn device_keys(dir: &Path) -> Result<Keypair, String> {
    let path = dir.join("device.json");
    let file = match store::read::<DeviceFile>(&path)? {
        Some(file) => file,
        None => {
            let keys = noise::generate_keypair()?;
            let file = DeviceFile { noise_private: hex(keys.private.as_slice()), noise_public: hex(&keys.public) };
            store::write(&path, &file)?;
            file
        }
    };
    Ok(Keypair { private: Zeroizing::new(unhex::<32>(&file.noise_private)?), public: unhex::<32>(&file.noise_public)? })
}

pub fn hosts(dir: &Path) -> Result<Vec<KnownHost>, String> {
    Ok(store::read::<Hosts>(&hosts_path(dir))?.unwrap_or_default().hosts)
}

/// Pick a host by name, or the only one.
pub fn pick_host(dir: &Path, name: Option<&str>) -> Result<KnownHost, String> {
    let all = hosts(dir)?;
    match name {
        Some(name) => all.into_iter().find(|h| h.name == name).ok_or_else(|| format!("no paired host named {name:?}")),
        None => match all.len() {
            0 => Err("this device is not paired with any bulge yet; run `bulge-remote join <link>`".into()),
            1 => Ok(all.into_iter().next().unwrap_or_else(|| unreachable!())),
            _ => Err(format!("several hosts are paired ({}); name one", all.iter().map(|h| h.name.as_str()).collect::<Vec<_>>().join(", "))),
        },
    }
}

pub fn forget(dir: &Path, name: &str) -> Result<bool, String> {
    store::transact::<Hosts, bool>(&hosts_path(dir), |h| {
        let before = h.hosts.len();
        h.hosts.retain(|host| host.name != name);
        let removed = h.hosts.len() != before;
        Ok((removed, removed))
    })
}

/// An open end-to-end session with a host.
pub struct Session {
    secure: Secure,
    link: Duplex,
    /// The newest reply id seen; older ids (re-sent after a reconnect) are
    /// acknowledged again but not returned twice.
    seen: u64,
}

impl Session {
    pub async fn send(&mut self, message: &Wire) -> Result<(), String> {
        self.link.send(self.secure.seal(message)?).await
    }

    /// Continue after replies up to `seen` were already shown.
    pub fn resume_after(&mut self, seen: u64) {
        self.seen = self.seen.max(seen);
    }

    pub fn seen(&self) -> u64 {
        self.seen
    }

    /// The next message; `Ok(None)` when the connection closed. Replies are
    /// acknowledged here, and repeats skipped. Cancel-safe.
    pub async fn next(&mut self) -> Result<Option<Wire>, String> {
        loop {
            let message = match self.link.recv().await {
                Some(Ok(bytes)) => self.secure.open::<Wire>(&bytes)?,
                Some(Err(error)) => return Err(error),
                None => return Ok(None),
            };
            if let Wire::Reply { id, .. } = &message {
                let id = *id;
                self.send(&Wire::Ack { id }).await?;
                if id <= self.seen {
                    continue;
                }
                self.seen = id;
            }
            return Ok(Some(message));
        }
    }
}

/// Reach the host through the relay and run the handshake with `psk`.
async fn open(keys: &Keypair, relay: &str, relay_key: &[u8; 32], host_id: &str, host_key: &[u8; 32], psk: &[u8; 32], opening: &Opening) -> Result<Session, Failure> {
    let mut link = tunnel::connect(relay, relay_key, STEP).await?;
    send_control(&link, &Control::Dial { id: host_id.to_owned() }).await?;
    match recv_control(&mut link, STEP * 2).await.map_err(|e| format!("relay did not connect us: {e}"))? {
        Control::Ok => {}
        Control::Error { message } => return Err(Failure::Transient(format!("relay: {message}"))),
        other => return Err(Failure::Transient(format!("unexpected {other:?} from relay"))),
    }
    handshake(keys, link, host_key, psk, opening).await
}

/// The device side of the end-to-end handshake, over any transport.
async fn handshake(keys: &Keypair, mut link: Duplex, host_key: &[u8; 32], psk: &[u8; 32], opening: &Opening) -> Result<Session, Failure> {
    let mut handshake = noise::initiator(keys, host_key, psk)?;
    let payload = serde_json::to_vec(opening).map_err(|e| e.to_string())?;
    link.send(noise::write_handshake(&mut handshake, &payload)?).await?;
    let reply = match timeout(STEP, link.recv()).await {
        Ok(Some(Ok(bytes))) => bytes,
        Ok(Some(Err(_)) | None) => return Err(Failure::Silent("the host closed the connection without answering (this device may not be paired, or the link was already used)".into())),
        Err(_) => return Err("the host did not answer".into()),
    };
    // Fails unless the host holds the key from the link AND used our PSK.
    noise::read_handshake(&mut handshake, &reply).map_err(|_| Failure::Rejected("the host's answer did not verify (wrong host key or pre-shared key)".into()))?;
    let mut session = Session { secure: Secure::new(handshake)?, link, seen: 0 };
    session.send(&Wire::Hello).await?;
    Ok(session)
}

/// Redeem a pairing link and remember the host as `host_name`.
pub async fn join(dir: &Path, link: &PairLink, host_name: &str, device_name: &str) -> Result<KnownHost, Failure> {
    if hosts(dir)?.iter().any(|h| h.name == host_name && h.host != link.host) {
        return Err(Failure::Rejected(format!("another host is already called {host_name:?}; choose a different --as name")));
    }
    let keys = device_keys(dir)?;
    let host_key = unhex::<32>(&link.key)?;
    let secret = Zeroizing::new(unhex::<32>(&link.secret)?);
    let opening = Opening { pair: Some(link.token.clone()), name: Some(device_name.to_owned()) };
    let relay_key = unhex::<32>(&link.relay_key)?;
    let mut session = open(&keys, &link.relay, &relay_key, &link.host, &host_key, &secret, &opening).await?;
    let (listed_as, psk) = match timeout(STEP, session.next()).await.map_err(|_| "the host did not finish pairing")?? {
        Some(Wire::Paired { name, psk }) => (name, psk),
        Some(Wire::Error { message }) => return Err(Failure::Rejected(format!("the host refused: {message}"))),
        Some(other) => return Err(format!("unexpected {other:?} from host").into()),
        None => return Err(Failure::Silent("the host closed the connection (link already used or expired?)".into())),
    };
    unhex::<32>(&psk).map_err(|e| format!("host sent a bad key: {e}"))?;
    let known = KnownHost { name: host_name.to_owned(), device_name: listed_as, relay: link.relay.clone(), relay_key: link.relay_key.clone(), host: link.host.clone(), key: link.key.clone(), psk };
    store::transact::<Hosts, ()>(&hosts_path(dir), |h| {
        h.hosts.retain(|existing| existing.name != known.name && existing.host != known.host);
        h.hosts.push(known.clone());
        Ok(((), true))
    })?;
    Ok(known)
}

/// Run the session handshake over a direct link (negotiated with `Punch`):
/// the same two-key check as over the relay.
pub async fn connect_over(dir: &Path, host: &KnownHost, link: Duplex) -> Result<Session, Failure> {
    let keys = device_keys(dir)?;
    let psk = Zeroizing::new(unhex::<32>(&host.psk)?);
    handshake(&keys, link, &unhex::<32>(&host.key)?, &psk, &Opening::default()).await
}

/// Open a chat session with a paired host.
pub async fn connect(dir: &Path, host: &KnownHost) -> Result<Session, Failure> {
    let keys = device_keys(dir)?;
    let psk = Zeroizing::new(unhex::<32>(&host.psk)?);
    open(&keys, &host.relay, &unhex::<32>(&host.relay_key)?, &host.host, &unhex::<32>(&host.key)?, &psk, &Opening::default()).await
}
