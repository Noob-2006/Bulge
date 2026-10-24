//! The bulge side: its identity, its paired devices, pairing tokens, and the
//! `remote` channel that `bulge channels serve` runs.
//!
//! Files in `~/.bulge/remote/` (all mode 600):
//! * `host.json` — the relay address and pinned key, the ed25519 key that
//!   proves the host's relay id, and the Noise static key.
//! * `devices.json` — paired devices: name, Noise public key, PSK.
//! * `pairing.json` — unredeemed pairing tokens (one use, ten minutes).
//!
//! The channel that serves devices is in [`crate::channel`].

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::link::PairLink;
use crate::noise::{self, Keypair};
use crate::wire::HOST_PROOF_CONTEXT;
use crate::{hex, random, store, unhex};

/// How long a pairing link stays valid.
pub const PAIRING_TTL_SECS: u64 = 600;
/// At most this many unredeemed links at once.
pub const MAX_PENDING_LINKS: usize = 3;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    relay: String,
    relay_key: String,
    sign_seed: String,
    noise_private: String,
    noise_public: String,
}

/// The host's keys and relay.
pub struct HostIdentity {
    pub relay: String,
    /// The relay's static key, pinned by the relay tunnel.
    pub relay_key: [u8; 32],
    sign: SigningKey,
    noise: Keypair,
}

impl HostIdentity {
    /// The relay id: the hex ed25519 public key.
    pub fn id(&self) -> String {
        hex(self.sign.verifying_key().as_bytes())
    }

    pub fn noise_public(&self) -> String {
        hex(&self.noise.public)
    }

    /// Sign the relay's challenge.
    pub fn prove(&self, nonce: &[u8]) -> String {
        hex(&self.sign.sign(&[HOST_PROOF_CONTEXT, nonce].concat()).to_bytes())
    }

    #[cfg_attr(not(feature = "channel"), allow(dead_code))] // used by the channel
    pub(crate) fn noise(&self) -> &Keypair {
        &self.noise
    }
}

fn host_path(dir: &Path) -> PathBuf {
    dir.join("host.json")
}

/// Create the host identity (or keep the existing keys and set the relay).
pub fn init(dir: &Path, relay: &str, relay_key: &str) -> Result<HostIdentity, String> {
    validate_relay(relay)?;
    let relay_key = crate::hex(&unhex::<32>(relay_key).map_err(|e| format!("relay key: {e}"))?);
    let path = host_path(dir);
    let file = match store::read::<HostFile>(&path)? {
        Some(mut file) => {
            file.relay = relay.to_owned();
            file.relay_key = relay_key;
            file
        }
        None => {
            let seed = Zeroizing::new(random::<32>()?);
            let noise = noise::generate_keypair()?;
            HostFile { relay: relay.to_owned(), relay_key, sign_seed: hex(seed.as_slice()), noise_private: hex(noise.private.as_slice()), noise_public: hex(&noise.public) }
        }
    };
    store::write(&path, &file)?;
    load(dir)
}

pub fn load(dir: &Path) -> Result<HostIdentity, String> {
    let path = host_path(dir);
    let file: HostFile = store::read(&path)?.ok_or_else(|| format!("{} is missing; run `bulge remote init --relay <host:port> --relay-key <key>` first", path.display()))?;
    let seed = Zeroizing::new(unhex::<32>(&file.sign_seed).map_err(|e| format!("{}: sign_seed: {e}", path.display()))?);
    let private = Zeroizing::new(unhex::<32>(&file.noise_private).map_err(|e| format!("{}: noise_private: {e}", path.display()))?);
    let public = unhex::<32>(&file.noise_public).map_err(|e| format!("{}: noise_public: {e}", path.display()))?;
    let relay_key = unhex::<32>(&file.relay_key).map_err(|e| format!("{}: relay_key: {e}", path.display()))?;
    Ok(HostIdentity { relay: file.relay, relay_key, sign: SigningKey::from_bytes(&seed), noise: Keypair { private, public } })
}

fn validate_relay(relay: &str) -> Result<(), String> {
    match relay.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p != 0) => Ok(()),
        _ => Err(format!("relay must be host:port, got {relay:?}")),
    }
}

/// A paired device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    pub name: String,
    /// Noise static public key (hex).
    pub public: String,
    pub(crate) psk: String,
    pub added: u64,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Devices {
    devices: Vec<Device>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    id: String,
    secret: String,
    expires_at: u64,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pairing {
    tokens: Vec<Token>,
}

fn devices_path(dir: &Path) -> PathBuf {
    dir.join("devices.json")
}

fn pairing_path(dir: &Path) -> PathBuf {
    dir.join("pairing.json")
}

/// Issue a one-time pairing link.
pub fn new_pairing(dir: &Path, now: u64) -> Result<PairLink, String> {
    let identity = load(dir)?;
    let token = Token { id: hex(&random::<8>()?), secret: hex(&random::<32>()?), expires_at: now + PAIRING_TTL_SECS };
    store::transact::<Pairing, ()>(&pairing_path(dir), |p| {
        p.tokens.retain(|t| t.expires_at > now);
        if p.tokens.len() >= MAX_PENDING_LINKS {
            return Err(format!("{MAX_PENDING_LINKS} pairing links are already waiting; use one or wait for them to expire"));
        }
        p.tokens.push(token.clone());
        Ok(((), true))
    })?;
    Ok(PairLink { v: crate::link::VERSION, host: identity.id(), key: identity.noise_public(), relay_key: hex(&identity.relay_key), relay: identity.relay, token: token.id, secret: token.secret })
}

pub fn devices(dir: &Path) -> Result<Vec<Device>, String> {
    Ok(store::read::<Devices>(&devices_path(dir))?.unwrap_or_default().devices)
}

/// Remove a paired device by name; its live session ends at its next message.
pub fn revoke(dir: &Path, name: &str) -> Result<bool, String> {
    store::transact::<Devices, bool>(&devices_path(dir), |d| {
        let before = d.devices.len();
        d.devices.retain(|dev| dev.name != name);
        let removed = d.devices.len() != before;
        Ok((removed, removed))
    })
}

#[cfg_attr(not(feature = "channel"), allow(dead_code))] // used by the channel
pub(crate) fn find_device(dir: &Path, public: &str) -> Result<Option<Device>, String> {
    Ok(devices(dir)?.into_iter().find(|d| d.public == public))
}

#[cfg_attr(not(feature = "channel"), allow(dead_code))] // used by the channel
pub(crate) fn token_secret(dir: &Path, id: &str, now: u64) -> Result<Option<[u8; 32]>, String> {
    let tokens = store::read::<Pairing>(&pairing_path(dir))?.unwrap_or_default().tokens;
    tokens.iter().find(|t| t.id == id && t.expires_at > now).map(|t| unhex::<32>(&t.secret)).transpose()
}

/// Make a device name printable, short and unique.
#[cfg_attr(not(feature = "channel"), allow(dead_code))] // used by the channel
fn clean_name(asked: Option<&str>, taken: &[Device], public: &str) -> String {
    let base: String = asked.unwrap_or("").chars().filter(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.')).take(32).collect();
    let base = if base.is_empty() { "device".to_owned() } else { base };
    let clash = |name: &str| taken.iter().any(|d| d.name == name && d.public != public);
    if !clash(&base) {
        return base;
    }
    (2..).map(|n| format!("{base}-{n}")).find(|name| !clash(name)).unwrap_or(base)
}

/// Spend the pairing token and list the device with a fresh PSK.
#[cfg_attr(not(feature = "channel"), allow(dead_code))] // used by the channel
pub(crate) fn redeem(dir: &Path, token: &str, asked: Option<&str>, public: &[u8; 32], now: u64) -> Result<Device, String> {
    store::transact::<Pairing, ()>(&pairing_path(dir), |p| {
        let at = p.tokens.iter().position(|t| t.id == token && t.expires_at > now).ok_or("that pairing link was already used or has expired")?;
        p.tokens.remove(at);
        Ok(((), true))
    })?;
    let public = hex(public);
    let psk = hex(&random::<32>()?);
    store::transact::<Devices, Device>(&devices_path(dir), |d| {
        let name = clean_name(asked, &d.devices, &public);
        // Re-pairing the same device replaces its old entry (and PSK).
        d.devices.retain(|dev| dev.public != public);
        let device = Device { name, public: public.clone(), psk: psk.clone(), added: now };
        d.devices.push(device.clone());
        Ok((device, true))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_cleaned_and_made_unique() {
        let taken = vec![Device { name: "phone".into(), public: "a".into(), psk: String::new(), added: 0 }];
        assert_eq!(clean_name(Some("phone"), &taken, "b"), "phone-2");
        assert_eq!(clean_name(Some("phone"), &taken, "a"), "phone", "the same device keeps its name");
        assert_eq!(clean_name(Some("../我的 筆電!"), &taken, "b"), "..我的筆電");
        assert_eq!(clean_name(None, &taken, "b"), "device");
    }

    #[test]
    fn relay_addresses_need_a_port() {
        assert!(validate_relay("relay.example:21117").is_ok());
        assert!(validate_relay("[::1]:21117").is_ok());
        assert!(validate_relay("relay.example").is_err());
        assert!(validate_relay(":80").is_err());
        assert!(validate_relay("x:0").is_err());
    }
}
