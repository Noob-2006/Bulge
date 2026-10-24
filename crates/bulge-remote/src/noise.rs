//! The end-to-end session: `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`.
//!
//! IK: the device (initiator) already knows the host's static key, from the
//! pairing link, and sends its own static key encrypted in the first message.
//! psk2: a 32-byte pre-shared key is mixed in at the end of the second
//! message, so the session keys depend on it — the host picks the PSK after
//! reading the device's static key (that device's PSK, or the pairing secret
//! when the device is redeeming a link), and the device's first transport
//! message only decrypts if both sides used the same one.
//!
//! The prologue names the protocol version; a mismatch fails the handshake.
//! There is no other pattern, cipher or version to fall back to.

use serde::Serialize;
use serde::de::DeserializeOwned;
use snow::{HandshakeState, TransportState};
use zeroize::Zeroizing;

use crate::frame::MAX_FRAME;

pub const PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const PROLOGUE: &[u8] = b"bulge-remote/1";
/// Bytes a Noise message adds to its payload (the AEAD tag).
const TAG: usize = 16;
/// The largest payload one transport message can carry (it must still fit
/// in a relay tunnel frame, which adds its own tag).
pub const MAX_PAYLOAD: usize = crate::tunnel::MAX_PAYLOAD - TAG;

/// A static X25519 keypair.
pub struct Keypair {
    pub private: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

fn builder() -> Result<snow::Builder<'static>, String> {
    let params = PATTERN.parse().map_err(|e| format!("noise params: {e:?}"))?;
    Ok(snow::Builder::new(params))
}

pub fn generate_keypair() -> Result<Keypair, String> {
    let keys = builder()?.generate_keypair().map_err(|e| format!("noise keypair: {e}"))?;
    let mut private = Zeroizing::new([0u8; 32]);
    private.copy_from_slice(&keys.private);
    let public = keys.public.as_slice().try_into().map_err(|_| "noise public key is not 32 bytes")?;
    Ok(Keypair { private, public })
}

/// Device side: start the handshake.
pub fn initiator(local: &Keypair, host_public: &[u8; 32], psk: &[u8; 32]) -> Result<HandshakeState, String> {
    builder()?
        .local_private_key(local.private.as_slice())
        .and_then(|b| b.remote_public_key(host_public))
        .and_then(|b| b.psk(2, psk))
        .and_then(|b| b.prologue(PROLOGUE))
        .and_then(snow::Builder::build_initiator)
        .map_err(|e| format!("noise: {e}"))
}

/// Host side: the PSK is set later with [`HandshakeState::set_psk`] once the
/// device's static key (first message) is known.
pub fn responder(local: &Keypair) -> Result<HandshakeState, String> {
    builder()?
        .local_private_key(local.private.as_slice())
        .and_then(|b| b.prologue(PROLOGUE))
        .and_then(snow::Builder::build_responder)
        .map_err(|e| format!("noise: {e}"))
}

/// Write a handshake message carrying `payload`.
pub fn write_handshake(state: &mut HandshakeState, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; MAX_FRAME];
    let len = state.write_message(payload, &mut out).map_err(|e| format!("noise handshake: {e}"))?;
    out.truncate(len);
    Ok(out)
}

/// Read a handshake message, returning its payload.
pub fn read_handshake(state: &mut HandshakeState, message: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = vec![0u8; MAX_FRAME];
    let len = state.read_message(message, &mut out).map_err(|_| "noise handshake failed (wrong keys)".to_string())?;
    out.truncate(len);
    Ok(out)
}

/// Encrypt/decrypt JSON messages once the handshake is done.
pub struct Secure {
    state: TransportState,
}

impl Secure {
    pub fn new(state: HandshakeState) -> Result<Self, String> {
        Ok(Self { state: state.into_transport_mode().map_err(|e| format!("noise: {e}"))? })
    }

    pub fn seal<T: Serialize>(&mut self, message: &T) -> Result<Vec<u8>, String> {
        let plain = Zeroizing::new(serde_json::to_vec(message).map_err(|e| e.to_string())?);
        if plain.len() > MAX_PAYLOAD {
            return Err(format!("message of {} bytes is too large", plain.len()));
        }
        let mut out = vec![0u8; plain.len() + TAG];
        let len = self.state.write_message(&plain, &mut out).map_err(|e| format!("noise: {e}"))?;
        out.truncate(len);
        Ok(out)
    }

    pub fn open<T: DeserializeOwned>(&mut self, frame: &[u8]) -> Result<T, String> {
        let mut plain = Zeroizing::new(vec![0u8; frame.len()]);
        let len = self.state.read_message(frame, &mut plain).map_err(|_| "message failed to decrypt".to_string())?;
        serde_json::from_slice(&plain[..len]).map_err(|e| format!("bad message: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Wire;

    fn handshake(device_psk: [u8; 32], host_psk: [u8; 32]) -> Result<(Secure, Secure), String> {
        let host = generate_keypair()?;
        let device = generate_keypair()?;
        let mut i = initiator(&device, &host.public, &device_psk)?;
        let mut r = responder(&host)?;
        let m1 = write_handshake(&mut i, b"opening")?;
        assert_eq!(read_handshake(&mut r, &m1)?, b"opening");
        assert_eq!(r.get_remote_static().unwrap(), device.public, "the host learns the device key");
        r.set_psk(2, &host_psk).map_err(|e| e.to_string())?;
        let m2 = write_handshake(&mut r, &[])?;
        read_handshake(&mut i, &m2)?;
        Ok((Secure::new(i)?, Secure::new(r)?))
    }

    #[test]
    fn matching_psk_talks_both_ways() {
        let (mut device, mut host) = handshake([7; 32], [7; 32]).unwrap();
        let sealed = device.seal(&Wire::Hello).unwrap();
        assert!(!sealed.windows(5).any(|w| w == b"hello"), "ciphertext");
        assert_eq!(host.open::<Wire>(&sealed).unwrap(), Wire::Hello);
        let reply = host.seal(&Wire::Reply { id: 1, text: "好".into() }).unwrap();
        assert_eq!(device.open::<Wire>(&reply).unwrap(), Wire::Reply { id: 1, text: "好".into() });
        // Replayed or tampered frames fail.
        assert!(host.open::<Wire>(&sealed).is_err());
    }

    #[test]
    fn a_wrong_psk_never_gets_through() {
        assert!(handshake([1; 32], [2; 32]).is_err(), "the device rejects the host's second message");
    }

    #[test]
    fn a_wrong_host_key_is_refused_by_the_host() {
        let host = generate_keypair().unwrap();
        let impostor = generate_keypair().unwrap();
        let device = generate_keypair().unwrap();
        let mut i = initiator(&device, &impostor.public, &[0; 32]).unwrap();
        let mut r = responder(&host).unwrap();
        let m1 = write_handshake(&mut i, b"x").unwrap();
        assert!(read_handshake(&mut r, &m1).is_err());
    }
}
