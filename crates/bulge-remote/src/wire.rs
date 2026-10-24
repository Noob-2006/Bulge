//! Message formats: the relay control frames (inside the encrypted relay
//! tunnel) and the end-to-end messages sealed inside Noise between device
//! and host.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::frame::Duplex;

/// Relay control frames are small.
pub const CONTROL_MAX: usize = 1024;

/// STUN request: prefix, 16-byte token, zero padding to 64 bytes (so the
/// answer is never larger than the question — no amplification).
pub const STUN_PREFIX: &[u8] = b"BULGE-STUN/1";
pub const STUN_LEN: usize = 64;

/// The relay's answer to a STUN request from `from`, if it is one: the
/// token and the address the request came from.
pub fn stun_answer(request: &[u8], from: std::net::SocketAddr) -> Option<Vec<u8>> {
    if request.len() != STUN_LEN || !request.starts_with(STUN_PREFIX) {
        return None;
    }
    let token = &request[STUN_PREFIX.len()..STUN_PREFIX.len() + 16];
    let mut answer = [STUN_PREFIX, token, from.to_string().as_bytes()].concat();
    answer.truncate(STUN_LEN);
    Some(answer)
}

/// What a host signs to prove to the relay that it owns its id.
pub const HOST_PROOF_CONTEXT: &[u8] = b"bulge-relay/1 host-proof\0";

/// Relay control protocol. Each TCP connection to the relay starts with one
/// of `Host`, `Dial` or `Accept`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Control {
    /// Host → relay: register as `id` (hex ed25519 public key).
    Host { id: String },
    /// Relay → host: sign this (hex 32 bytes) with the id's key.
    Challenge { nonce: String },
    /// Host → relay: hex ed25519 signature of `HOST_PROOF_CONTEXT || nonce`.
    Proof { sig: String },
    /// Device → relay: connect me to host `id`.
    Dial { id: String },
    /// Relay → host (on the control connection): a device is waiting as `sid`.
    Incoming { sid: String },
    /// Host → relay (on a new connection): this connection serves `sid`.
    Accept { sid: String },
    Ping,
    Pong,
    /// Accepted; for `Dial`/`Accept` the tunnel carries the device↔host
    /// session frames from here on.
    Ok,
    Error { message: String },
}

pub async fn send_control(link: &Duplex, message: &Control) -> Result<(), String> {
    link.send(serde_json::to_vec(message).map_err(|e| e.to_string())?).await
}

pub async fn recv_control(link: &mut Duplex, wait: Duration) -> Result<Control, String> {
    parse_control(&link.recv_within(wait).await?)
}

pub fn parse_control(bytes: &[u8]) -> Result<Control, String> {
    if bytes.len() > CONTROL_MAX {
        return Err(format!("control frame of {} bytes is too large", bytes.len()));
    }
    serde_json::from_slice(bytes).map_err(|e| format!("bad control frame: {e}"))
}

/// The first handshake message's payload (device → host, encrypted to the
/// host's static key).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opening {
    /// The pairing token id when this connection redeems a pairing link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pair: Option<String>,
    /// The name the device asks to be listed under (pairing only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// One entry of a command palette.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandEntry {
    pub name: String,
    pub summary: String,
}

/// End-to-end messages, sealed in Noise transport messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Wire {
    /// Device → host, first transport message: proves the device holds the
    /// PSK (the host admits nothing until this decrypts).
    Hello,
    /// Host → device after a pairing: the device's own long-term PSK (hex)
    /// and the name it is listed under.
    Paired { name: String, psk: String },
    /// Device → host: a message for bulge.
    /// Numbered per device (growing across restarts); kept by the device
    /// until the host confirms it with `Received`, and re-sent after a
    /// reconnect — the host skips numbers it has taken.
    Msg { id: u64, text: String },
    /// Host → device: messages up to and including `id` were taken.
    Received { id: u64 },
    /// Host → device: bulge's reply (or part of it), numbered per device.
    /// Kept by the host until acknowledged, and re-sent after a reconnect.
    Reply { id: u64, text: String },
    /// Device → host: replies up to and including `id` arrived.
    Ack { id: u64 },
    /// Either way: try a direct path. The device sends its candidate
    /// addresses; the host answers with its own and the fingerprint of the
    /// QUIC certificate it will present (see `direct`).
    Punch { candidates: Vec<String>, cert: Option<String> },
    /// Host → device, at the start of a session: the commands bulge
    /// understands, for the device's command palette.
    Commands { list: Vec<CommandEntry> },
    /// Host → device: a job is running for this device.
    Typing,
    Ping,
    Pong,
    /// Host → device: the request was refused (the session then closes).
    Error { message: String },
    /// A message type this side does not know (from a newer peer): ignored,
    /// so adding one never breaks older clients.
    #[serde(other)]
    Unknown,
}

/// The largest message text a device sends (its JSON must fit one Noise
/// message inside one tunnel frame, with room for escaping).
pub const MAX_MESSAGE_BYTES: usize = 40_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stun_answers_only_well_formed_requests_and_never_amplifies() {
        let from: std::net::SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let mut request = [STUN_PREFIX, &[9u8; 16]].concat();
        assert!(stun_answer(&request, from).is_none(), "short");
        request.resize(STUN_LEN, 0);
        let answer = stun_answer(&request, from).unwrap();
        assert!(answer.len() <= request.len());
        assert!(answer.ends_with(b"203.0.113.7:40000"));
        assert!(stun_answer(&[0u8; STUN_LEN], from).is_none());
    }
}
