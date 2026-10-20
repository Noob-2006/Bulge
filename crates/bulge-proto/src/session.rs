//! Authenticated session over any byte stream (vsock on the guest, the
//! libkrun-provided unix socket on the host): handshake, then typed messages.
//! Sending and receiving can run concurrently from different tasks.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::Mutex;

use crate::frame::{
    Channel, FrameError, Limits, NegotiatedProtocol, PROTOCOL_MAJOR, PROTOCOL_MINOR, PeerIdentity, PeerRole, ProtocolError,
    ProtocolOffer, SessionKey, read_frame, write_frame,
};
use crate::handshake::{Handshake, HandshakeError};

/// 1 MiB frames: room for a 256 KiB command result plus envelope.
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 1 << 20;
const MAX_IN_FLIGHT: u16 = 8;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);
/// Idle reads after the handshake may block indefinitely; writes may not.
const WRITE_DEADLINE: Duration = Duration::from_secs(30);
const READ_IDLE: Duration = Duration::from_secs(60 * 60 * 24 * 365);

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("handshake ended without a negotiated protocol")]
    Incomplete,
}

pub struct SessionParams {
    pub key: SessionKey,
    pub session_id: String,
    pub generation: u64,
    pub name: String,
    pub version: String,
    /// Identity of the running artifact (e.g. a hash of the binary).
    pub artifact_identity: String,
}

pub struct Sender<S> {
    channel: Arc<Mutex<Channel>>,
    writer: WriteHalf<S>,
    max_frame: u32,
}

pub struct Receiver<S> {
    channel: Arc<Mutex<Channel>>,
    reader: ReadHalf<S>,
    max_frame: u32,
}

fn offer(role: PeerRole, params: &SessionParams) -> ProtocolOffer {
    ProtocolOffer {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        peer: PeerIdentity {
            role,
            name: params.name.clone(),
            version: params.version.clone(),
            artifact_identity: params.artifact_identity.clone(),
        },
        feature_bits: 0,
        limits: Limits {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_in_flight: MAX_IN_FLIGHT,
            bootstrap_timeout_ms: u32::try_from(BOOTSTRAP_TIMEOUT.as_millis()).unwrap_or(u32::MAX),
        },
    }
}

/// Run the two-frame handshake for `role` and split the stream into a sender
/// and receiver sharing the authenticated channel state.
pub async fn establish<S>(
    mut stream: S,
    role: PeerRole,
    params: SessionParams,
) -> Result<(Sender<S>, Receiver<S>, NegotiatedProtocol), SessionError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let local = offer(role, &params);
    let mut channel = Channel::new(role, params.session_id, params.generation, params.key, DEFAULT_MAX_FRAME_BYTES)?;
    let mut handshake = Handshake::new(local)?;
    let bootstrap_max = DEFAULT_MAX_FRAME_BYTES;
    match role {
        PeerRole::Host => {
            let offer = handshake.start(&mut channel)?;
            write_frame(&mut stream, &offer, bootstrap_max, BOOTSTRAP_TIMEOUT).await?;
            let accept = read_frame(&mut stream, bootstrap_max, BOOTSTRAP_TIMEOUT).await?;
            handshake.receive(&mut channel, &accept)?;
        }
        PeerRole::Guest => {
            let offer = read_frame(&mut stream, bootstrap_max, BOOTSTRAP_TIMEOUT).await?;
            let accept = handshake.receive(&mut channel, &offer)?.ok_or(SessionError::Incomplete)?;
            write_frame(&mut stream, &accept, bootstrap_max, BOOTSTRAP_TIMEOUT).await?;
            handshake.complete_acceptance(&mut channel)?;
        }
    }
    let negotiated = handshake.negotiated().cloned().ok_or(SessionError::Incomplete)?;
    let max_frame = channel.max_frame_bytes();
    let channel = Arc::new(Mutex::new(channel));
    let (reader, writer) = tokio::io::split(stream);
    Ok((
        Sender { channel: channel.clone(), writer, max_frame },
        Receiver { channel, reader, max_frame },
        negotiated,
    ))
}

impl<S: AsyncWrite + Unpin> Sender<S> {
    pub async fn send<T: Serialize>(&mut self, message: &T) -> Result<(), SessionError> {
        let frame = self.channel.lock().await.seal(message)?;
        let result = write_frame(&mut self.writer, &frame, self.max_frame, WRITE_DEADLINE).await;
        if result.is_err() {
            self.channel.lock().await.retire();
        }
        Ok(result?)
    }
}

impl<S: AsyncRead + Unpin> Receiver<S> {
    /// Waits for the next message; any framing or authentication failure
    /// retires the channel for both halves.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<T, SessionError> {
        let frame = match read_frame(&mut self.reader, self.max_frame, READ_IDLE).await {
            Ok(frame) => frame,
            Err(error) => {
                self.channel.lock().await.retire();
                return Err(error.into());
            }
        };
        Ok(self.channel.lock().await.open(&frame)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{GuestMessage, HostMessage};

    fn params(key: [u8; 32]) -> SessionParams {
        SessionParams {
            key: SessionKey::from_bytes(key),
            session_id: "s-1".into(),
            generation: 1,
            name: "test".into(),
            version: "0".into(),
            artifact_identity: "test-artifact".into(),
        }
    }

    #[tokio::test]
    async fn host_and_guest_exchange_messages() {
        let (host_io, guest_io) = tokio::io::duplex(1 << 16);
        let guest = tokio::spawn(async move {
            let (mut tx, mut rx, _) = establish(guest_io, PeerRole::Guest, params([7; 32])).await.expect("guest");
            let msg: HostMessage = rx.recv().await.expect("recv");
            assert_eq!(msg, HostMessage::Shutdown);
            tx.send(&GuestMessage::Ready { commands: vec!["exec".into()] }).await.expect("send");
        });
        let (mut tx, mut rx, negotiated) = establish(host_io, PeerRole::Host, params([7; 32])).await.expect("host");
        assert_eq!(negotiated.remote_peer.role, PeerRole::Guest);
        tx.send(&HostMessage::Shutdown).await.expect("send");
        let reply: GuestMessage = rx.recv().await.expect("recv");
        assert_eq!(reply, GuestMessage::Ready { commands: vec!["exec".into()] });
        guest.await.expect("join");
    }

    #[tokio::test]
    async fn mismatched_keys_fail_the_handshake() {
        let (host_io, guest_io) = tokio::io::duplex(1 << 16);
        let guest = tokio::spawn(async move { establish(guest_io, PeerRole::Guest, params([1; 32])).await.is_err() });
        let host = establish(host_io, PeerRole::Host, params([2; 32])).await;
        assert!(host.is_err());
        assert!(guest.await.expect("join"));
    }
}
