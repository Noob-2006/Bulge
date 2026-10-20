//! Transport-neutral authenticated framing between the bulge host app and the
//! guest daemon.
//!
//! This module starts after the host has delivered a fresh [`SessionKey`],
//! session identifier, and nonzero generation to the guest out of band. It
//! provides the version, limit, generation, sequence, authentication, and
//! transport-length invariants shared by every adapter.

use std::{
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use hmac::{Hmac, KeyInit, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
};
use zeroize::Zeroize;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
/// Largest feature mask that every JSON implementation can represent exactly.
pub const MAX_FEATURE_BITS: u64 = (1 << 53) - 1;
const BOOTSTRAP_MINOR: u16 = 0;
static NEXT_CHANNEL_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

fn next_channel_instance_id(counter: &AtomicU64) -> Result<u64, ProtocolError> {
    // try_update requires Rust 1.95, newer than this crate's declared MSRV.
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current
            .checked_add(1)
            .ok_or(ProtocolError::ChannelInstanceIdExhausted)?;
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(previous) => return Ok(previous),
            Err(observed) => current = observed,
        }
    }
}

const FRAME_MAGIC: [u8; 4] = *b"BLGC";
const AUTH_TAG_BYTES: usize = 32;
const FIXED_HEADER_BYTES: usize = 4 + 2 + 2 + 1 + 8 + 8 + 2 + 4;
const PAYLOAD_LENGTH_OFFSET: usize = 4 + 2 + 2 + 1 + 8 + 8 + 2;
const MIN_FRAME_BYTES: u32 = 65;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerRole {
    Host,
    Guest,
}

impl PeerRole {
    const fn outgoing_direction(self) -> Direction {
        match self {
            Self::Host => Direction::HostToGuest,
            Self::Guest => Direction::GuestToHost,
        }
    }

    const fn expected_remote(self) -> Self {
        match self {
            Self::Host => Self::Guest,
            Self::Guest => Self::Host,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    HostToGuest,
    GuestToHost,
}

impl Direction {
    const fn wire_value(self) -> u8 {
        match self {
            Self::HostToGuest => 1,
            Self::GuestToHost => 2,
        }
    }

    fn from_wire(value: u8) -> Result<Self, FrameError> {
        match value {
            1 => Ok(Self::HostToGuest),
            2 => Ok(Self::GuestToHost),
            _ => Err(FrameError::InvalidDirection(value)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerIdentity {
    pub role: PeerRole,
    pub name: String,
    pub version: String,
    pub artifact_identity: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub max_frame_bytes: u32,
    pub max_in_flight: u16,
    pub bootstrap_timeout_ms: u32,
}

impl Limits {
    fn validate(self) -> Result<Self, ProtocolError> {
        if self.max_frame_bytes < MIN_FRAME_BYTES {
            return Err(ProtocolError::InvalidLimit("maxFrameBytes"));
        }
        if self.max_in_flight == 0 {
            return Err(ProtocolError::InvalidLimit("maxInFlight"));
        }
        if self.bootstrap_timeout_ms == 0 {
            return Err(ProtocolError::InvalidLimit("bootstrapTimeoutMs"));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolOffer {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub peer: PeerIdentity,
    pub feature_bits: u64,
    pub limits: Limits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedProtocol {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub feature_bits: u64,
    pub limits: Limits,
    pub remote_peer: PeerIdentity,
}

/// Negotiate additive features and limits without allowing either peer to
/// raise the other's local ceilings.
///
/// # Errors
///
/// Returns an error when roles or major versions are incompatible, or when
/// either peer offers an invalid limit or the local minor version is not
/// implemented.
pub fn negotiate(
    local: &ProtocolOffer,
    remote: &ProtocolOffer,
) -> Result<NegotiatedProtocol, ProtocolError> {
    let local_limits = local.limits.validate()?;
    let remote_limits = remote.limits.validate()?;

    if local.peer.role == remote.peer.role {
        return Err(ProtocolError::InvalidPeerRole);
    }
    if local.feature_bits > MAX_FEATURE_BITS || remote.feature_bits > MAX_FEATURE_BITS {
        return Err(ProtocolError::InvalidFeatureBits);
    }
    if local.protocol_major != PROTOCOL_MAJOR || remote.protocol_major != PROTOCOL_MAJOR {
        return Err(ProtocolError::UnsupportedMajor {
            local: local.protocol_major,
            remote: remote.protocol_major,
        });
    }
    if local.protocol_minor > PROTOCOL_MINOR {
        return Err(ProtocolError::UnsupportedLocalMinor(local.protocol_minor));
    }

    Ok(NegotiatedProtocol {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: local.protocol_minor.min(remote.protocol_minor),
        feature_bits: local.feature_bits & remote.feature_bits,
        limits: Limits {
            max_frame_bytes: local_limits
                .max_frame_bytes
                .min(remote_limits.max_frame_bytes),
            max_in_flight: local_limits.max_in_flight.min(remote_limits.max_in_flight),
            bootstrap_timeout_ms: local_limits
                .bootstrap_timeout_ms
                .min(remote_limits.bootstrap_timeout_ms),
        },
        remote_peer: remote.peer.clone(),
    })
}

/// A fresh 256-bit key supplied out of band by the host app.
pub struct SessionKey([u8; 32]);

impl SessionKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh key using the operating system random source.
    ///
    /// # Errors
    ///
    /// Returns an error when the operating system random source is unavailable.
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for SessionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionKey([redacted])")
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Authenticates frames for exactly one process session and generation.
///
/// Create a new instance after every process restart. Sequence numbers are
/// directional and start at one. A rejected frame never advances the receive
/// high-water mark.
pub struct Channel {
    instance_id: u64,
    role: PeerRole,
    protocol_minor: u16,
    session_id: String,
    generation: u64,
    key: SessionKey,
    max_frame_bytes: u32,
    frame_limit_locked: bool,
    send_sequence: u64,
    receive_sequence: u64,
    liveness: ChannelLiveness,
}

#[derive(Clone)]
pub(crate) struct ChannelLiveness(Arc<watch::Sender<bool>>);

impl ChannelLiveness {
    pub(crate) fn is_retired(&self) -> bool {
        *self.0.borrow()
    }

    #[allow(dead_code, reason = "transport owners await retirement in P2")]
    pub(crate) async fn retired(&self) {
        if self.is_retired() {
            return;
        }
        let mut receiver = self.0.subscribe();
        while !*receiver.borrow_and_update() {
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Channel {
    /// Create state for one role in one process-session generation.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized session identifier, a zero
    /// generation, or an undersized frame limit.
    pub fn new(
        role: PeerRole,
        session_id: String,
        generation: u64,
        key: SessionKey,
        max_frame_bytes: u32,
    ) -> Result<Self, ProtocolError> {
        if session_id.is_empty() || session_id.len() > usize::from(u16::MAX) {
            return Err(ProtocolError::InvalidSessionId);
        }
        if generation == 0 {
            return Err(ProtocolError::InvalidGeneration);
        }
        if (max_frame_bytes as usize) < minimum_frame_bytes(session_id.len()) {
            return Err(ProtocolError::InvalidLimit("maxFrameBytes"));
        }
        let instance_id = next_channel_instance_id(&NEXT_CHANNEL_INSTANCE_ID)?;

        Ok(Self {
            instance_id,
            role,
            protocol_minor: BOOTSTRAP_MINOR,
            session_id,
            generation,
            key,
            max_frame_bytes,
            frame_limit_locked: false,
            send_sequence: 0,
            receive_sequence: 0,
            liveness: ChannelLiveness(Arc::new(watch::channel(false).0)),
        })
    }

    /// Permanently retire this process-session channel.
    pub fn retire(&mut self) {
        self.key.0.zeroize();
        self.liveness.0.send_replace(true);
    }

    #[must_use]
    pub fn is_retired(&self) -> bool {
        self.liveness.is_retired()
    }

    #[allow(dead_code, reason = "transport owners await retirement in P2")]
    pub(crate) fn liveness(&self) -> ChannelLiveness {
        self.liveness.clone()
    }

    /// Return an opaque process-local identity for binding a state machine to
    /// this exact channel instance. The value has no wire or trust meaning.
    #[must_use]
    pub const fn instance_id(&self) -> u64 {
        self.instance_id
    }

    #[must_use]
    pub const fn role(&self) -> PeerRole {
        self.role
    }

    #[must_use]
    pub const fn max_frame_bytes(&self) -> u32 {
        self.max_frame_bytes
    }

    #[must_use]
    pub fn max_payload_bytes(&self) -> usize {
        self.max_frame_bytes as usize - FIXED_HEADER_BYTES - self.session_id.len() - AUTH_TAG_BYTES
    }

    /// Apply the negotiated frame ceiling without resetting channel sequence.
    ///
    /// # Errors
    ///
    /// Returns an error if the new limit cannot hold a minimal frame, would
    /// raise the ceiling used to bootstrap this channel, or configuration has
    /// locked the negotiated ceiling for the rest of the channel generation.
    pub fn lower_frame_limit(
        &mut self,
        negotiated_max_frame_bytes: u32,
    ) -> Result<(), ProtocolError> {
        if self.frame_limit_locked {
            return Err(ProtocolError::FrameLimitLocked);
        }
        if (negotiated_max_frame_bytes as usize) < minimum_frame_bytes(self.session_id.len()) {
            return Err(ProtocolError::InvalidLimit("maxFrameBytes"));
        }
        if negotiated_max_frame_bytes > self.max_frame_bytes {
            return Err(ProtocolError::LimitIncrease {
                current: self.max_frame_bytes,
                requested: negotiated_max_frame_bytes,
            });
        }
        self.max_frame_bytes = negotiated_max_frame_bytes;
        Ok(())
    }

    #[allow(dead_code, reason = "configuration exchange locks the ceiling in P2")]
    pub(crate) fn lock_frame_limit(&mut self) {
        self.frame_limit_locked = true;
    }

    /// Apply the authenticated protocol selection after the bootstrap exchange.
    ///
    /// Bootstrap frames always use minor zero so an older peer can read the
    /// offer. Both peers apply the independently verified selection only after
    /// the final bootstrap frame, without resetting directional sequence state.
    ///
    /// # Errors
    ///
    /// Returns an error if the selection is unsupported or would raise the
    /// channel's local frame ceiling.
    pub fn apply_negotiated_protocol(
        &mut self,
        negotiated: &NegotiatedProtocol,
    ) -> Result<(), ProtocolError> {
        if negotiated.protocol_major != PROTOCOL_MAJOR {
            return Err(ProtocolError::UnsupportedMajor {
                local: PROTOCOL_MAJOR,
                remote: negotiated.protocol_major,
            });
        }
        if negotiated.protocol_minor > PROTOCOL_MINOR {
            return Err(ProtocolError::UnsupportedLocalMinor(
                negotiated.protocol_minor,
            ));
        }
        self.lower_frame_limit(negotiated.limits.max_frame_bytes)?;
        self.protocol_minor = negotiated.protocol_minor;
        Ok(())
    }

    /// Serialize and authenticate the next outgoing payload.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails, the encoded frame exceeds
    /// the local ceiling, the sequence has been exhausted, or the channel was
    /// retired by an inbound or transport failure.
    pub fn seal<T: Serialize>(&mut self, payload: &T) -> Result<Vec<u8>, FrameError> {
        if self.is_retired() {
            return Err(FrameError::ChannelRetired);
        }
        let sequence = self
            .send_sequence
            .checked_add(1)
            .ok_or(FrameError::SequenceExhausted)?;
        let session_id = self.session_id.as_bytes();
        let minimum_capacity = FIXED_HEADER_BYTES
            .checked_add(session_id.len())
            .and_then(|size| size.checked_add(AUTH_TAG_BYTES))
            .ok_or(FrameError::FrameTooLarge {
                size: u64::MAX,
                limit: self.max_frame_bytes,
            })?;
        if minimum_capacity >= self.max_frame_bytes as usize {
            return Err(FrameError::FrameTooLarge {
                size: minimum_capacity.saturating_add(1) as u64,
                limit: self.max_frame_bytes,
            });
        }

        let mut frame = Vec::with_capacity(minimum_capacity);
        frame.extend_from_slice(&FRAME_MAGIC);
        frame.extend_from_slice(&PROTOCOL_MAJOR.to_be_bytes());
        frame.extend_from_slice(&self.protocol_minor.to_be_bytes());
        frame.push(self.role.outgoing_direction().wire_value());
        frame.extend_from_slice(&self.generation.to_be_bytes());
        frame.extend_from_slice(&sequence.to_be_bytes());
        let session_len =
            u16::try_from(session_id.len()).map_err(|_| FrameError::InvalidSessionId)?;
        frame.extend_from_slice(&session_len.to_be_bytes());
        frame.extend_from_slice(&0_u32.to_be_bytes());
        frame.extend_from_slice(session_id);

        let payload_start = frame.len();
        let max_authenticated_len = self.max_frame_bytes as usize - AUTH_TAG_BYTES;
        let serialization = {
            let mut writer = BoundedFrameWriter::new(&mut frame, max_authenticated_len);
            match serde_json::to_writer(&mut writer, payload) {
                Ok(()) => Ok(()),
                Err(_) if writer.exceeded => Err(FrameError::FrameTooLarge {
                    size: u64::from(self.max_frame_bytes) + 1,
                    limit: self.max_frame_bytes,
                }),
                Err(error) => Err(FrameError::Serialize(error)),
            }
        };
        serialization?;

        let payload_len = u32::try_from(frame.len() - payload_start).map_err(|_| {
            FrameError::FrameTooLarge {
                size: u64::MAX,
                limit: self.max_frame_bytes,
            }
        })?;
        frame[PAYLOAD_LENGTH_OFFSET..PAYLOAD_LENGTH_OFFSET + 4]
            .copy_from_slice(&payload_len.to_be_bytes());

        let mut mac = HmacSha256::new_from_slice(&self.key.0)
            .map_err(|_| FrameError::Authentication)?;
        mac.update(&frame);
        frame.extend_from_slice(&mac.finalize().into_bytes());
        self.send_sequence = sequence;
        Ok(frame)
    }

    /// Authenticate, validate, and deserialize the next incoming frame.
    ///
    /// # Errors
    ///
    /// Returns an error for authentication, session, generation, direction,
    /// sequence, version, size, framing, or payload failures.
    pub fn open<T: DeserializeOwned>(&mut self, frame: &[u8]) -> Result<T, FrameError> {
        if self.is_retired() {
            return Err(FrameError::ChannelRetired);
        }

        let result = self.open_active(frame);
        if result.is_err() {
            self.retire();
        }
        result
    }

    fn open_active<T: DeserializeOwned>(&mut self, frame: &[u8]) -> Result<T, FrameError> {
        if frame.len() > self.max_frame_bytes as usize {
            return Err(FrameError::FrameTooLarge {
                size: frame.len() as u64,
                limit: self.max_frame_bytes,
            });
        }
        let minimum = FIXED_HEADER_BYTES + AUTH_TAG_BYTES;
        if frame.len() < minimum {
            return Err(FrameError::Truncated);
        }

        let authenticated_len = frame.len() - AUTH_TAG_BYTES;
        let (authenticated, supplied_tag) = frame.split_at(authenticated_len);
        let mut mac = HmacSha256::new_from_slice(&self.key.0)
            .map_err(|_| FrameError::Authentication)?;
        mac.update(authenticated);
        mac.verify_slice(supplied_tag)
            .map_err(|_| FrameError::Authentication)?;

        let mut cursor = 0;
        let magic = take::<4>(authenticated, &mut cursor)?;
        if magic != FRAME_MAGIC {
            return Err(FrameError::InvalidMagic);
        }
        let major = u16::from_be_bytes(take::<2>(authenticated, &mut cursor)?);
        let minor = u16::from_be_bytes(take::<2>(authenticated, &mut cursor)?);
        if major != PROTOCOL_MAJOR || minor != self.protocol_minor {
            return Err(FrameError::UnsupportedVersion { major, minor });
        }
        let direction = Direction::from_wire(take::<1>(authenticated, &mut cursor)?[0])?;
        if direction != self.role.expected_remote().outgoing_direction() {
            return Err(FrameError::WrongDirection);
        }
        let generation = u64::from_be_bytes(take::<8>(authenticated, &mut cursor)?);
        if generation != self.generation {
            return Err(FrameError::WrongGeneration {
                expected: self.generation,
                received: generation,
            });
        }
        let sequence = u64::from_be_bytes(take::<8>(authenticated, &mut cursor)?);
        let expected_sequence = self
            .receive_sequence
            .checked_add(1)
            .ok_or(FrameError::SequenceExhausted)?;
        if sequence != expected_sequence {
            return Err(FrameError::UnexpectedSequence {
                expected: expected_sequence,
                received: sequence,
            });
        }
        let session_len = usize::from(u16::from_be_bytes(take::<2>(authenticated, &mut cursor)?));
        let payload_len =
            usize::try_from(u32::from_be_bytes(take::<4>(authenticated, &mut cursor)?))
                .map_err(|_| FrameError::Truncated)?;
        let session = take_slice(authenticated, &mut cursor, session_len)?;
        if session != self.session_id.as_bytes() {
            return Err(FrameError::WrongSession);
        }
        let payload = take_slice(authenticated, &mut cursor, payload_len)?;
        if cursor != authenticated.len() {
            return Err(FrameError::TrailingBytes);
        }

        let decoded = serde_json::from_slice(payload).map_err(FrameError::Deserialize)?;
        self.receive_sequence = sequence;
        Ok(decoded)
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.liveness.0.send_replace(true);
    }
}

const fn minimum_frame_bytes(session_id_bytes: usize) -> usize {
    FIXED_HEADER_BYTES + session_id_bytes + AUTH_TAG_BYTES + 1
}

struct BoundedFrameWriter<'a> {
    frame: &'a mut Vec<u8>,
    max_len: usize,
    exceeded: bool,
}

impl<'a> BoundedFrameWriter<'a> {
    const fn new(frame: &'a mut Vec<u8>, max_len: usize) -> Self {
        Self {
            frame,
            max_len,
            exceeded: false,
        }
    }
}

impl std::io::Write for BoundedFrameWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let remaining = self.max_len.saturating_sub(self.frame.len());
        if bytes.len() > remaining {
            self.exceeded = true;
            return Err(std::io::Error::other("frame limit exceeded"));
        }
        self.frame.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], FrameError> {
    let value = take_slice(bytes, cursor, N)?;
    value.try_into().map_err(|_| FrameError::Truncated)
}

fn take_slice<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], FrameError> {
    let end = cursor.checked_add(length).ok_or(FrameError::Truncated)?;
    let value = bytes.get(*cursor..end).ok_or(FrameError::Truncated)?;
    *cursor = end;
    Ok(value)
}

/// Read one length-prefixed frame while applying the local ceiling before
/// allocating the payload buffer.
///
/// # Errors
///
/// Returns an error for a zero or oversized frame, an I/O failure, or expiry
/// of the local deadline.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_frame_bytes: u32,
    deadline: Duration,
) -> Result<Vec<u8>, FrameError> {
    if max_frame_bytes < MIN_FRAME_BYTES {
        return Err(FrameError::InvalidFrameLimit(max_frame_bytes));
    }
    let operation = async {
        let length = reader.read_u32().await.map_err(FrameError::Io)?;
        if length == 0 || length > max_frame_bytes {
            return Err(FrameError::FrameTooLarge {
                size: u64::from(length),
                limit: max_frame_bytes,
            });
        }
        let mut frame = vec![0_u8; length as usize];
        reader
            .read_exact(&mut frame)
            .await
            .map_err(FrameError::Io)?;
        Ok(frame)
    };
    tokio::time::timeout(deadline, operation)
        .await
        .map_err(|_| FrameError::Deadline)?
}

/// Write one bounded, length-prefixed frame within a local deadline.
///
/// # Errors
///
/// Returns an error for a zero or oversized frame, an I/O failure, or expiry
/// of the local deadline.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &[u8],
    max_frame_bytes: u32,
    deadline: Duration,
) -> Result<(), FrameError> {
    if max_frame_bytes < MIN_FRAME_BYTES {
        return Err(FrameError::InvalidFrameLimit(max_frame_bytes));
    }
    let length = u32::try_from(frame.len()).map_err(|_| FrameError::FrameTooLarge {
        size: frame.len() as u64,
        limit: max_frame_bytes,
    })?;
    if length == 0 || length > max_frame_bytes {
        return Err(FrameError::FrameTooLarge {
            size: u64::from(length),
            limit: max_frame_bytes,
        });
    }

    let operation = async {
        writer
            .write_all(&length.to_be_bytes())
            .await
            .map_err(FrameError::Io)?;
        writer.write_all(frame).await.map_err(FrameError::Io)?;
        writer.flush().await.map_err(FrameError::Io)
    };
    tokio::time::timeout(deadline, operation)
        .await
        .map_err(|_| FrameError::Deadline)?
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("channel instance id space exhausted")]
    ChannelInstanceIdExhausted,
    #[error("feature bits exceed the portable JSON integer range")]
    InvalidFeatureBits,
    #[error("peers must have complementary roles")]
    InvalidPeerRole,
    #[error("invalid limit: {0}")]
    InvalidLimit(&'static str),
    #[error("invalid session id")]
    InvalidSessionId,
    #[error("negotiated frame limit cannot increase from {current} to {requested}")]
    LimitIncrease { current: u32, requested: u32 },
    #[error("frame limit is locked for this configured channel")]
    FrameLimitLocked,
    #[error("generation must be nonzero")]
    InvalidGeneration,
    #[error("unsupported protocol major version (local {local}, remote {remote})")]
    UnsupportedMajor { local: u16, remote: u16 },
    #[error("local protocol minor version {0} is not implemented")]
    UnsupportedLocalMinor(u16),
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("frame authentication failed")]
    Authentication,
    #[error("channel is retired")]
    ChannelRetired,
    #[error("frame deadline exceeded")]
    Deadline,
    #[error("frame length {size} exceeds local limit {limit}")]
    FrameTooLarge { size: u64, limit: u32 },
    #[error("invalid frame direction {0}")]
    InvalidDirection(u8),
    #[error("invalid frame magic")]
    InvalidMagic,
    #[error("invalid local frame limit {0}")]
    InvalidFrameLimit(u32),
    #[error("invalid frame session id")]
    InvalidSessionId,
    #[error("frame belongs to another generation (expected {expected}, received {received})")]
    WrongGeneration { expected: u64, received: u64 },
    #[error("frame belongs to another session")]
    WrongSession,
    #[error("frame direction is invalid for this peer")]
    WrongDirection,
    #[error("sequence exhausted; rotate the generation")]
    SequenceExhausted,
    #[error("unexpected sequence (expected {expected}, received {received})")]
    UnexpectedSequence { expected: u64, received: u64 },
    #[error("frame is truncated")]
    Truncated,
    #[error("frame contains trailing bytes")]
    TrailingBytes,
    #[error("unsupported frame version {major}.{minor}")]
    UnsupportedVersion { major: u16, minor: u16 },
    #[error("payload serialization failed")]
    Serialize(#[source] serde_json::Error),
    #[error("payload deserialization failed")]
    Deserialize(#[source] serde_json::Error),
    #[error("transport failed")]
    Io(#[source] std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::*;
    use serde::ser::SerializeSeq;
    use serde::Deserialize;
    use serde_json::{json, Value};
    use tokio::io::AsyncWriteExt;

    const KEY: [u8; 32] = [0x5a; 32];

    /// Known-answer vector for the frame format: key `[0x5a; 32]`, session
    /// `session-7`, generation `7`, host role, sequence `1`, payload
    /// `{"requestId":"abc","type":"probe"}`. The magic is `BLGC`; this hex
    /// string pins every header field, the payload bytes, and the HMAC tag.
    const KNOWN_ANSWER_FRAME_HEX: &str = concat!(
        "424c4743",         // magic "BLGC"
        "0001",             // protocol major 1
        "0000",             // protocol minor 0
        "01",               // host -> guest
        "0000000000000007", // generation 7
        "0000000000000001", // sequence 1
        "0009",             // session id length 9
        "00000022",         // payload length 34
        "73657373696f6e2d37", // "session-7"
        "7b22726571756573744964223a22616263222c2274797065223a2270726f6265227d",
        "339a7c12a12bc7d3634b1132305ccf1fb9b6e68e50c19595b2e0192750ff764b",
    );

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NegotiationFixture {
        schema_version: u8,
        local_offer: ProtocolOffer,
        remote_offer: ProtocolOffer,
        selected_feature_bits: u64,
    }

    struct CountingPayload {
        serialized: Arc<AtomicUsize>,
    }

    impl Serialize for CountingPayload {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(1_000_000))?;
            for value in 0..1_000_000_u32 {
                self.serialized.fetch_add(1, Ordering::Relaxed);
                sequence.serialize_element(&value)?;
            }
            sequence.end()
        }
    }

    fn decode_hex(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "hex input must have an even length");
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = char::from(pair[0]).to_digit(16).expect("hex digit");
                let low = char::from(pair[1]).to_digit(16).expect("hex digit");
                u8::try_from((high << 4) | low).expect("byte")
            })
            .collect()
    }

    fn offer(role: PeerRole, limits: Limits) -> ProtocolOffer {
        ProtocolOffer {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            peer: PeerIdentity {
                role,
                name: match role {
                    PeerRole::Host => "test-host",
                    PeerRole::Guest => "test-guest",
                }
                .into(),
                version: "1.0.0".into(),
                artifact_identity: "sha256:test-only".into(),
            },
            feature_bits: 0b0111,
            limits,
        }
    }

    fn channel(role: PeerRole, generation: u64) -> Channel {
        Channel::new(
            role,
            "session-7".into(),
            generation,
            SessionKey::from_bytes(KEY),
            4096,
        )
        .unwrap()
    }

    #[test]
    fn channel_instance_id_exhaustion_never_wraps_or_reuses_an_id() {
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(next_channel_instance_id(&counter).unwrap(), u64::MAX - 1);
        for _ in 0..2 {
            assert!(matches!(
                next_channel_instance_id(&counter),
                Err(ProtocolError::ChannelInstanceIdExhausted)
            ));
            assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        }
    }

    #[test]
    fn frame_limit_must_fit_the_specific_session_identifier() {
        let session_id = "longer-session-id";
        assert!(matches!(
            Channel::new(
                PeerRole::Guest,
                session_id.into(),
                1,
                SessionKey::from_bytes(KEY),
                MIN_FRAME_BYTES,
            ),
            Err(ProtocolError::InvalidLimit("maxFrameBytes"))
        ));

        let exact_minimum = u32::try_from(minimum_frame_bytes(session_id.len())).unwrap();
        let mut channel = Channel::new(
            PeerRole::Guest,
            session_id.into(),
            1,
            SessionKey::from_bytes(KEY),
            exact_minimum,
        )
        .unwrap();
        assert_eq!(channel.max_payload_bytes(), 1);
        assert!(matches!(
            channel.lower_frame_limit(exact_minimum - 1),
            Err(ProtocolError::InvalidLimit("maxFrameBytes"))
        ));
        assert_eq!(channel.seal(&0_u8).unwrap().len(), exact_minimum as usize);
    }

    #[test]
    fn known_answer_frame_is_byte_exact_and_decodable() {
        let expected_frame = decode_hex(KNOWN_ANSWER_FRAME_HEX);
        let payload = json!({"type": "probe", "requestId": "abc"});

        let mut host = channel(PeerRole::Host, 7);
        assert_eq!(host.seal(&payload).unwrap(), expected_frame);

        let mut guest = channel(PeerRole::Guest, 7);
        assert_eq!(guest.open::<Value>(&expected_frame).unwrap(), payload);
    }

    #[test]
    fn negotiation_intersects_features_and_uses_lower_limits() {
        let local = offer(
            PeerRole::Host,
            Limits {
                max_frame_bytes: 4096,
                max_in_flight: 8,
                bootstrap_timeout_ms: 2_000,
            },
        );
        let mut remote = offer(
            PeerRole::Guest,
            Limits {
                max_frame_bytes: 2048,
                max_in_flight: 16,
                bootstrap_timeout_ms: 1_000,
            },
        );
        remote.feature_bits = 0b1011;

        let negotiated = negotiate(&local, &remote).unwrap();
        assert_eq!(negotiated.feature_bits, 0b0011);
        assert_eq!(negotiated.limits.max_frame_bytes, 2048);
        assert_eq!(negotiated.limits.max_in_flight, 8);
        assert_eq!(negotiated.limits.bootstrap_timeout_ms, 1_000);
        assert_eq!(negotiated.remote_peer, remote.peer);
    }

    #[test]
    fn negotiation_rejects_unknown_major_and_same_role() {
        let limits = Limits {
            max_frame_bytes: 4096,
            max_in_flight: 8,
            bootstrap_timeout_ms: 1_000,
        };
        let local = offer(PeerRole::Host, limits);
        let mut remote = offer(PeerRole::Guest, limits);
        remote.protocol_major += 1;
        assert!(matches!(
            negotiate(&local, &remote),
            Err(ProtocolError::UnsupportedMajor { .. })
        ));

        let same_role = offer(PeerRole::Host, limits);
        assert_eq!(
            negotiate(&local, &same_role),
            Err(ProtocolError::InvalidPeerRole)
        );

        let mut unsupported_local = local.clone();
        unsupported_local.protocol_minor += 1;
        assert_eq!(
            negotiate(&unsupported_local, &remote),
            Err(ProtocolError::UnsupportedMajor {
                local: PROTOCOL_MAJOR,
                remote: PROTOCOL_MAJOR + 1
            })
        );

        let compatible_remote = offer(PeerRole::Guest, limits);
        assert_eq!(
            negotiate(&unsupported_local, &compatible_remote),
            Err(ProtocolError::UnsupportedLocalMinor(1))
        );
    }

    #[test]
    fn negotiation_rejects_feature_bits_that_json_cannot_preserve() {
        let limits = Limits {
            max_frame_bytes: 4096,
            max_in_flight: 8,
            bootstrap_timeout_ms: 1_000,
        };
        let mut local = offer(PeerRole::Host, limits);
        let mut remote = offer(PeerRole::Guest, limits);

        local.feature_bits = MAX_FEATURE_BITS;
        remote.feature_bits = MAX_FEATURE_BITS;
        assert_eq!(
            negotiate(&local, &remote).unwrap().feature_bits,
            MAX_FEATURE_BITS
        );

        remote.feature_bits += 1;
        assert_eq!(
            negotiate(&local, &remote),
            Err(ProtocolError::InvalidFeatureBits)
        );
    }

    #[test]
    fn negotiation_preserves_features_above_32_bits() {
        // The reference fixture is inlined so the crate has no dependency on
        // the reference checkout. The selected mask above 2^32 must survive
        // JSON decoding and the intersection without truncation.
        let fixture: NegotiationFixture = serde_json::from_str(
            r#"{
                "schemaVersion": 1,
                "localOffer": {
                    "protocolMajor": 1,
                    "protocolMinor": 0,
                    "peer": {
                        "role": "host",
                        "name": "fixture-host",
                        "version": "1.0.0",
                        "artifactIdentity": "sha256:fixture-host"
                    },
                    "featureBits": 4503599627370499,
                    "limits": {
                        "maxFrameBytes": 4096,
                        "maxInFlight": 8,
                        "bootstrapTimeoutMs": 1000
                    }
                },
                "remoteOffer": {
                    "protocolMajor": 1,
                    "protocolMinor": 0,
                    "peer": {
                        "role": "guest",
                        "name": "fixture-guest",
                        "version": "1.0.0",
                        "artifactIdentity": "sha256:fixture-guest"
                    },
                    "featureBits": 4503599627370501,
                    "limits": {
                        "maxFrameBytes": 2048,
                        "maxInFlight": 4,
                        "bootstrapTimeoutMs": 500
                    }
                },
                "selectedFeatureBits": 4503599627370497
            }"#,
        )
        .unwrap();
        assert_eq!(fixture.schema_version, 1);
        assert!(fixture.selected_feature_bits > u64::from(u32::MAX));
        assert_eq!(
            negotiate(&fixture.local_offer, &fixture.remote_offer)
                .unwrap()
                .feature_bits,
            fixture.selected_feature_bits
        );
    }

    #[test]
    fn negotiated_limit_can_only_lower_an_active_channel() {
        let mut channel = channel(PeerRole::Host, 7);
        channel.lower_frame_limit(2048).unwrap();
        assert_eq!(
            channel.lower_frame_limit(4096),
            Err(ProtocolError::LimitIncrease {
                current: 2048,
                requested: 4096
            })
        );
        assert_eq!(
            channel.lower_frame_limit(MIN_FRAME_BYTES - 1),
            Err(ProtocolError::InvalidLimit("maxFrameBytes"))
        );
    }

    #[test]
    fn authenticated_frame_round_trips_and_replay_fails_closed() {
        let mut host = channel(PeerRole::Host, 7);
        let mut guest = channel(PeerRole::Guest, 7);
        let frame = host
            .seal(&json!({"type":"probe","requestId":"abc"}))
            .unwrap();

        let decoded: Value = guest.open(&frame).unwrap();
        assert_eq!(decoded["requestId"], "abc");
        assert!(matches!(
            guest.open::<Value>(&frame),
            Err(FrameError::UnexpectedSequence {
                expected: 2,
                received: 1
            })
        ));
    }

    #[test]
    fn skipped_sequence_is_rejected_without_advancing_the_high_water_mark() {
        let mut host = channel(PeerRole::Host, 7);
        let mut guest = channel(PeerRole::Guest, 7);
        let first = host.seal(&json!({"n": 1})).unwrap();
        let second = host.seal(&json!({"n": 2})).unwrap();

        assert!(matches!(
            guest.open::<Value>(&second),
            Err(FrameError::UnexpectedSequence {
                expected: 1,
                received: 2
            })
        ));
        assert!(guest.is_retired());
        assert!(matches!(
            guest.open::<Value>(&first),
            Err(FrameError::ChannelRetired)
        ));
        assert!(matches!(
            guest.seal(&json!({"n": 3})),
            Err(FrameError::ChannelRetired)
        ));
    }

    #[test]
    fn negotiated_protocol_updates_active_header_without_resetting_sequence() {
        let local = offer(
            PeerRole::Host,
            Limits {
                max_frame_bytes: 4096,
                max_in_flight: 8,
                bootstrap_timeout_ms: 1_000,
            },
        );
        let remote = offer(
            PeerRole::Guest,
            Limits {
                max_frame_bytes: 2048,
                max_in_flight: 4,
                bootstrap_timeout_ms: 500,
            },
        );
        let negotiated = negotiate(&local, &remote).unwrap();
        let mut host = channel(PeerRole::Host, 7);
        let mut guest = channel(PeerRole::Guest, 7);

        let bootstrap = host.seal(&json!({"type":"offer"})).unwrap();
        assert_eq!(
            guest.open::<Value>(&bootstrap).unwrap(),
            json!({"type":"offer"})
        );
        host.apply_negotiated_protocol(&negotiated).unwrap();
        guest.apply_negotiated_protocol(&negotiated).unwrap();

        let active = host.seal(&json!({"type":"active"})).unwrap();
        assert_eq!(
            u16::from_be_bytes(active[6..8].try_into().unwrap()),
            negotiated.protocol_minor
        );
        assert_eq!(u64::from_be_bytes(active[17..25].try_into().unwrap()), 2);
        assert_eq!(
            guest.open::<Value>(&active).unwrap(),
            json!({"type":"active"})
        );
    }

    #[test]
    fn outbound_serialization_stops_at_frame_ceiling_without_advancing_sequence() {
        let serialized = Arc::new(AtomicUsize::new(0));
        let mut host = Channel::new(
            PeerRole::Host,
            "session-7".into(),
            7,
            SessionKey::from_bytes(KEY),
            128,
        )
        .unwrap();
        let oversized = host.seal(&CountingPayload {
            serialized: Arc::clone(&serialized),
        });
        assert!(matches!(
            oversized,
            Err(FrameError::FrameTooLarge {
                size: 129,
                limit: 128
            })
        ));
        assert!(serialized.load(Ordering::Relaxed) < 100);

        let frame = host.seal(&json!({"ok":true})).unwrap();
        let mut guest = Channel::new(
            PeerRole::Guest,
            "session-7".into(),
            7,
            SessionKey::from_bytes(KEY),
            128,
        )
        .unwrap();
        assert_eq!(guest.open::<Value>(&frame).unwrap(), json!({"ok":true}));
    }

    #[test]
    fn authentication_failure_permanently_retires_channel() {
        let mut host = channel(PeerRole::Host, 7);
        let mut guest = channel(PeerRole::Guest, 7);
        let valid = host.seal(&json!({"type":"probe"})).unwrap();
        let mut tampered = valid.clone();
        tampered[FIXED_HEADER_BYTES] ^= 1;

        assert!(matches!(
            guest.open::<Value>(&tampered),
            Err(FrameError::Authentication)
        ));
        assert!(guest.is_retired());
        assert!(matches!(
            guest.open::<Value>(&valid),
            Err(FrameError::ChannelRetired)
        ));
        assert!(matches!(
            guest.seal(&json!({"type":"status"})),
            Err(FrameError::ChannelRetired)
        ));
    }

    #[test]
    fn tampering_with_any_frame_byte_fails_closed() {
        let payload = json!({"type":"probe","requestId":"abc"});
        let mut host = channel(PeerRole::Host, 7);
        let valid = host.seal(&payload).unwrap();

        for index in 0..valid.len() {
            let mut guest = channel(PeerRole::Guest, 7);
            let mut tampered = valid.clone();
            tampered[index] ^= 0x80;
            assert!(
                guest.open::<Value>(&tampered).is_err(),
                "tampered byte {index} was accepted"
            );
            assert!(guest.is_retired(), "tamper at {index} did not poison");
            assert!(matches!(
                guest.open::<Value>(&valid),
                Err(FrameError::ChannelRetired)
            ));
            assert!(matches!(
                guest.seal(&payload),
                Err(FrameError::ChannelRetired)
            ));
        }
    }

    #[test]
    fn retired_generation_and_wrong_direction_are_rejected() {
        let mut old_host = channel(PeerRole::Host, 6);
        let mut current_guest = channel(PeerRole::Guest, 7);
        let old = old_host.seal(&json!({"type":"probe"})).unwrap();
        assert!(matches!(
            current_guest.open::<Value>(&old),
            Err(FrameError::WrongGeneration {
                expected: 7,
                received: 6
            })
        ));

        let mut another_host = channel(PeerRole::Host, 7);
        let outgoing = another_host.seal(&json!({"type":"probe"})).unwrap();
        let mut reflecting_host = channel(PeerRole::Host, 7);
        assert!(matches!(
            reflecting_host.open::<Value>(&outgoing),
            Err(FrameError::WrongDirection)
        ));
        assert!(reflecting_host.is_retired());
    }

    #[tokio::test]
    async fn bounded_reader_rejects_length_before_payload_allocation() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_all(&4097_u32.to_be_bytes()).await.unwrap();

        assert!(matches!(
            read_frame(&mut reader, 4096, Duration::from_secs(1)).await,
            Err(FrameError::FrameTooLarge {
                size: 4097,
                limit: 4096
            })
        ));

        assert!(matches!(
            read_frame(&mut reader, MIN_FRAME_BYTES - 1, Duration::from_secs(1)).await,
            Err(FrameError::InvalidFrameLimit(_))
        ));
    }

    #[tokio::test]
    async fn bounded_transport_round_trips_and_enforces_deadline() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        write_frame(&mut writer, b"frame", 128, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut reader, 128, Duration::from_secs(1))
                .await
                .unwrap(),
            b"frame"
        );

        assert!(matches!(
            read_frame(&mut reader, 128, Duration::from_millis(1)).await,
            Err(FrameError::Deadline)
        ));
    }

    #[test]
    fn session_key_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", SessionKey::from_bytes(KEY)),
            "SessionKey([redacted])"
        );
    }

    #[test]
    fn minimum_frame_size_matches_wire_contract() {
        assert_eq!(
            MIN_FRAME_BYTES as usize,
            FIXED_HEADER_BYTES + AUTH_TAG_BYTES + 2
        );
    }
}
