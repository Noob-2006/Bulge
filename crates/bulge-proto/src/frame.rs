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
#[path = "frame_tests.rs"]
mod tests;
