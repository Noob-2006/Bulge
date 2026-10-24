//! Authenticated offer/accept state machine for the host/guest protocol.
//!
//! The host app drives one [`Handshake`] per peer. The host sends an
//! authenticated `offer`, the guest independently negotiates against its own
//! offer and replies with one authenticated `accept`, and the host
//! independently recomputes the selection. A handshake is bound to exactly one
//! [`Channel`] instance and accepts only that two-frame ordering.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::frame::{
    Channel, FrameError, Limits, NegotiatedProtocol, PeerIdentity, PeerRole, ProtocolError,
    ProtocolOffer, negotiate,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandshakeState {
    Starting,
    AwaitingAcceptance,
    AcceptancePending,
    Authenticated,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolSelection {
    pub protocol_major: u16,
    pub protocol_minor: u16,
    pub feature_bits: u64,
    pub limits: Limits,
}

impl From<&NegotiatedProtocol> for ProtocolSelection {
    fn from(negotiated: &NegotiatedProtocol) -> Self {
        Self {
            protocol_major: negotiated.protocol_major,
            protocol_minor: negotiated.protocol_minor,
            feature_bits: negotiated.feature_bits,
            limits: negotiated.limits,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum HandshakeMessage {
    Offer {
        offer: ProtocolOffer,
    },
    Accept {
        offer: ProtocolOffer,
        selection: ProtocolSelection,
    },
}

/// Drives the two-frame authenticated protocol handshake for one peer.
pub struct Handshake {
    local_offer: ProtocolOffer,
    state: HandshakeState,
    negotiated: Option<NegotiatedProtocol>,
    pending_negotiated: Option<NegotiatedProtocol>,
    channel_instance_id: Option<u64>,
}

impl Handshake {
    /// Create a handshake for a host or guest offer.
    ///
    /// # Errors
    ///
    /// Returns an error when the local offer is invalid or uses an unsupported
    /// protocol version.
    pub fn new(local_offer: ProtocolOffer) -> Result<Self, HandshakeError> {
        validate_local_offer(&local_offer)?;
        Ok(Self {
            local_offer,
            state: HandshakeState::Starting,
            negotiated: None,
            pending_negotiated: None,
            channel_instance_id: None,
        })
    }

    #[must_use]
    pub const fn state(&self) -> HandshakeState {
        self.state
    }

    #[must_use]
    pub const fn local_role(&self) -> PeerRole {
        self.local_offer.peer.role
    }

    #[must_use]
    pub const fn local_peer(&self) -> &PeerIdentity {
        &self.local_offer.peer
    }

    #[allow(dead_code, reason = "transport owners inspect the binding in P2")]
    pub(crate) const fn bound_channel_instance_id(&self) -> Option<u64> {
        self.channel_instance_id
    }

    #[must_use]
    pub const fn negotiated(&self) -> Option<&NegotiatedProtocol> {
        self.negotiated.as_ref()
    }

    /// Encode the host's initial authenticated offer.
    ///
    /// # Errors
    ///
    /// Returns an error when called by a guest, called out of order, or when
    /// the offer cannot be encoded within the bootstrap frame ceiling.
    pub fn start(&mut self, channel: &mut Channel) -> Result<Vec<u8>, HandshakeError> {
        if let Err(error) = self.bind_channel(channel) {
            channel.retire();
            return Err(error);
        }
        if channel.role() != self.local_offer.peer.role {
            return self.fail(channel, HandshakeError::ChannelRoleMismatch);
        }
        if self.local_offer.peer.role != PeerRole::Host {
            return self.fail(channel, HandshakeError::HostMustInitiate);
        }
        if self.state != HandshakeState::Starting {
            return self.fail(channel, HandshakeError::UnexpectedMessage);
        }

        let frame = match channel.seal(&HandshakeMessage::Offer {
            offer: self.local_offer.clone(),
        }) {
            Ok(frame) => frame,
            Err(error) => return self.fail(channel, HandshakeError::Frame(error)),
        };
        self.state = HandshakeState::AwaitingAcceptance;
        Ok(frame)
    }

    /// Consume one authenticated handshake frame and optionally return the
    /// guest's authenticated acceptance frame.
    ///
    /// # Errors
    ///
    /// Returns an error for framing/authentication failure, incompatible or
    /// forged negotiation, wrong peer roles, or invalid message ordering.
    /// Frame and state-machine errors permanently retire the bound channel and
    /// handshake. A different channel instance is rejected before processing:
    /// only that supplied replacement is retired, and the bound handshake is
    /// unchanged.
    pub fn receive(
        &mut self,
        channel: &mut Channel,
        frame: &[u8],
    ) -> Result<Option<Vec<u8>>, HandshakeError> {
        if let Err(error) = self.bind_channel(channel) {
            channel.retire();
            return Err(error);
        }
        if channel.role() != self.local_offer.peer.role {
            return self.fail(channel, HandshakeError::ChannelRoleMismatch);
        }
        let result = self.receive_active(channel, frame);
        if result.is_err() {
            channel.retire();
            self.state = HandshakeState::Failed;
            self.negotiated = None;
            self.pending_negotiated = None;
        }
        result
    }

    /// Commit the guest's negotiated channel state after its acceptance frame
    /// has been written successfully using the bootstrap ceiling.
    ///
    /// The guest remains in [`HandshakeState::AcceptancePending`] until this
    /// method succeeds, so active traffic cannot race ahead of the final
    /// bootstrap frame. On transport failure, retire the channel before calling
    /// this method; completion then fails terminally.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong channel, role, state, a retired channel,
    /// or an invalid negotiated selection. State and negotiation errors retire
    /// the bound channel and handshake. A different channel instance is
    /// rejected before processing and retires only the supplied replacement.
    pub fn complete_acceptance(&mut self, channel: &mut Channel) -> Result<(), HandshakeError> {
        if let Err(error) = self.bind_channel(channel) {
            channel.retire();
            return Err(error);
        }
        if channel.role() != PeerRole::Guest {
            return self.fail(channel, HandshakeError::ChannelRoleMismatch);
        }
        if channel.is_retired() {
            return self.fail(channel, HandshakeError::Frame(FrameError::ChannelRetired));
        }
        if self.state != HandshakeState::AcceptancePending {
            return self.fail(channel, HandshakeError::UnexpectedMessage);
        }
        let Some(negotiated) = self.pending_negotiated.take() else {
            return self.fail(channel, HandshakeError::UnexpectedMessage);
        };
        if let Err(error) = channel.apply_negotiated_protocol(&negotiated) {
            return self.fail(channel, HandshakeError::Negotiation(error));
        }
        self.negotiated = Some(negotiated);
        self.state = HandshakeState::Authenticated;
        Ok(())
    }

    fn receive_active(
        &mut self,
        channel: &mut Channel,
        frame: &[u8],
    ) -> Result<Option<Vec<u8>>, HandshakeError> {
        let message = channel
            .open::<HandshakeMessage>(frame)
            .map_err(HandshakeError::Frame)?;
        match (self.local_offer.peer.role, self.state, message) {
            (PeerRole::Guest, HandshakeState::Starting, HandshakeMessage::Offer { offer }) => {
                self.accept_host(channel, &offer).map(Some)
            }
            (
                PeerRole::Host,
                HandshakeState::AwaitingAcceptance,
                HandshakeMessage::Accept { offer, selection },
            ) => {
                self.confirm_guest(channel, &offer, selection)?;
                Ok(None)
            }
            _ => Err(HandshakeError::UnexpectedMessage),
        }
    }

    fn accept_host(
        &mut self,
        channel: &mut Channel,
        host_offer: &ProtocolOffer,
    ) -> Result<Vec<u8>, HandshakeError> {
        if host_offer.peer.role != PeerRole::Host {
            return Err(HandshakeError::WrongPeerRole);
        }
        validate_peer_identity(host_offer)?;
        let negotiated =
            negotiate(&self.local_offer, host_offer).map_err(HandshakeError::Negotiation)?;
        let selection = ProtocolSelection::from(&negotiated);

        // The acceptance is the last bootstrap-ceiling frame. Lowering before
        // sealing it could make a valid negotiation impossible to acknowledge.
        let acceptance = channel
            .seal(&HandshakeMessage::Accept {
                offer: self.local_offer.clone(),
                selection,
            })
            .map_err(HandshakeError::Frame)?;
        self.pending_negotiated = Some(negotiated);
        self.state = HandshakeState::AcceptancePending;
        Ok(acceptance)
    }

    fn confirm_guest(
        &mut self,
        channel: &mut Channel,
        guest_offer: &ProtocolOffer,
        claimed: ProtocolSelection,
    ) -> Result<(), HandshakeError> {
        if guest_offer.peer.role != PeerRole::Guest {
            return Err(HandshakeError::WrongPeerRole);
        }
        validate_peer_identity(guest_offer)?;
        let negotiated =
            negotiate(&self.local_offer, guest_offer).map_err(HandshakeError::Negotiation)?;
        if claimed != ProtocolSelection::from(&negotiated) {
            return Err(HandshakeError::SelectionMismatch);
        }
        channel
            .apply_negotiated_protocol(&negotiated)
            .map_err(HandshakeError::Negotiation)?;
        self.negotiated = Some(negotiated);
        self.state = HandshakeState::Authenticated;
        Ok(())
    }

    fn fail<T>(
        &mut self,
        channel: &mut Channel,
        error: HandshakeError,
    ) -> Result<T, HandshakeError> {
        channel.retire();
        self.state = HandshakeState::Failed;
        self.negotiated = None;
        self.pending_negotiated = None;
        Err(error)
    }

    fn bind_channel(&mut self, channel: &Channel) -> Result<(), HandshakeError> {
        let instance_id = channel.instance_id();
        match self.channel_instance_id {
            None => {
                self.channel_instance_id = Some(instance_id);
                Ok(())
            }
            Some(bound) if bound == instance_id => Ok(()),
            Some(_) => Err(HandshakeError::ChannelInstanceMismatch),
        }
    }
}

fn validate_local_offer(offer: &ProtocolOffer) -> Result<(), HandshakeError> {
    validate_peer_identity(offer)?;
    let counterpart = ProtocolOffer {
        protocol_major: offer.protocol_major,
        protocol_minor: offer.protocol_minor,
        peer: PeerIdentity {
            role: match offer.peer.role {
                PeerRole::Host => PeerRole::Guest,
                PeerRole::Guest => PeerRole::Host,
            },
            name: "validation-peer".into(),
            version: "0".into(),
            artifact_identity: "validation-only".into(),
        },
        feature_bits: offer.feature_bits,
        limits: offer.limits,
    };
    negotiate(offer, &counterpart)
        .map(|_| ())
        .map_err(HandshakeError::Negotiation)
}

fn validate_peer_identity(offer: &ProtocolOffer) -> Result<(), HandshakeError> {
    if offer.peer.name.trim().is_empty()
        || offer.peer.version.trim().is_empty()
        || offer.peer.artifact_identity.trim().is_empty()
    {
        return Err(HandshakeError::InvalidPeerIdentity);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("handshake frame failed")]
    Frame(#[source] FrameError),
    #[error("protocol negotiation failed")]
    Negotiation(#[source] ProtocolError),
    #[error("guest cannot initiate the handshake")]
    HostMustInitiate,
    #[error("acceptance does not match the independently negotiated selection")]
    SelectionMismatch,
    #[error("unexpected handshake message")]
    UnexpectedMessage,
    #[error("peer identity fields must be nonempty")]
    InvalidPeerIdentity,
    #[error("handshake message came from the wrong peer role")]
    WrongPeerRole,
    #[error("handshake role does not match the authenticated channel role")]
    ChannelRoleMismatch,
    #[error("handshake cannot move between authenticated channel instances")]
    ChannelInstanceMismatch,
}

#[cfg(test)]
#[path = "handshake_tests.rs"]
mod tests;
