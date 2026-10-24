use super::*;
use crate::frame::{PROTOCOL_MAJOR, PROTOCOL_MINOR, SessionKey};

const KEY: [u8; 32] = [0x3c; 32];

fn offer(role: PeerRole, max_frame_bytes: u32, feature_bits: u64) -> ProtocolOffer {
    ProtocolOffer {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        peer: PeerIdentity {
            role,
            name: match role {
                PeerRole::Host => "test-product",
                PeerRole::Guest => "openclaw-node",
            }
            .into(),
            version: "1.0.0".into(),
            artifact_identity: "sha256:test-only".into(),
        },
        feature_bits,
        limits: Limits {
            max_frame_bytes,
            max_in_flight: 8,
            bootstrap_timeout_ms: 1_000,
        },
    }
}

fn channel(role: PeerRole, max_frame_bytes: u32) -> Channel {
    Channel::new(
        role,
        "handshake-session".into(),
        9,
        SessionKey::from_bytes(KEY),
        max_frame_bytes,
    )
    .unwrap()
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

#[test]
fn host_and_guest_authenticate_the_same_selection() {
    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0b0111)).unwrap();
    let mut guest = Handshake::new(offer(PeerRole::Guest, 2048, 0b1011)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    let mut guest_channel = channel(PeerRole::Guest, 4096);

    let offer_frame = host.start(&mut host_channel).unwrap();
    let acceptance = guest
        .receive(&mut guest_channel, &offer_frame)
        .unwrap()
        .unwrap();
    assert_eq!(guest_channel.max_frame_bytes(), 4096);
    assert_eq!(guest.state(), HandshakeState::AcceptancePending);
    assert!(guest.negotiated().is_none());
    guest.complete_acceptance(&mut guest_channel).unwrap();
    assert_eq!(guest_channel.max_frame_bytes(), 2048);
    assert_eq!(guest.state(), HandshakeState::Authenticated);

    assert!(
        host.receive(&mut host_channel, &acceptance)
            .unwrap()
            .is_none()
    );
    assert_eq!(host_channel.max_frame_bytes(), 2048);
    assert_eq!(host.state(), HandshakeState::Authenticated);
    assert_eq!(
        ProtocolSelection::from(host.negotiated().unwrap()),
        ProtocolSelection::from(guest.negotiated().unwrap())
    );
    assert_eq!(host.negotiated().unwrap().feature_bits, 0b0011);

    let active = host_channel.seal(&"active").unwrap();
    assert_eq!(
        u16::from_be_bytes(active[6..8].try_into().unwrap()),
        host.negotiated().unwrap().protocol_minor
    );
    assert_eq!(u64::from_be_bytes(active[17..25].try_into().unwrap()), 2);
    assert_eq!(guest_channel.open::<String>(&active).unwrap(), "active");

    let reply = guest_channel.seal(&"reply").unwrap();
    assert_eq!(host_channel.open::<String>(&reply).unwrap(), "reply");
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    schema_version: u8,
    supervisor_offer: FixtureOffer,
    runtime_offer: FixtureOffer,
    selection: ProtocolSelection,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixtureOffer {
    protocol_major: u16,
    protocol_minor: u16,
    peer: FixturePeer,
    feature_bits: u64,
    limits: Limits,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FixturePeer {
    role: String,
    name: String,
    version: String,
    artifact_identity: String,
}

impl FixtureOffer {
    fn into_offer(self) -> ProtocolOffer {
        ProtocolOffer {
            protocol_major: self.protocol_major,
            protocol_minor: self.protocol_minor,
            peer: PeerIdentity {
                role: match self.peer.role.as_str() {
                    "supervisor" => PeerRole::Host,
                    "runtime" => PeerRole::Guest,
                    other => panic!("unknown fixture role {other}"),
                },
                name: self.peer.name,
                version: self.peer.version,
                artifact_identity: self.peer.artifact_identity,
            },
            feature_bits: self.feature_bits,
            limits: self.limits,
        }
    }
}

#[test]
fn cross_language_handshake_fixture_selects_the_same_protocol() {
    // The upstream fixture pins exact `OCSC`/supervisor/runtime frames.
    // M1 changes the magic to `BLGC` and the roles to host/guest, so exact
    // upstream bytes cannot be reproduced. The fixture's offers and
    // independently derived selection remain the semantic oracle.
    let fixture: Fixture = serde_json::from_str(
        r#"{
            "schemaVersion": 1,
            "supervisorOffer": {
                "protocolMajor": 1,
                "protocolMinor": 0,
                "peer": {
                    "role": "supervisor",
                    "name": "test-product",
                    "version": "1.0.0",
                    "artifactIdentity": "sha256:test-only"
                },
                "featureBits": 7,
                "limits": {
                    "maxFrameBytes": 4096,
                    "maxInFlight": 8,
                    "bootstrapTimeoutMs": 1000
                }
            },
            "runtimeOffer": {
                "protocolMajor": 1,
                "protocolMinor": 0,
                "peer": {
                    "role": "runtime",
                    "name": "openclaw-node",
                    "version": "1.0.0",
                    "artifactIdentity": "sha256:test-only"
                },
                "featureBits": 11,
                "limits": {
                    "maxFrameBytes": 2048,
                    "maxInFlight": 8,
                    "bootstrapTimeoutMs": 1000
                }
            },
            "selection": {
                "protocolMajor": 1,
                "protocolMinor": 0,
                "featureBits": 3,
                "limits": {
                    "maxFrameBytes": 2048,
                    "maxInFlight": 8,
                    "bootstrapTimeoutMs": 1000
                }
            }
        }"#,
    )
    .unwrap();
    assert_eq!(fixture.schema_version, 1);

    let host_offer = fixture.supervisor_offer.into_offer();
    let guest_offer = fixture.runtime_offer.into_offer();
    assert_eq!(
        ProtocolSelection::from(&negotiate(&host_offer, &guest_offer).unwrap()),
        fixture.selection
    );

    let mut host = Handshake::new(host_offer).unwrap();
    let mut guest = Handshake::new(guest_offer).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    let mut guest_channel = channel(PeerRole::Guest, 4096);

    let offer_frame = host.start(&mut host_channel).unwrap();
    let acceptance = guest
        .receive(&mut guest_channel, &offer_frame)
        .unwrap()
        .unwrap();
    guest.complete_acceptance(&mut guest_channel).unwrap();
    assert!(
        host.receive(&mut host_channel, &acceptance)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        ProtocolSelection::from(host.negotiated().unwrap()),
        fixture.selection
    );
    assert_eq!(
        ProtocolSelection::from(guest.negotiated().unwrap()),
        fixture.selection
    );
}

#[test]
fn forged_selection_fails_and_retires_host() {
    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0b0011)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    let mut malicious_guest_channel = channel(PeerRole::Guest, 4096);
    let offer_frame = host.start(&mut host_channel).unwrap();
    let _: HandshakeMessage = malicious_guest_channel.open(&offer_frame).unwrap();

    let guest_offer = offer(PeerRole::Guest, 2048, 0b0011);
    let forged = malicious_guest_channel
        .seal(&HandshakeMessage::Accept {
            offer: guest_offer,
            selection: ProtocolSelection {
                protocol_major: PROTOCOL_MAJOR,
                protocol_minor: PROTOCOL_MINOR,
                feature_bits: u64::MAX,
                limits: Limits {
                    max_frame_bytes: 4096,
                    max_in_flight: u16::MAX,
                    bootstrap_timeout_ms: u32::MAX,
                },
            },
        })
        .unwrap();

    assert!(matches!(
        host.receive(&mut host_channel, &forged),
        Err(HandshakeError::SelectionMismatch)
    ));
    assert_eq!(host.state(), HandshakeState::Failed);
    assert!(host_channel.is_retired());
}

#[test]
fn guest_commits_selection_only_after_acceptance_delivery() {
    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0)).unwrap();
    let mut guest = Handshake::new(offer(PeerRole::Guest, 128, 0)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    let mut guest_channel = channel(PeerRole::Guest, 4096);

    let offer_frame = host.start(&mut host_channel).unwrap();
    let acceptance = guest
        .receive(&mut guest_channel, &offer_frame)
        .unwrap()
        .unwrap();
    assert!(acceptance.len() > 128);
    assert_eq!(guest.state(), HandshakeState::AcceptancePending);
    assert_eq!(guest_channel.max_frame_bytes(), 4096);
    assert!(guest.negotiated().is_none());

    guest.complete_acceptance(&mut guest_channel).unwrap();
    assert_eq!(guest.state(), HandshakeState::Authenticated);
    assert_eq!(guest_channel.max_frame_bytes(), 128);
}

#[test]
fn failed_acceptance_delivery_is_terminal() {
    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0)).unwrap();
    let mut guest = Handshake::new(offer(PeerRole::Guest, 2048, 0)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    let mut guest_channel = channel(PeerRole::Guest, 4096);

    let offer_frame = host.start(&mut host_channel).unwrap();
    guest
        .receive(&mut guest_channel, &offer_frame)
        .unwrap()
        .unwrap();
    guest_channel.retire();
    assert!(matches!(
        guest.complete_acceptance(&mut guest_channel),
        Err(HandshakeError::Frame(FrameError::ChannelRetired))
    ));
    assert_eq!(guest.state(), HandshakeState::Failed);
    assert!(guest.negotiated().is_none());
}

#[test]
fn handshake_cannot_move_to_another_channel_instance() {
    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0b0011)).unwrap();
    let mut original_channel = channel(PeerRole::Host, 4096);
    let _offer_frame = host.start(&mut original_channel).unwrap();

    let guest_offer = offer(PeerRole::Guest, 2048, 0b0011);
    let selection =
        ProtocolSelection::from(&negotiate(&host.local_offer, &guest_offer).unwrap());
    let mut other_guest_channel = channel(PeerRole::Guest, 4096);
    let acceptance = other_guest_channel
        .seal(&HandshakeMessage::Accept {
            offer: guest_offer,
            selection,
        })
        .unwrap();
    let mut other_host_channel = channel(PeerRole::Host, 4096);

    assert!(matches!(
        host.receive(&mut other_host_channel, &acceptance),
        Err(HandshakeError::ChannelInstanceMismatch)
    ));
    assert_eq!(host.state(), HandshakeState::AwaitingAcceptance);
    assert!(other_host_channel.is_retired());
    assert!(!original_channel.is_retired());

    assert!(
        host.receive(&mut original_channel, &acceptance)
            .unwrap()
            .is_none()
    );
    assert_eq!(host.state(), HandshakeState::Authenticated);
}

#[test]
fn incompatible_offer_fails_and_retires_guest() {
    let mut host_offer = offer(PeerRole::Host, 4096, 0);
    host_offer.protocol_major += 1;
    let mut host_channel = channel(PeerRole::Host, 4096);
    let incompatible = host_channel
        .seal(&HandshakeMessage::Offer { offer: host_offer })
        .unwrap();
    let mut guest = Handshake::new(offer(PeerRole::Guest, 4096, 0)).unwrap();
    let mut guest_channel = channel(PeerRole::Guest, 4096);

    assert!(matches!(
        guest.receive(&mut guest_channel, &incompatible),
        Err(HandshakeError::Negotiation(
            ProtocolError::UnsupportedMajor { .. }
        ))
    ));
    assert_eq!(guest.state(), HandshakeState::Failed);
    assert!(guest_channel.is_retired());
}

#[test]
fn same_role_offer_fails_and_retires() {
    let mut guest = Handshake::new(offer(PeerRole::Guest, 4096, 0)).unwrap();
    let mut guest_channel = channel(PeerRole::Guest, 4096);
    let mut wrong_role_channel = channel(PeerRole::Host, 4096);
    let frame = wrong_role_channel
        .seal(&HandshakeMessage::Offer {
            offer: offer(PeerRole::Guest, 4096, 0),
        })
        .unwrap();

    assert!(matches!(
        guest.receive(&mut guest_channel, &frame),
        Err(HandshakeError::WrongPeerRole)
    ));
    assert_eq!(guest.state(), HandshakeState::Failed);
    assert!(guest_channel.is_retired());
}

#[test]
fn wrong_order_is_terminal() {
    let mut guest = Handshake::new(offer(PeerRole::Guest, 4096, 0)).unwrap();
    let mut guest_channel = channel(PeerRole::Guest, 4096);
    assert!(matches!(
        guest.start(&mut guest_channel),
        Err(HandshakeError::HostMustInitiate)
    ));
    assert_eq!(guest.state(), HandshakeState::Failed);
    assert!(guest_channel.is_retired());
}

#[test]
fn repeated_or_out_of_order_messages_fail_and_retire() {
    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    let mut guest_channel = channel(PeerRole::Guest, 4096);
    let guest_offer = offer(PeerRole::Guest, 4096, 0);
    let selection =
        ProtocolSelection::from(&negotiate(&host.local_offer, &guest_offer).unwrap());
    let early_accept = guest_channel
        .seal(&HandshakeMessage::Accept {
            offer: guest_offer,
            selection,
        })
        .unwrap();

    assert!(matches!(
        host.receive(&mut host_channel, &early_accept),
        Err(HandshakeError::UnexpectedMessage)
    ));
    assert_eq!(host.state(), HandshakeState::Failed);
    assert!(host_channel.is_retired());

    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0)).unwrap();
    let mut guest = Handshake::new(offer(PeerRole::Guest, 4096, 0)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    let mut guest_channel = channel(PeerRole::Guest, 4096);
    let offer_frame = host.start(&mut host_channel).unwrap();
    let acceptance = guest
        .receive(&mut guest_channel, &offer_frame)
        .unwrap()
        .unwrap();
    assert!(
        host.receive(&mut host_channel, &acceptance)
            .unwrap()
            .is_none()
    );
    guest.complete_acceptance(&mut guest_channel).unwrap();

    let repeated_offer = host_channel
        .seal(&HandshakeMessage::Offer {
            offer: offer(PeerRole::Host, 4096, 0),
        })
        .unwrap();
    assert!(matches!(
        guest.receive(&mut guest_channel, &repeated_offer),
        Err(HandshakeError::UnexpectedMessage)
    ));
    assert_eq!(guest.state(), HandshakeState::Failed);
    assert!(guest_channel.is_retired());

    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    let mut guest = Handshake::new(offer(PeerRole::Guest, 4096, 0)).unwrap();
    let mut guest_channel = channel(PeerRole::Guest, 4096);
    let offer_frame = host.start(&mut host_channel).unwrap();
    let acceptance = guest
        .receive(&mut guest_channel, &offer_frame)
        .unwrap()
        .unwrap();
    assert!(
        host.receive(&mut host_channel, &acceptance)
            .unwrap()
            .is_none()
    );
    let second_accept = guest_channel
        .seal(&HandshakeMessage::Accept {
            offer: offer(PeerRole::Guest, 4096, 0),
            selection: ProtocolSelection::from(host.negotiated().unwrap()),
        })
        .unwrap();
    assert!(matches!(
        host.receive(&mut host_channel, &second_accept),
        Err(HandshakeError::UnexpectedMessage)
    ));
    assert_eq!(host.state(), HandshakeState::Failed);
    assert!(host_channel.is_retired());
}

#[test]
fn swapped_channel_roles_are_terminal_before_frame_processing() {
    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0)).unwrap();
    let mut guest_channel = channel(PeerRole::Guest, 4096);
    assert!(matches!(
        host.start(&mut guest_channel),
        Err(HandshakeError::ChannelRoleMismatch)
    ));
    assert_eq!(host.state(), HandshakeState::Failed);
    assert!(guest_channel.is_retired());

    let mut guest = Handshake::new(offer(PeerRole::Guest, 4096, 0)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    assert!(matches!(
        guest.receive(&mut host_channel, b"ignored"),
        Err(HandshakeError::ChannelRoleMismatch)
    ));
    assert_eq!(guest.state(), HandshakeState::Failed);
    assert!(host_channel.is_retired());
}

#[test]
fn malformed_frame_retires_handshake_and_channel() {
    let mut guest = Handshake::new(offer(PeerRole::Guest, 4096, 0)).unwrap();
    let mut guest_channel = channel(PeerRole::Guest, 4096);
    assert!(matches!(
        guest.receive(&mut guest_channel, b"not-authenticated"),
        Err(HandshakeError::Frame(_))
    ));
    assert_eq!(guest.state(), HandshakeState::Failed);
    assert!(guest_channel.is_retired());
}

#[test]
fn invalid_local_identity_is_rejected_before_channel_use() {
    let mut invalid = offer(PeerRole::Guest, 4096, 0);
    invalid.peer.artifact_identity.clear();
    assert!(matches!(
        Handshake::new(invalid),
        Err(HandshakeError::InvalidPeerIdentity)
    ));
}

#[test]
fn invalid_host_identity_is_terminal_for_guest() {
    let mut host_channel = channel(PeerRole::Host, 4096);
    let mut invalid = offer(PeerRole::Host, 4096, 0);
    invalid.peer.name = "  ".into();
    let frame = host_channel
        .seal(&HandshakeMessage::Offer { offer: invalid })
        .unwrap();
    let mut guest = Handshake::new(offer(PeerRole::Guest, 4096, 0)).unwrap();
    let mut guest_channel = channel(PeerRole::Guest, 4096);

    assert!(matches!(
        guest.receive(&mut guest_channel, &frame),
        Err(HandshakeError::InvalidPeerIdentity)
    ));
    assert_eq!(guest.state(), HandshakeState::Failed);
    assert!(guest_channel.is_retired());
}

#[test]
fn invalid_guest_identity_is_terminal_for_host() {
    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    let offer_frame = host.start(&mut host_channel).unwrap();
    let mut guest_channel = channel(PeerRole::Guest, 4096);
    let _: HandshakeMessage = guest_channel.open(&offer_frame).unwrap();
    let mut invalid = offer(PeerRole::Guest, 4096, 0);
    invalid.peer.version.clear();
    let selection = ProtocolSelection::from(&negotiate(&host.local_offer, &invalid).unwrap());
    let frame = guest_channel
        .seal(&HandshakeMessage::Accept {
            offer: invalid,
            selection,
        })
        .unwrap();

    assert!(matches!(
        host.receive(&mut host_channel, &frame),
        Err(HandshakeError::InvalidPeerIdentity)
    ));
    assert_eq!(host.state(), HandshakeState::Failed);
    assert!(host_channel.is_retired());
}

#[test]
fn unencodable_initial_offer_is_terminal() {
    let mut host = Handshake::new(offer(PeerRole::Host, 128, 0)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 128);
    assert!(matches!(
        host.start(&mut host_channel),
        Err(HandshakeError::Frame(FrameError::FrameTooLarge { .. }))
    ));
    assert_eq!(host.state(), HandshakeState::Failed);
    assert!(host_channel.is_retired());
}

#[test]
fn known_answer_handshake_frames_are_byte_exact() {
    let mut host = Handshake::new(offer(PeerRole::Host, 4096, 0b0111)).unwrap();
    let mut guest = Handshake::new(offer(PeerRole::Guest, 2048, 0b1011)).unwrap();
    let mut host_channel = channel(PeerRole::Host, 4096);
    let mut guest_channel = channel(PeerRole::Guest, 4096);

    let offer_frame = host.start(&mut host_channel).unwrap();
    assert_eq!(offer_frame, decode_hex(KNOWN_ANSWER_OFFER_HEX));
    let acceptance = guest
        .receive(&mut guest_channel, &offer_frame)
        .unwrap()
        .unwrap();
    assert_eq!(acceptance, decode_hex(KNOWN_ANSWER_ACCEPT_HEX));

    guest.complete_acceptance(&mut guest_channel).unwrap();
    host.receive(&mut host_channel, &acceptance).unwrap();
    assert_eq!(
        ProtocolSelection::from(host.negotiated().unwrap()),
        ProtocolSelection::from(guest.negotiated().unwrap())
    );
}

const KNOWN_ANSWER_OFFER_HEX: &str = concat!(
    "424c4743",                           // magic "BLGC"
    "0001",                               // protocol major 1
    "0000",                               // protocol minor 0
    "01",                                 // host -> guest
    "0000000000000009",                   // generation 9
    "0000000000000001",                   // sequence 1
    "0011",                               // session id length 17
    "000000fd",                           // payload length 253
    "68616e647368616b652d73657373696f6e", // "handshake-session"
    "7b2274797065223a226f66666572222c226f66666572223a7b2270726f746f636f6c4d616a6f72223a312c2270726f746f636f6c4d696e6f72223a302c2270656572223a7b22726f6c65223a22686f7374222c226e616d65223a22746573742d70726f64756374222c2276657273696f6e223a22312e302e30222c2261727469666163744964656e74697479223a227368613235363a746573742d6f6e6c79227d2c226665617475726542697473223a372c226c696d697473223a7b226d61784672616d654279746573223a343039362c226d6178496e466c69676874223a382c22626f6f74737472617054696d656f75744d73223a313030307d7d7d",
    "64f8f8882c3440556ae1d9abf22ccb5fd06e9250c89bc01df6aa879f004c76f6",
);
const KNOWN_ANSWER_ACCEPT_HEX: &str = concat!(
    "424c4743",                           // magic "BLGC"
    "0001",                               // protocol major 1
    "0000",                               // protocol minor 0
    "02",                                 // guest -> host
    "0000000000000009",                   // generation 9
    "0000000000000001",                   // sequence 1
    "0011",                               // session id length 17
    "0000018d",                           // payload length 397
    "68616e647368616b652d73657373696f6e", // "handshake-session"
    "7b2274797065223a22616363657074222c226f66666572223a7b2270726f746f636f6c4d616a6f72223a312c2270726f746f636f6c4d696e6f72223a302c2270656572223a7b22726f6c65223a226775657374222c226e616d65223a226f70656e636c61772d6e6f6465222c2276657273696f6e223a22312e302e30222c2261727469666163744964656e74697479223a227368613235363a746573742d6f6e6c79227d2c226665617475726542697473223a31312c226c696d697473223a7b226d61784672616d654279746573223a323034382c226d6178496e466c69676874223a382c22626f6f74737472617054696d656f75744d73223a313030307d7d2c2273656c656374696f6e223a7b2270726f746f636f6c4d616a6f72223a312c2270726f746f636f6c4d696e6f72223a302c226665617475726542697473223a332c226c696d697473223a7b226d61784672616d654279746573223a323034382c226d6178496e466c69676874223a382c22626f6f74737472617054696d656f75744d73223a313030307d7d7d",
    "e1a238bce1f5b26e029555bf86bf9817b6dbe9baf9cf5d18b385ade02f5f2eb6",
);
