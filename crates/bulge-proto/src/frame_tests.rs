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
