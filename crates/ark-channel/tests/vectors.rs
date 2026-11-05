//! Replay of recorded request/response vectors captured from real servers.
//!
//! `tests/real/vectors/` holds bytes recorded from services this machine ran
//! (`tests/real/run.sh`): ngircd 27, ntfy 2.37.2, GreenMail, Synapse. These tests
//! need no network and no container — they pin ark's parsers to what the real
//! servers actually send, including the parts ark has to fall back on (for
//! example ngircd answers `CAP … NAK` to every IRCv3 capability, so there is no
//! `message-tags` and no server msgid).

use std::path::PathBuf;

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join("tests/real/vectors")
}

/// ngircd 27: registration numerics, ISUPPORT, a JOIN and a channel message.
#[test]
fn irc_registration_and_message_lines_from_ngircd() {
    let raw = std::fs::read_to_string(vectors().join("irc_ngircd_session.txt")).expect("vector file");
    let lines: Vec<ark_channel::irc::Line> = raw.lines().filter_map(ark_channel::irc::parse_line).collect();
    assert!(lines.len() >= 20, "parsed {} lines", lines.len());

    let welcome = lines.iter().find(|l| l.command == "001").expect("001");
    assert_eq!(welcome.param(0), "vec_r5", "001 carries our nick");
    assert!(welcome.last().contains("Welcome"), "{:?}", welcome.last());

    // ISUPPORT: the real server's NICKLEN is 9, which larger nick-fallback
    // candidates would exceed (see docs/protocols/irc.md).
    let isupport: Vec<String> = lines.iter().filter(|l| l.command == "005").map(|l| l.params.join(" ")).collect();
    assert!(isupport.iter().any(|p| p.contains("NICKLEN=9")), "{isupport:?}");

    // Every IRCv3 capability we ask for is refused by this server.
    let nak = lines.iter().find(|l| l.command == "CAP" && l.param(1) == "NAK").expect("CAP NAK");
    assert!(nak.last().contains("message-tags"), "{nak:?}");

    let msg = lines.iter().find(|l| l.command == "PRIVMSG").expect("PRIVMSG");
    assert_eq!(msg.nick(), "vec_alice", "prefix carries nick!user@host");
    assert_eq!(msg.param(0), "#vec", "first param is the target");
    assert_eq!(msg.last(), "hello from a recorded ngircd session");
    assert_eq!(msg.tag("msgid"), None, "no message-tags: ark must fall back to a local id");

    let join = lines.iter().find(|l| l.command == "JOIN").expect("JOIN");
    assert_eq!(join.param(0), "#vec");
    assert_eq!(join.nick(), "vec_r5");
}

/// ntfy 2.37.2: the publish response and the matching stream event.
#[test]
fn ntfy_publish_response_and_stream_event() {
    let pubv: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(vectors().join("ntfy_publish_response.json")).unwrap()).expect("publish json");
    let ev: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(vectors().join("ntfy_stream_event.json")).unwrap()).expect("event json");
    assert_eq!(pubv["id"], ev["id"], "the stream event carries the id the publish returned");
    assert_eq!(ev["event"], "message");
    assert_eq!(ev["topic"], "ark-vectors");
    assert_eq!(ev["title"], "rec", "publisher title is not identity");
    assert!(ev["tags"].as_array().is_some_and(|t| t.iter().any(|t| t == "human")));

    let m = ark_channel::ntfy::recorded_inbound("ntfy", "ark-vectors", &ev).expect("inbound");
    assert_eq!(m.sender, "ark-vectors", "sender is the topic, never the title");
    assert_eq!(m.chat, "ark-vectors");
    assert_eq!(m.text, "recorded body");
    assert_eq!(m.message_id, ev["id"].as_str().unwrap());
    assert_eq!(m.ts, ev["time"].as_i64().unwrap(), "ntfy time is unix seconds");

    // control events are not messages
    for k in ["open", "keepalive", "poll_request"] {
        let mut ctl = ev.clone();
        ctl["event"] = serde_json::Value::String(k.into());
        assert!(ark_channel::ntfy::recorded_inbound("ntfy", "ark-vectors", &ctl).is_none(), "{k} became a message");
    }
}

/// GreenMail: a real SMTP-delivered message, quoted-printable, as IMAP returned it.
#[test]
fn email_message_from_greenmail() {
    let raw = std::fs::read(vectors().join("greenmail_message.eml")).expect("vector file");
    let m = ark_channel::email::parse_mail(&raw);
    assert_eq!(ark_channel::email::header(&m.headers, "subject").map(str::trim), Some("ark"));
    assert!(ark_channel::email::header(&m.headers, "message-id").is_some_and(|v| v.starts_with('<') && v.ends_with('>')), "Message-ID");
    assert_eq!(m.text.trim(), "reply body from ark", "quoted-printable decoded: {:?}", m.text);
    assert_eq!(ark_channel::email::extract_address(ark_channel::email::header(&m.headers, "from").unwrap()), "ark@localhost");
    // Own mail is dropped by comparing From with the account address (channel
    // level, `email.rs` poll), not by `is_automated`; a self-addressed message is
    // not "automated".
    assert!(!ark_channel::email::is_automated("ark@localhost", &m.headers), "a human From must not be filtered as automated mail");
}

/// Synapse: a real `/sync` slice, trimmed; the room event becomes an `Inbound`.
#[test]
fn matrix_sync_event_from_synapse() {
    let sync: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(vectors().join("synapse_sync_slice.json")).unwrap()).expect("sync json");
    let rooms = sync["rooms"]["join"].as_object().expect("joined rooms");
    let mut seen = 0;
    for (room_id, room) in rooms {
        // The room name is not in this trimmed slice (state is empty); a room
        // message's chat_type therefore follows `is_dm = false`.
        let name = "";
        for ev in room["timeline"]["events"].as_array().cloned().unwrap_or_default() {
            if ev["type"] != "m.room.message" {
                continue;
            }
            let who = ev["sender"].as_str().unwrap_or("").to_string();
            let got = ark_channel::matrix::recorded_inbound("matrix", "@ark:localhost", room_id, name, false, &ev);
            if who == "@ark:localhost" {
                assert!(got.is_none(), "our own timeline echo must not become an Inbound");
                continue;
            }
            let m = got.expect("inbound");
            assert_eq!(m.chat, *room_id, "chat is the room id");
            assert_eq!(m.sender, who);
            assert!(m.message_id.starts_with('$'), "event id: {:?}", m.message_id);
            assert!(ev["origin_server_ts"].is_i64(), "the fixture keeps the real ts");
            assert_eq!(m.ts, ev["origin_server_ts"].as_i64().unwrap() / 1000, "ms → s");
            seen += 1;
        }
    }
    assert!(seen > 0, "the recorded sync slice has no room message; re-record it");
}
