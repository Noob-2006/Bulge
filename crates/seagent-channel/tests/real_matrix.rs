//! Real Matrix homeserver integration test (Synapse, see `tests/real/run.sh`).
//!
//! Opt in with `SEAGENT_REAL_MATRIX_HS=http://127.0.0.1:28008`, `SEAGENT_REAL_MATRIX_USER`
//! (`@seagent:localhost`), `SEAGENT_REAL_MATRIX_PASS`, and a second, human account
//! `SEAGENT_REAL_MATRIX_PEER` / `SEAGENT_REAL_MATRIX_PEER_PASS`. Skipped without them.
//! The peer uses its own HTTP client: that is the human, not the code under test.

mod support;

use seagent_channel::http::{Http, Payload};
use seagent_channel::{config, Channel, ChatType, Outbound};
use serde_json::{json, Value};
use std::time::Duration;

struct Real {
    hs: String,
    user: String,
    pass: String,
    peer: String,
    peer_pass: String,
}

fn real() -> Option<Real> {
    Some(Real {
        hs: std::env::var("SEAGENT_REAL_MATRIX_HS").ok()?.trim_end_matches('/').to_string(),
        user: std::env::var("SEAGENT_REAL_MATRIX_USER").ok()?,
        pass: std::env::var("SEAGENT_REAL_MATRIX_PASS").ok()?,
        peer: std::env::var("SEAGENT_REAL_MATRIX_PEER").ok()?,
        peer_pass: std::env::var("SEAGENT_REAL_MATRIX_PEER_PASS").ok()?,
    })
}

fn call(r: &Real, method: &str, path: &str, token: Option<&str>, body: Value) -> (u16, Value) {
    let mut h = Http::new(Duration::from_secs(30));
    if let Some(t) = token {
        h = h.bearer(t);
    }
    let url = format!("{}{}", r.hs, path);
    let resp = h.call(method, &url, &[], Payload::Json(&body)).unwrap_or_else(|e| panic!("{method} {path}: {e}"));
    let v: Value = serde_json::from_str(&resp.body).unwrap_or(Value::Null);
    (resp.status, v)
}

static PEER_TOKEN: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// One login per test process: homeservers rate-limit repeated logins.
fn login(r: &Real, user: &str, pass: &str) -> String {
    PEER_TOKEN.get_or_init(|| login_once(r, user, pass)).clone()
}

fn login_once(r: &Real, user: &str, pass: &str) -> String {
    let body = json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": user}, "password": pass, "initial_device_display_name": "seagent real test peer"});
    let (st, v) = call(r, "POST", "/_matrix/client/v3/login", None, body);
    assert_eq!(st, 200, "login {user}: {v}");
    v["access_token"].as_str().expect("access_token").to_string()
}

fn build(r: &Real, state: &std::path::Path) -> std::sync::Arc<dyn Channel> {
    let v = json!({
        "kind": "matrix",
        "homeserver": r.hs,
        "user_id": r.user,
        "password": r.pass,
        "e2ee": false,
        "cross_signing": false,
        "key_backup": false,
        "read_receipts": false,
        "presence": "",
        "auto_join": true,
        "poll_timeout_secs": 5,
    });
    let cfg = config::parse_config("matrix-real", &v).expect("parse");
    let secrets: config::Secrets = std::sync::Arc::new(|s: &str| s.to_string());
    config::build("matrix-real", &cfg, state, &secrets).expect("build")
}

/// Create a room, invite the bot, and return the room id (as the human peer).
fn room_with_bot(r: &Real, token: &str, name: &str) -> String {
    let (st, v) = call(r, "POST", "/_matrix/client/v3/createRoom", Some(token), json!({"name": name, "preset": "public_chat", "visibility": "public"}));
    assert_eq!(st, 200, "createRoom: {v}");
    let room = v["room_id"].as_str().expect("room_id").to_string();
    let (st, v) = call(r, "POST", &format!("/_matrix/client/v3/rooms/{room}/invite"), Some(token), json!({"user_id": r.user}));
    assert_eq!(st, 200, "invite: {v}");
    room
}

/// Wait until the bot is in the room: its join comes from a `/sync` (poll).
fn wait_join(r: &Real, chan: &dyn Channel, token: &str, room: &str) {
    let cancel = seagent_core::Cancel::new();
    for _ in 0..30 {
        let _ = chan.poll(&cancel);
        let (st, _) = call(r, "GET", &format!("/_matrix/client/v3/rooms/{room}/state/m.room.member/{}", r.user), Some(token), json!({}));
        if st == 200 {
            return;
        }
    }
    panic!("the bot never joined {room}");
}

/// Inbound: the bot joins an invited room on a real homeserver and receives a message.
#[test]
fn joins_and_receives_on_real_synapse() {
    let Some(r) = real() else {
        support::skipped("matrix inbound", "SEAGENT_REAL_MATRIX_HS");
        return;
    };
    let token = login(&r, &r.peer, &r.peer_pass);
    let scratch = support::Scratch::new("mx-in");
    let chan = build(&r, scratch.path());
    // First sync establishes the since token; the invite then arrives as new.
    let _ = chan.poll(&seagent_core::Cancel::new());
    let room = room_with_bot(&r, &token, "seagent real test in");
    wait_join(&r, chan.as_ref(), &token, &room);
    // The bot auto-joins on the next /sync; wait for its membership.
    let body = "hello from a real synapse";
    let mut delivered = false;
    for _ in 0..20 {
        // The send endpoint is idempotent: PUT with a txn id.
        let (st, v) = call(&r, "PUT", &format!("/_matrix/client/v3/rooms/{room}/send/m.room.message/{}", uniq()), Some(&token), json!({"msgtype": "m.text", "body": body}));
        assert_eq!(st, 200, "send: {v}");
        let got = support::poll_until(chan.as_ref(), Duration::from_secs(3), |all| all.iter().any(|m| m.text == body));
        if let Some(m) = got.iter().find(|m| m.text == body) {
            assert_eq!(m.sender, r.peer, "sender is the full user id");
            assert_eq!(m.chat, room, "chat is the room id");
            assert!(matches!(m.chat_type, ChatType::Group | ChatType::Channel), "room chat type: {:?}", m.chat_type);
            assert!(m.message_id.starts_with('$'), "event id: {:?}", m.message_id);
            delivered = true;
            break;
        }
    }
    assert!(delivered, "the bot never delivered the room message");
}

/// Outbound: our message lands in the room timeline of a real homeserver.
#[test]
fn sends_to_real_synapse() {
    let Some(r) = real() else {
        support::skipped("matrix outbound", "SEAGENT_REAL_MATRIX_HS");
        return;
    };
    let token = login(&r, &r.peer, &r.peer_pass);
    let scratch = support::Scratch::new("mx-out");
    let chan = build(&r, scratch.path());
    let _ = chan.poll(&seagent_core::Cancel::new());
    let room = room_with_bot(&r, &token, "seagent real test out");
    wait_join(&r, chan.as_ref(), &token, &room);
    let text = "seagent says hi over synapse";
    let mut sent_ok = false;
    for _ in 0..20 {
        match chan.send(&Outbound::text(&room, text)) {
            Ok(sent) => {
                assert!(sent.ids.first().is_some_and(|i| i.starts_with('$')), "event id: {sent:?}");
                sent_ok = true;
                break;
            }
            Err(e) => eprintln!("send attempt failed (bot may still be joining): {e}"),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(sent_ok, "the bot never managed to send");
    let (st, v) = call(&r, "GET", &format!("/_matrix/client/v3/rooms/{room}/messages?dir=b&limit=20"), Some(&token), json!({}));
    assert_eq!(st, 200, "messages: {v}");
    let found = v["chunk"].as_array().is_some_and(|c| c.iter().any(|e| e["content"]["body"].as_str() == Some(text) && e["sender"].as_str() == Some(r.user.as_str())));
    assert!(found, "message not in the timeline: {v}");
}

fn uniq() -> String {
    format!("seagent{}{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0))
}
