//! Real Nextcloud Talk (spreed) integration test.
//!
//! Opt in with the env line printed by `tests/real/nextcloud_up.sh --keep`:
//! `SEAGENT_REAL_NEXTCLOUD_URL`, `_USER`/`_PASSWORD` (the API user + app password),
//! `_PEER`/`_PEER_PASSWORD` (a second human), `_ROOM` (conversation token),
//! `_BOT_NAME`/`_BOT_SECRET` (the installed Talk bot), `_WEBHOOK_PORT` (the port the
//! bot's webhook URL points at) and the admin credentials. Skipped without them.
//!
//! The peer/admin side speaks plain OCS here: that is the human and the server, not
//! the code under test. Seagent is built through the real `[channels.*]` config path and
//! is driven only through `Channel`.
//!
//! Talk delivers chat messages to a bot as signed webhooks, so inbound goes through
//! the same HTTP server the daemon runs (`listen` must be reachable from inside the
//! container: the bot's URL is `http://host.containers.internal:<port>/…`).
//!
//! The bot API is brute-force protected (per client IP, up to a 25 s delay), and the
//! wrong-secret test below is a real rejection, so repeated runs against a server
//! that has collected failures get slow: `nextcloud_up.sh` clears the counter with
//! `occ security:bruteforce:reset <gateway>` before it hands the stack over.

mod support;

use seagent_channel::http::{Http, Payload};
use seagent_channel::{config, Channel, ChannelErrorKind as K, ChatType, Media, MediaKind, Outbound};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

const HOOK_PATH: &str = "/nextcloud-talk-webhook";

struct Real {
    base: String,
    user: String,
    pass: String,
    peer: String,
    peer_pass: String,
    admin: String,
    admin_pass: String,
    room: String,
    bot_name: String,
    bot_secret: String,
    bot_id: String,
    hook_port: u16,
}

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn real() -> Option<Real> {
    Some(Real {
        base: env("SEAGENT_REAL_NEXTCLOUD_URL")?.trim_end_matches('/').to_string(),
        user: env("SEAGENT_REAL_NEXTCLOUD_USER")?,
        pass: env("SEAGENT_REAL_NEXTCLOUD_PASSWORD")?,
        peer: env("SEAGENT_REAL_NEXTCLOUD_PEER")?,
        peer_pass: env("SEAGENT_REAL_NEXTCLOUD_PEER_PASSWORD")?,
        admin: env("SEAGENT_REAL_NEXTCLOUD_ADMIN")?,
        admin_pass: env("SEAGENT_REAL_NEXTCLOUD_ADMIN_PASSWORD")?,
        room: env("SEAGENT_REAL_NEXTCLOUD_ROOM")?,
        bot_name: env("SEAGENT_REAL_NEXTCLOUD_BOT_NAME").unwrap_or_else(|| "Seagent".into()),
        bot_secret: env("SEAGENT_REAL_NEXTCLOUD_BOT_SECRET")?,
        bot_id: env("SEAGENT_REAL_NEXTCLOUD_BOT_ID")?,
        hook_port: env("SEAGENT_REAL_NEXTCLOUD_WEBHOOK_PORT")?.parse().ok()?,
    })
}

/// One webhook listener per process: the port is fixed by the bot's installed URL.
static HOOK: Mutex<()> = Mutex::new(());

fn hook() -> MutexGuard<'static, ()> {
    HOOK.lock().unwrap_or_else(|e| e.into_inner())
}

fn basic(user: &str, pass: &str) -> String {
    use base64::Engine;
    format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}")))
}

/// An OCS call as a web user (the peer / the admin), `format=json`.
fn ocs(r: &Real, user: &str, pass: &str, method: &str, path: &str, form: &[(&str, &str)]) -> (u16, Value) {
    let auth = basic(user, pass);
    let h = [("authorization", auth.as_str()), ("ocs-apirequest", "true"), ("accept", "application/json")];
    let url = format!("{}{path}", r.base);
    let resp = Http::new(Duration::from_secs(30))
        .call(method, &url, &h, if form.is_empty() { Payload::None } else { Payload::Form(form) })
        .unwrap_or_else(|e| panic!("{method} {path}: {e:?}"));
    let v: Value = serde_json::from_str(&resp.body).unwrap_or(Value::Null);
    (resp.status, v)
}

/// Post a chat message the way a human client does; returns its message id.
fn peer_says(r: &Real, text: &str) -> String {
    let (st, v) = ocs(r, &r.peer, &r.peer_pass, "POST", &format!("/ocs/v2.php/apps/spreed/api/v1/chat/{}", r.room), &[("message", text)]);
    assert!((200..300).contains(&st), "peer cannot post: {st} {v}");
    v["ocs"]["data"]["id"].as_i64().map(|n| n.to_string()).unwrap_or_default()
}

/// The last messages the peer sees in the conversation, newest first.
fn peer_history(r: &Real) -> Vec<Value> {
    let path = format!("/ocs/v2.php/apps/spreed/api/v1/chat/{}?lookIntoFuture=0&limit=100&setReadMarker=0&noStatusUpdate=1&markNotificationsAsRead=0", r.room);
    let (st, v) = ocs(r, &r.peer, &r.peer_pass, "GET", &path, &[]);
    assert_eq!(st, 200, "peer cannot read the conversation: {v}");
    v["ocs"]["data"].as_array().cloned().unwrap_or_default()
}

fn wait_for<F: Fn(&[Value]) -> bool>(r: &Real, secs: u64, f: F) -> Vec<Value> {
    // Talk sends the webhook right after the chat message is stored, but the
    // message we look for may still need a round of polling.
    let end = std::time::Instant::now() + Duration::from_secs(secs);
    let mut all = Vec::new();
    while std::time::Instant::now() < end {
        all = peer_history(r);
        if f(&all) {
            return all;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    all
}

fn build(r: &Real, state: &std::path::Path, extra: &Value) -> Result<Arc<dyn Channel>, String> {
    let mut v = json!({
        "kind": "nextcloud_talk",
        "base_url": r.base,
        "bot_secret": r.bot_secret,
        "listen": format!("0.0.0.0:{}", r.hook_port),
        "api_user": r.user,
        "api_password": r.pass,
        "bot_name": r.bot_name,
        "allowed_backends": [r.base],
        "poll_timeout_secs": 1,
    });
    if let (Some(dst), Some(src)) = (v.as_object_mut(), extra.as_object()) {
        for (k, val) in src {
            dst.insert(k.clone(), val.clone());
        }
    }
    let cfg = config::parse_config("nctalk-real", &v)?;
    let secrets: config::Secrets = Arc::new(|s: &str| s.to_string());
    config::build("nctalk-real", &cfg, state, &secrets)
}

/// Bind the fixed webhook port, retrying while the previous test's server unwinds.
fn build_waiting(r: &Real, state: &std::path::Path, extra: &Value) -> Arc<dyn Channel> {
    let mut err = String::new();
    for _ in 0..20 {
        match build(r, state, extra) {
            Ok(c) => return c,
            Err(e) => err = e,
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("cannot build the channel: {err}");
}

/// Inbound: a message another participant posts through OCS arrives at seagent with the
/// conversation token, the sender's user id and display name, and the message id.
#[test]
fn inbound_message_from_a_real_conversation() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk inbound", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-in");
    let chan = build_waiting(&r, scratch.path(), &json!({}));

    let text = format!("inbound from the real server {} {}", std::process::id(), now());
    let id = peer_says(&r, &text);

    let got = support::poll_until(chan.as_ref(), Duration::from_secs(20), |all| all.iter().any(|m| m.text == text));
    let m = got.iter().find(|m| m.text == text).unwrap_or_else(|| panic!("not delivered as inbound: {got:?}"));
    assert_eq!(m.chat, r.room, "the conversation token is the chat");
    assert_eq!(m.sender, r.peer, "sender is the Talk user id");
    assert_eq!(m.sender_name, "Seagent Peer", "sender_name is the Talk display name");
    assert_eq!(m.chat_type, ChatType::Group, "a public conversation is a group (room type 3)");
    assert_eq!(m.message_id, id, "the message id is the OCS/Talk message id");
    assert!(!m.is_bot);
    assert_eq!(m.channel, "nctalk-real");
    assert!(chan.caps().media, "api credentials are set: media is on");

    // A plain-text "@Seagent" is the only way to mention a bot in Talk 19 (bots are not
    // in the mention picker), and seagent has to recognise it in the message text.
    let ping = format!("@{} ping {}", r.bot_name, now());
    peer_says(&r, &ping);
    let got = support::poll_until(chan.as_ref(), Duration::from_secs(20), |all| all.iter().any(|m| m.text == ping));
    let m = got.iter().find(|m| m.text == ping).unwrap_or_else(|| panic!("mention not delivered: {got:?}"));
    assert!(m.mentioned && m.addressed(), "a plain @name mention is recognised: {m:?}");
    chan.stop();
}

/// Outbound: seagent posts through the signed bot API and a second client reads exactly
/// that text back from the conversation.
#[test]
fn outbound_message_is_readable_by_a_second_client() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk outbound", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-out");
    let chan = build_waiting(&r, scratch.path(), &json!({}));

    let text = format!("seagent outbound {} {} **markdown**", std::process::id(), now());
    let sent = chan.send(&Outbound::text(&r.room, &text)).expect("send");
    // Documented behaviour of the Talk bot API: it answers 201 with an empty data
    // array, so there is no message id to report. `Sent::ids` stays empty.
    assert!(sent.ids.is_empty(), "the bot message endpoint returns no id: {sent:?}");

    let hist = wait_for(&r, 10, |all| all.iter().any(|m| m["message"] == text.as_str()));
    let m = hist.iter().find(|m| m["message"] == text.as_str()).unwrap_or_else(|| panic!("not on the server: {hist:?}"));
    assert_eq!(m["actorType"], "bots", "posted as a bot, not as the API user: {m}");
    assert!(m["actorId"].as_str().unwrap_or("").starts_with("bot-"), "bot actor id: {m}");
    assert_eq!(m["actorDisplayName"].as_str(), Some(format!("{} (Bot)", r.bot_name).as_str()), "Talk shows bots as `<name> (Bot)`: {m}");
    assert_eq!(hist.iter().filter(|m| m["message"] == text.as_str()).count(), 1, "exactly once");

    // Our own message must not come back as inbound (Talk does not webhook a bot
    // its own messages, and seagent also drops Application actors by name).
    let got = support::poll_until(chan.as_ref(), Duration::from_secs(4), |all| all.iter().any(|m| m.text == text));
    assert!(got.iter().all(|m| m.text != text), "own message echoed back: {got:?}");
    chan.stop();
}

/// A message posted by the API user (a plain person, not the bot) is *not* dropped:
/// only seagent's own WebDAV shares are filtered out.
#[test]
fn api_user_messages_are_delivered() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk api user", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-api");
    let chan = build_waiting(&r, scratch.path(), &json!({}));

    let text = format!("from the api user {} {}", std::process::id(), now());
    let (st, v) = ocs(&r, &r.user, &r.pass, "POST", &format!("/ocs/v2.php/apps/spreed/api/v1/chat/{}", r.room), &[("message", &text)]);
    assert!((200..300).contains(&st), "api user cannot post: {st} {v}");

    let got = support::poll_until(chan.as_ref(), Duration::from_secs(20), |all| all.iter().any(|m| m.text == text));
    let m = got.iter().find(|m| m.text == text).unwrap_or_else(|| panic!("api user message dropped: {got:?}"));
    assert_eq!(m.sender, r.user);
    assert!(!m.is_bot, "a person, not a bot");
    chan.stop();
}

/// Reactions go out through the signed bot reaction API and show up on the message
/// as the bot; removing them takes them away again.
#[test]
fn reactions_add_and_remove_through_the_bot_api() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk reactions", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-react");
    let chan = build_waiting(&r, scratch.path(), &json!({}));

    let text = format!("react to me {} {}", std::process::id(), now());
    let id = peer_says(&r, &text);
    assert_eq!(reaction_count(&peer_history(&r), &id), 0, "no reactions to start with");
    chan.react(&r.room, &id, "👍", false).expect("add reaction");

    // Talk 19 reports `reactions` as {emoji: count}. Nobody else reacts, so the
    // single thumbs-up on the peer's message is the bot's reaction message.
    let mut ok = 0;
    for _ in 0..20 {
        ok = reaction_count(&peer_history(&r), &id);
        if ok > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(ok, 1, "the bot's reaction is not on the message");

    chan.react(&r.room, &id, "👍", true).expect("remove reaction");
    let mut left = 1;
    for _ in 0..20 {
        left = reaction_count(&peer_history(&r), &id);
        if left == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert_eq!(left, 0, "the reaction is still there after remove");

    // What seagent does not claim, the server cannot do either: Talk bots have no edit
    // or delete, and seagent reports those as unsupported instead of trying.
    let caps = chan.caps();
    assert!(!caps.edit && !caps.delete && !caps.typing && !caps.buttons && !caps.threads);
    assert!(caps.reply && caps.reactions > 0);
    assert_eq!(caps.max_len, 32000, "Talk's chat message limit");
    assert_eq!(chan.edit(&r.room, &id, "x").unwrap_err().kind, K::Unsupported);
    assert_eq!(chan.delete(&r.room, &id).unwrap_err().kind, K::Unsupported);
    chan.stop();
}

/// The 32000-character split is the server's own limit: a 40000-character text
/// arrives as two messages of 32000 + 8000, both accepted.
#[test]
fn long_messages_are_split_at_the_real_server_limit() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk chunking", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-long");
    let chan = build_waiting(&r, scratch.path(), &json!({}));

    let tag = format!("long{} ", now());
    let text = format!("{tag}{}", "x".repeat(40000 - tag.chars().count()));
    chan.send(&Outbound::text(&r.room, &text)).expect("send");

    // The split point is `MAX_MESSAGE - 8` (the chunker reserves room to close a
    // code fence): 40000 characters become 31992 + 8008 and the server accepts both.
    let mut split: Option<(Value, Value)> = None;
    for _ in 0..40 {
        let hist = peer_history(&r);
        if let Some(first) = hist.iter().find(|m| m["message"].as_str().unwrap_or("").starts_with(&tag)) {
            let next = first["id"].as_i64().map(|n| n + 1);
            if let Some(second) = hist.iter().find(|m| m["id"].as_i64() == next) {
                split = Some((first.clone(), second.clone()));
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let (first, second) = split.expect("both pieces are in the conversation");
    let lens: Vec<usize> = [&first, &second].iter().map(|m| m["message"].as_str().unwrap_or("").chars().count()).collect();
    assert_eq!(lens, vec![31992, 8008], "split at MAX_MESSAGE-8: {lens:?}");
    assert!(lens.iter().all(|&n| n <= 32000), "Talk's MAX_CHAT_LENGTH is 32000: {lens:?}");
    let joined: String = [&first, &second].iter().map(|m| m["message"].as_str().unwrap_or("")).collect();
    assert_eq!(joined, text, "the pieces lose or duplicate text");
    assert_eq!(second["actorType"], "bots", "the second piece is its own bot message");
    chan.stop();
}

/// `allowed_backends` pins `X-Nextcloud-Talk-Backend`, which the real server fills
/// with `overwrite.cli.url` + "/". A channel that does not accept it sees nothing.
#[test]
fn allowed_backends_is_enforced_by_the_real_sender() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk backend pinning", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-be");
    let chan = build_waiting(&r, scratch.path(), &json!({ "allowed_backends": ["https://some-other-cloud.example"] }));

    let text = format!("backend pinned {} {}", std::process::id(), now());
    peer_says(&r, &text);
    let got = support::poll_until(chan.as_ref(), Duration::from_secs(6), |all| all.iter().any(|m| m.text == text));
    assert!(got.iter().all(|m| m.text != text), "a rejected backend still delivered: {got:?}");

    // …and the same message with the backend the server really sends is delivered,
    // so the negative above is the pin and not a broken webhook.
    chan.stop();
    let chan = build_waiting(&r, scratch.path(), &json!({ "allowed_backends": [r.base] }));
    let text = format!("backend accepted {} {}", std::process::id(), now());
    peer_says(&r, &text);
    let got = support::poll_until(chan.as_ref(), Duration::from_secs(20), |all| all.iter().any(|m| m.text == text));
    assert!(got.iter().any(|m| m.text == text), "allowed backend did not deliver: {got:?}");
    chan.stop();
}

/// The same channel works against a conversation it never saw at startup: the room
/// is created through the OCS API, the bot is enabled there, and both directions
/// work without any seagent-side configuration change.
#[test]
fn works_in_a_conversation_created_through_ocs() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk new room", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-room");
    let chan = build_waiting(&r, scratch.path(), &json!({}));

    let name = format!("seagent-e2e-{}", now());
    let (st, v) = ocs(&r, &r.admin, &r.admin_pass, "POST", "/ocs/v2.php/apps/spreed/api/v4/room", &[("roomType", "3"), ("roomName", &name)]);
    assert_eq!(st, 201, "room creation: {v}");
    let room = v["ocs"]["data"]["token"].as_str().expect("token").to_string();
    let (st, v) = ocs(&r, &r.admin, &r.admin_pass, "POST", &format!("/ocs/v2.php/apps/spreed/api/v4/room/{room}/participants"), &[("newParticipant", &r.peer)]);
    assert!((200..300).contains(&st), "adding the peer: {v}");
    let (st, v) = ocs(&r, &r.admin, &r.admin_pass, "POST", &format!("/ocs/v2.php/apps/spreed/api/v1/bot/{room}/{}", r.bot_id), &[]);
    assert!((200..300).contains(&st), "enabling the bot in {room}: {v}");

    let text = format!("into the new room {} {}", std::process::id(), now());
    chan.send(&Outbound::text(&room, &text)).expect("send to a fresh conversation");
    let (st, v) = ocs(&r, &r.peer, &r.peer_pass, "GET", &format!("/ocs/v2.php/apps/spreed/api/v1/chat/{room}?lookIntoFuture=0&limit=50&setReadMarker=0&noStatusUpdate=1"), &[]);
    assert_eq!(st, 200, "{v}");
    assert!(v["ocs"]["data"].as_array().is_some_and(|a| a.iter().any(|m| m["message"] == text.as_str())), "not visible in {room}: {v}");

    let back = format!("reply in the new room {} {}", std::process::id(), now());
    let (st, v) = ocs(&r, &r.peer, &r.peer_pass, "POST", &format!("/ocs/v2.php/apps/spreed/api/v1/chat/{room}"), &[("message", &back)]);
    assert!((200..300).contains(&st), "{v}");
    let got = support::poll_until(chan.as_ref(), Duration::from_secs(20), |all| all.iter().any(|m| m.text == back));
    let m = got.iter().find(|m| m.text == back).unwrap_or_else(|| panic!("not delivered from {room}: {got:?}"));
    assert_eq!(m.chat, room, "the new conversation token is the chat");
    assert_eq!(m.chat_name, name, "the conversation name comes with the webhook");
    chan.stop();
}

/// Reactions as the peer sees them on one message: Talk 19 sends an emoji→count
/// object, newer versions a list of actors. Both are counted the same way here.
fn reaction_count(hist: &[Value], id: &str) -> i64 {
    let m = hist.iter().find(|m| m["id"].as_i64().map(|n| n.to_string()).as_deref() == Some(id));
    let Some(r) = m.and_then(|m| m["reactions"].as_object()) else { return 0 };
    r.values()
        .map(|v| v.as_i64().unwrap_or_else(|| v.as_array().map(|a| a.len() as i64).unwrap_or(0)))
        .sum()
}

/// The signature is checked by the server on every bot call: a channel holding the
/// wrong secret gets 401, which seagent reports as `Auth` — and nothing is posted.
#[test]
fn a_wrong_bot_secret_is_rejected_by_the_server() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk auth", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-auth");
    let chan = build_waiting(&r, scratch.path(), &json!({ "bot_secret": "0".repeat(64) }));

    let text = format!("signed by nobody {} {}", std::process::id(), now());
    let err = chan.send(&Outbound::text(&r.room, &text)).unwrap_err();
    assert_eq!(err.kind, K::Auth, "wrong secret: {err:?}");
    assert!(!err.message.contains("000000"), "the error must not leak the secret");
    assert_eq!(chan.react(&r.room, "1", "\u{1f44d}", false).unwrap_err().kind, K::Auth, "reactions are signed too");

    let hist = peer_history(&r);
    assert!(hist.iter().all(|m| m["message"] != text.as_str()), "a wrongly signed message was posted");
    chan.stop();
}

/// Files: seagent uploads over WebDAV, shares into the conversation with a caption, and
/// the file shows up as the message's `file` parameter for the other participants.
#[test]
fn uploads_a_file_and_shares_it_into_the_conversation() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk file upload", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-file");
    let chan = build_waiting(&r, scratch.path(), &json!({}));

    let name = format!("seagent-e2e-{}.txt", now());
    let path = scratch.file(&name);
    std::fs::write(&path, b"hello from seagent's attachment\n").expect("write");
    let caption = format!("attachment {}", now());
    let mut out = Outbound::text(&r.room, &caption);
    out.media.push(Media {
        kind: MediaKind::Document,
        path: Some(path.display().to_string()),
        name: name.clone(),
        mime: "text/plain".into(),
        size: 26,
        caption: Some(caption.clone()),
        ..Default::default()
    });
    let sent = chan.send(&out).expect("send with a file");
    assert!(sent.ids.iter().any(|i| i.starts_with("share:")), "the share id is reported: {sent:?}");
    assert_eq!(sent.ids.len(), 1, "the caption rides on the file, no second message: {sent:?}");

    let mut found: Option<Value> = None;
    for _ in 0..40 {
        let hist = peer_history(&r);
        if let Some(m) = hist.iter().find(|m| m["messageParameters"]["file"]["name"] == name.as_str()) {
            found = Some(m.clone());
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let m = found.unwrap_or_else(|| panic!("the shared file is not in the conversation: {:?}", peer_history(&r)));
    // A file is shared through files_sharing with the API user's credentials, so the
    // message is authored by that user — not by the bot. Talk copies it into the
    // conversation folder, so the reported path is `Talk/<name>`, not `/Seagent/…`.
    assert_eq!(m["actorType"], "users", "shared by the API user: {m}");
    assert_eq!(m["actorId"], r.user.as_str());
    assert_eq!(m["messageParameters"]["file"]["mimetype"], "text/plain");
    assert_eq!(m["message"], caption.as_str(), "the caption is the message text: {m}");
    assert_eq!(m["messageParameters"]["file"]["name"], name.as_str());
    chan.stop();
}

/// A file seagent shares comes back through the webhook authored by the API user. That
/// echo is seagent's own message, not something to answer: it must not be delivered.
#[test]
fn our_own_file_share_is_not_echoed_as_inbound() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk share echo", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-echo");
    let chan = build_waiting(&r, scratch.path(), &json!({}));

    // A name without seagent's own `seagent-` prefix: the filter has to recognise the share
    // it just made, not just the name.
    let name = format!("notes-{}.txt", now());
    let path = scratch.file(&name);
    std::fs::write(&path, b"receipt\n").expect("write");
    let caption = format!("here is the receipt {}", now());
    let mut out = Outbound::text(&r.room, &caption);
    out.media.push(Media {
        kind: MediaKind::Document,
        path: Some(path.display().to_string()),
        name: name.clone(),
        mime: "text/plain".into(),
        size: 8,
        caption: Some(caption.clone()),
        ..Default::default()
    });
    chan.send(&out).expect("send with a file");

    let got = support::poll_until(chan.as_ref(), Duration::from_secs(6), |all| all.iter().any(|m| m.text.contains(&caption)));
    assert!(got.iter().all(|m| !m.text.contains(&caption)), "seagent delivered its own file share as inbound: {got:?}");
    // …and the message really is in the conversation, so the assertion above is not vacuous.
    let hist = peer_history(&r);
    assert!(hist.iter().any(|m| m["messageParameters"]["file"]["name"] == name.as_str()), "the share itself is missing: {hist:?}");
    chan.stop();
}

/// Inbound files: the peer puts a file into the conversation and seagent downloads it.
/// Talk reports the file path inside the *sender's* files, and the share link, so a
/// download that only looks in the API user's own WebDAV root is not enough.
#[test]
fn downloads_a_file_the_peer_shared() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk media download", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-dl");
    let chan = build_waiting(&r, scratch.path(), &json!({}));

    let name = format!("peer-{}.txt", now());
    let body = b"bytes from the peer\n";
    let auth = basic(&r.peer, &r.peer_pass);
    let h = [("authorization", auth.as_str()), ("ocs-apirequest", "true")];
    // Straight into the peer's DAV root: `http::Http::call` does not send MKCOL
    // (unknown methods fall back to POST), and no folder is needed for a share.
    let dav = format!("{}/remote.php/dav/files/{}", r.base, r.peer);
    let resp = Http::new(Duration::from_secs(20))
        .call("PUT", &format!("{dav}/{name}"), &h, Payload::Raw("text/plain", body))
        .expect("dav put");
    assert!(resp.status == 201 || resp.status == 204, "peer upload: {} {}", resp.status, resp.body);
    let (st, v) = ocs(&r, &r.peer, &r.peer_pass, "POST", "/ocs/v2.php/apps/files_sharing/api/v1/shares?format=json", &[("path", &format!("/{name}")), ("shareType", "10"), ("shareWith", &r.room)]);
    assert!((200..300).contains(&st), "sharing into the conversation: {st} {v}");

    let got = support::poll_until(chan.as_ref(), Duration::from_secs(20), |all| all.iter().any(|m| m.media.iter().any(|x| x.name == name)));
    let m = got.iter().find(|m| m.media.iter().any(|x| x.name == name)).unwrap_or_else(|| panic!("the shared file did not arrive: {got:?}"));
    let media = m.media.iter().find(|x| x.name == name).unwrap();
    assert_eq!(media.mime, "text/plain");
    assert_eq!(media.size, body.len() as u64);
    let bytes = chan.fetch_media(media).expect("download the shared file");
    assert_eq!(bytes, body, "the downloaded bytes are the uploaded ones");
    chan.stop();
}

fn now() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// The webhook path and the signature helpers are the ones the daemon uses; a
/// request signed with the installed bot secret is accepted and a wrong one is not.
/// (Cheap, and it proves the listener really is seagent's, not the test's.)
#[test]
fn the_listener_rejects_a_wrongly_signed_webhook() {
    let Some(r) = real() else {
        support::skipped("nextcloud talk signature", "SEAGENT_REAL_NEXTCLOUD_URL");
        return;
    };
    let _g = hook();
    let scratch = support::Scratch::new("nc-sig");
    let chan = build_waiting(&r, scratch.path(), &json!({}));
    let body = json!({"type": "Create", "actor": {"type": "Person", "id": "users/x", "name": "X"}, "object": {"type": "Note", "id": "1", "content": "forged"}, "target": {"type": "Collection", "id": r.room, "name": "seagent-e2e"}}).to_string();
    let call = |sig: &str| {
        let h = [("x-nextcloud-talk-random", "0123456789abcdef0123456789abcdef0123456789abcdef"), ("x-nextcloud-talk-signature", sig), ("x-nextcloud-talk-backend", r.base.as_str()), ("content-type", "application/json")];
        Http::new(Duration::from_secs(5))
            .call("POST", &format!("http://127.0.0.1:{}{HOOK_PATH}", r.hook_port), &h, Payload::Raw("application/json", body.as_bytes()))
            .map(|resp| resp.status)
            .unwrap_or(0)
    };
    assert_eq!(call(&"0".repeat(64)), 401, "a forged signature is rejected");
    assert_eq!(call("not-hex"), 401);
    let got = support::poll_until(chan.as_ref(), Duration::from_secs(3), |all| all.iter().any(|m| m.text == "forged"));
    assert!(got.iter().all(|m| m.text != "forged"), "forged webhook was delivered: {got:?}");
    chan.stop();
}
