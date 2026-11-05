//! Real Mattermost integration test (podman `mattermost/mattermost-team-edition`
//! + Postgres, started by `tests/real/mattermost_up.sh`).
//!
//! Opt in with `SEAGENT_REAL_MATTERMOST_URL`, `SEAGENT_REAL_MATTERMOST_TOKEN` (bot
//! token), `SEAGENT_REAL_MATTERMOST_CHANNEL`, `SEAGENT_REAL_MATTERMOST_TEAM`,
//! `SEAGENT_REAL_MATTERMOST_PEER_TOKEN` / `_PEER_ID` (a human account) and
//! `SEAGENT_REAL_MATTERMOST_BOT_ID`; skipped otherwise. The peer uses its own HTTP
//! client: that is the human, not the code under test. The channel is built
//! through the real `[channels.*]` config path, so this proves the wiring too.

mod support;

use seagent_channel::http::{Http, Payload};
use seagent_channel::{config, Channel, ChannelErrorKind, ChatType, Outbound};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

struct Real {
    url: String,
    token: String,
    channel: String,
    team: String,
    peer_token: String,
    peer: String,
    bot: String,
    bot2_token: Option<String>,
    bot2: Option<String>,
}

fn real() -> Option<Real> {
    Some(Real {
        url: std::env::var("SEAGENT_REAL_MATTERMOST_URL").ok()?.trim().trim_end_matches('/').to_string(),
        token: std::env::var("SEAGENT_REAL_MATTERMOST_TOKEN").ok()?,
        channel: std::env::var("SEAGENT_REAL_MATTERMOST_CHANNEL").ok()?,
        team: std::env::var("SEAGENT_REAL_MATTERMOST_TEAM").ok()?,
        peer_token: std::env::var("SEAGENT_REAL_MATTERMOST_PEER_TOKEN").ok()?,
        peer: std::env::var("SEAGENT_REAL_MATTERMOST_PEER_ID").ok()?,
        bot: std::env::var("SEAGENT_REAL_MATTERMOST_BOT_ID").ok()?,
        bot2_token: std::env::var("SEAGENT_REAL_MATTERMOST_BOT2_TOKEN").ok(),
        bot2: std::env::var("SEAGENT_REAL_MATTERMOST_BOT2_ID").ok(),
    })
}

/// A REST call as one of the two real accounts, not through seagent.
fn api(r: &Real, method: &str, path: &str, token: &str, body: Value) -> (u16, Value) {
    let resp = Http::new(Duration::from_secs(30))
        .bearer(token)
        .call(method, &format!("{}{path}", r.url), &[], if body.is_null() { Payload::None } else { Payload::Json(&body) })
        .unwrap_or_else(|e| panic!("{method} {path}: {e}"));
    let v: Value = serde_json::from_str(&resp.body).unwrap_or(Value::Null);
    (resp.status, v)
}

fn ok(r: &Real, method: &str, path: &str, token: &str, body: Value) -> Value {
    let (st, v) = api(r, method, path, token, body);
    assert!((200..300).contains(&st), "{method} {path}: HTTP {st} {v}");
    v
}

/// `text` posted by the human peer at the top level, or as a thread reply.
fn peer_post(r: &Real, text: &str, root: Option<&str>) -> String {
    let mut body = json!({"channel_id": r.channel, "message": text});
    if let Some(root) = root {
        body["root_id"] = json!(root);
    }
    ok(r, "POST", "/api/v4/posts", &r.peer_token, body)["id"].as_str().expect("post id").to_string()
}

fn build(r: &Real, token: &str, state: &std::path::Path) -> std::sync::Arc<dyn Channel> {
    build_opts(r, token, state, false)
}

fn build_opts(r: &Real, token: &str, state: &std::path::Path, reaction_events: bool) -> std::sync::Arc<dyn Channel> {
    let v = json!({
        "kind": "mattermost",
        "url": r.url,
        "token": token,
        "poll_timeout_secs": 5,
        "reaction_events": reaction_events,
    });
    let cfg = config::parse_config("mattermost-real", &v).expect("parse");
    let secrets: config::Secrets = std::sync::Arc::new(|s: &str| s.to_string());
    config::build("mattermost-real", &cfg, state, &secrets).expect("build")
}

fn uniq(tag: &str) -> String {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{tag}-{}-{n}", std::process::id())
}

/// Poll until `f` matches or `timeout` passes, returning everything seen.
fn poll_until(chan: &dyn Channel, timeout: Duration, mut f: impl FnMut(&seagent_channel::Inbound) -> bool) -> Vec<seagent_channel::Inbound> {
    let cancel = seagent_core::Cancel::new();
    let end = Instant::now() + timeout;
    let mut all: Vec<seagent_channel::Inbound> = Vec::new();
    while Instant::now() < end {
        match chan.poll(&cancel) {
            Ok(batch) => {
                for m in batch {
                    all.push(m);
                }
            }
            Err(e) => panic!("poll failed: {e}"),
        }
        if all.iter().any(&mut f) {
            break;
        }
    }
    all
}

/// The bot's socket may still be authenticating when the peer posts; retry the
/// post (with a fresh marker) until an event arrives, as a person would.
fn deliver(chan: &dyn Channel, r: &Real, tag: &str, mk: impl Fn(&str) -> String) -> (String, seagent_channel::Inbound) {
    let mut last = String::new();
    for _ in 0..4 {
        let text = mk(&uniq(tag));
        last = text.clone();
        let id = peer_post(r, &text, None);
        let got = poll_until(chan, Duration::from_secs(8), |m| m.text == text);
        if let Some(m) = got.into_iter().find(|m| m.text == text) {
            return (id, m);
        }
    }
    panic!("the bot never received {last:?}");
}

/// Inbound: a peer's post arrives with the real channel/sender/thread, and the
/// bot's own posts are not echoed back.
#[test]
fn receives_peer_posts_on_real_mattermost() {
    let Some(r) = real() else {
        support::skipped("mattermost inbound", "SEAGENT_REAL_MATTERMOST_URL");
        return;
    };
    let scratch = support::Scratch::new("mm-in");
    let chan = build(&r, &r.token, scratch.path());
    // Opens the websocket; the first poll may return nothing.
    let _ = chan.poll(&seagent_core::Cancel::new());

    let (id, m) = deliver(chan.as_ref(), &r, "in", |u| format!("hello from a real mattermost {u}"));
    assert_eq!(m.chat, r.channel, "chat is the channel id");
    assert_eq!(m.sender, r.peer, "sender is the peer's user id");
    assert_eq!(m.message_id, id, "the server's post id");
    assert_eq!(m.chat_type, ChatType::Group, "public channel O: {m:?}");
    assert_eq!(m.chat_name, "Seagent E2E");
    assert_eq!(m.thread, None);
    assert_eq!(m.account, r.team, "account is the team id");
    assert_eq!(m.sender_name, "seagentpeer", "sender_name without the @: {m:?}");
    assert!(!m.mentioned, "no mention in the text: {m:?}");
    assert!(!m.is_bot, "a human post is not a bot post");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    assert!((now - m.ts).abs() < 300, "create_at is milliseconds on the wire, seconds in Inbound: {m:?}");

    // `@seagentbot` in the text is a mention the real server resolves for us.
    let mention = format!("@seagentbot ping {}", uniq("mention"));
    let mention_id = peer_post(&r, &mention, None);
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.message_id == mention_id);
    let men = got.iter().find(|m| m.message_id == mention_id).unwrap_or_else(|| panic!("mention not delivered: {got:?}"));
    assert!(men.mentioned, "@seagentbot must set mentioned: {men:?}");

    // A prefix of another bot's name is not a mention of this bot.
    let near = format!("@seagentbot2 not for seagent {}", uniq("near"));
    let near_id = peer_post(&r, &near, None);
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.message_id == near_id);
    let nm = got.iter().find(|m| m.message_id == near_id).unwrap_or_else(|| panic!("near-mention not delivered: {got:?}"));
    assert!(!nm.mentioned, "@seagentbot2 is not @seagentbot: {nm:?}");

    // An inbound edit: `post_edited` carries the new text and `edit_at`.
    let edited_text = format!("edited by the peer {}", uniq("edit"));
    let (st, v) = api(&r, "PUT", &format!("/api/v4/posts/{id}/patch"), &r.peer_token, json!({"message": edited_text}));
    assert_eq!(st, 200, "peer edit: {v}");
    let edit_at = v["edit_at"].as_i64().unwrap_or(0);
    assert!(edit_at > 0, "the server stamped edit_at: {v}");
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.edited && m.text == edited_text);
    let ed = got.iter().find(|m| m.edited && m.text == edited_text).unwrap_or_else(|| panic!("inbound edit not delivered: {got:?}"));
    assert_eq!(ed.message_id, format!("{id}:e{edit_at}"), "edit ids differ from the original");
    assert_eq!(ed.sender, r.peer);
    assert_eq!(ed.thread, None);
    assert_eq!(ed.chat, r.channel);

    // A thread reply: root id, thread chat type and a reply reference.
    let root = peer_post(&r, &format!("thread root {}", uniq("root")), None);
    let reply_text = uniq("reply");
    let reply_id = peer_post(&r, &reply_text, Some(&root));
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.message_id == reply_id);
    let rep = got.iter().find(|m| m.message_id == reply_id).unwrap_or_else(|| panic!("thread reply not delivered: {got:?}"));
    assert_eq!(rep.text, reply_text);
    assert_eq!(rep.thread.as_deref(), Some(root.as_str()), "thread is the root id");
    assert_eq!(rep.chat_type, ChatType::Thread);
    assert_eq!(rep.reply.as_ref().map(|x| x.id.as_str()), Some(root.as_str()));
    assert_eq!(rep.reply.as_ref().map(|x| x.is_own), Some(false), "the root was the peer's");

    // Our own post must not come back as inbound (the server echoes WS events).
    let text = uniq("echo");
    let sent = chan.send(&Outbound::text(&r.channel, &text)).expect("send");
    let back = poll_until(chan.as_ref(), Duration::from_secs(3), |_| false);
    assert!(!back.iter().any(|m| m.text == text), "own post echoed back: {back:?}");
    assert!(!back.iter().any(|m| m.sender == r.bot), "bot post echoed back: {back:?}");
    assert_eq!(sent.ids.len(), 1);
    assert!(!m.addressed(), "a plain channel post is not addressed to the bot: {m:?}");

    // A reply in the bot's own thread counts as addressed (`reply.is_own`).
    let own_id = sent.ids[0].clone();
    let answer = format!("answering seagent {}", uniq("ownthread"));
    let answer_id = peer_post(&r, &answer, Some(&own_id));
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.message_id == answer_id);
    let am = got.iter().find(|m| m.message_id == answer_id).unwrap_or_else(|| panic!("reply to the bot not delivered: {got:?}"));
    assert_eq!(am.thread.as_deref(), Some(own_id.as_str()));
    assert_eq!(am.reply.as_ref().map(|x| x.is_own), Some(true), "the thread root is the bot's own post: {am:?}");
    assert!(am.addressed(), "a reply in the bot's thread is addressed to it: {am:?}");

    // An edit inside a thread: `post_edited` carries root_id and edit_at.
    let rep_edit = format!("thread reply edited {}", uniq("tredit"));
    let (st, v) = api(&r, "PUT", &format!("/api/v4/posts/{reply_id}/patch"), &r.peer_token, json!({"message": rep_edit}));
    assert!((200..300).contains(&st), "peer thread edit: {st} {v}");
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.edited && m.text == rep_edit);
    let te = got.iter().find(|m| m.edited && m.text == rep_edit).unwrap_or_else(|| panic!("thread edit not delivered: {got:?}"));
    assert_eq!(te.thread.as_deref(), Some(root.as_str()), "an edited reply stays in its thread: {te:?}");
    assert_eq!(te.chat_type, ChatType::Thread);
    assert!(te.message_id.starts_with(&format!("{reply_id}:e")), "edit id: {}", te.message_id);
}

/// Outbound: the server stores exactly what seagent sent; edits, thread replies,
/// the emoji mapping and long-text splitting all round-trip.
#[test]
fn sends_edits_and_threads_on_real_mattermost() {
    let Some(r) = real() else {
        support::skipped("mattermost outbound", "SEAGENT_REAL_MATTERMOST_URL");
        return;
    };
    let scratch = support::Scratch::new("mm-out");
    let chan = build(&r, &r.token, scratch.path());

    let text = uniq("seagent says hi");
    let sent = chan.send(&Outbound::text(&r.channel, &text)).expect("send");
    let id = sent.ids.first().expect("one post id").clone();
    let stored = ok(&r, "GET", &format!("/api/v4/posts/{id}"), &r.token, Value::Null);
    assert_eq!(stored["message"].as_str(), Some(text.as_str()), "the server shows exactly our text: {stored}");
    assert_eq!(stored["channel_id"].as_str(), Some(r.channel.as_str()));
    assert_eq!(stored["user_id"].as_str(), Some(r.bot.as_str()));

    // Edit round-trip (PUT /posts/{id}/patch).
    let edited = uniq("edited by seagent");
    chan.edit(&r.channel, &id, &edited).expect("edit");
    let stored = ok(&r, "GET", &format!("/api/v4/posts/{id}"), &r.token, Value::Null);
    assert_eq!(stored["message"].as_str(), Some(edited.as_str()), "edit landed: {stored}");

    // Thread reply: root_id is set from `reply_to`.
    let root = peer_post(&r, &format!("root for seagent {}", uniq("root")), None);
    let mut out = Outbound::text(&r.channel, &uniq("seagent replies in thread"));
    out.reply_to = Some(root.clone());
    let sent = chan.send(&out).expect("thread reply");
    let rid = sent.ids.first().expect("reply id").clone();
    let stored = ok(&r, "GET", &format!("/api/v4/posts/{rid}"), &r.token, Value::Null);
    assert_eq!(stored["root_id"].as_str(), Some(root.as_str()), "root_id: {stored}");

    // `reply_to` may be a reply, not the root: the root id is walked up over REST.
    let inner = peer_post(&r, &uniq("reply in the thread"), Some(&root));
    let mut out = Outbound::text(&r.channel, &uniq("seagent replies to a reply"));
    out.reply_to = Some(inner.clone());
    let sent = chan.send(&out).expect("reply to a reply");
    let stored = ok(&r, "GET", &format!("/api/v4/posts/{}", sent.ids[0]), &r.token, Value::Null);
    assert_eq!(stored["root_id"].as_str(), Some(root.as_str()), "a reply's root must be the thread root: {stored}");

    // A `thread` that is a reply's id: the server rejects it with 400
    // `api.post.create_post.root_id.app_error`, and seagent reposts at the top
    // level instead of failing (the real error text must keep matching).
    let mut out = Outbound::text(&r.channel, &uniq("seagent with a stale thread"));
    out.thread = Some(inner);
    let sent = chan.send(&out).expect("a root_id the server refuses must not fail the send");
    let stored = ok(&r, "GET", &format!("/api/v4/posts/{}", sent.ids[0]), &r.token, Value::Null);
    assert_eq!(stored["root_id"].as_str(), Some(""), "fell back to a top-level post: {stored}");

    // Reaction: the emoji name mapping must be understood by the real server.
    chan.react(&r.channel, &root, "👍", false).expect("react");
    let reactions = ok(&r, "GET", &format!("/api/v4/posts/{root}/reactions"), &r.token, Value::Null);
    let mine = reactions.as_array().into_iter().flatten().find(|x| x["user_id"].as_str() == Some(r.bot.as_str())).unwrap_or_else(|| panic!("no reaction from the bot: {reactions}"));
    assert_eq!(mine["emoji_name"].as_str(), Some("+1"), "👍 maps to +1");
    chan.react(&r.channel, &root, "👍", true).expect("unreact");
    let reactions = ok(&r, "GET", &format!("/api/v4/posts/{root}/reactions"), &r.token, Value::Null);
    assert!(!reactions.as_array().into_iter().flatten().any(|x| x["user_id"].as_str() == Some(r.bot.as_str())), "reaction removed: {reactions}");

    // A post over the 16383-character limit is split into several posts.
    let long = format!("{}{}{}", uniq("start"), "長".repeat(16_500), uniq("end"));
    assert!(long.chars().count() > seagent_channel::mattermost::MAX_MESSAGE);
    let sent = chan.send(&Outbound::text(&r.channel, &long)).expect("long send");
    assert!(sent.ids.len() >= 2, "long text must be split: {sent:?}");
    let mut joined = String::new();
    for pid in &sent.ids {
        let p = ok(&r, "GET", &format!("/api/v4/posts/{pid}"), &r.token, Value::Null);
        let msg = p["message"].as_str().unwrap_or_else(|| panic!("post {pid} without message: {p}"));
        assert!(msg.chars().count() <= seagent_channel::mattermost::MAX_MESSAGE, "piece over the limit: {} chars", msg.chars().count());
        assert_eq!(p["channel_id"].as_str(), Some(r.channel.as_str()));
        joined.push_str(msg);
    }
    assert!(joined.starts_with("start-"), "first piece lost the head: {:.60}", &joined[..joined.len().min(60)]);
    assert!(joined.ends_with(&long[long.len() - 20..]), "last piece lost the tail");
    assert_eq!(joined.chars().filter(|c| *c == '長').count(), 16_500, "every character is stored");
}

/// A direct message (`user:<id>`) and a file upload use the real REST shapes
/// (`/channels/direct`, multipart `/files`), and a delete really deletes.
#[test]
fn direct_messages_uploads_and_deletes_on_real_mattermost() {
    let Some(r) = real() else {
        support::skipped("mattermost dm/upload", "SEAGENT_REAL_MATTERMOST_URL");
        return;
    };
    let scratch = support::Scratch::new("mm-dm");
    let chan = build(&r, &r.token, scratch.path());
    // Before the socket is up, typing falls back to POST /users/me/typing.
    chan.typing(&r.channel, None).expect("typing over REST");
    // Opens the websocket: the peer's DM below must be posted after this.
    let _ = chan.poll(&seagent_core::Cancel::new());

    // `user:<id>` must resolve to a D channel through POST /channels/direct.
    let dm_text = uniq("dm from seagent");
    chan.send(&Outbound::text(&format!("user:{}", r.peer), &dm_text)).expect("dm send");
    // `POST /channels/direct` is idempotent: asking as the peer returns the same D channel.
    let dm = ok(&r, "POST", "/api/v4/channels/direct", &r.peer_token, json!([r.peer, r.bot]));
    let dm_id = dm["id"].as_str().expect("dm channel id").to_string();
    assert_eq!(dm["type"].as_str(), Some("D"));
    let posts = ok(&r, "GET", &format!("/api/v4/channels/{dm_id}/posts?per_page=20"), &r.peer_token, Value::Null);
    let found = posts["posts"].as_object().into_iter().flat_map(|o| o.values()).any(|p| p["message"].as_str() == Some(dm_text.as_str()) && p["user_id"].as_str() == Some(r.bot.as_str()));
    assert!(found, "the DM did not reach the peer: {posts}");

    // `@username` resolves through GET /users/username/{name} to the same D channel.
    let at_text = uniq("dm by username");
    chan.send(&Outbound::text("@seagentpeer", &at_text)).expect("dm by @username");
    let posts = ok(&r, "GET", &format!("/api/v4/channels/{dm_id}/posts?per_page=20"), &r.peer_token, Value::Null);
    assert!(posts["posts"].as_object().into_iter().flat_map(|o| o.values()).any(|p| p["message"].as_str() == Some(at_text.as_str())), "@seagentpeer did not reach the DM: {posts}");

    // A DM reply arrives as `ChatType::Direct` with the D channel as chat.
    let reply_text = uniq("dm reply");
    let pid = ok(&r, "POST", "/api/v4/posts", &r.peer_token, json!({"channel_id": dm_id, "message": reply_text}))["id"].as_str().expect("id").to_string();
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.message_id == pid);
    let m = got.iter().find(|m| m.message_id == pid).unwrap_or_else(|| panic!("dm not delivered: {got:?}"));
    assert_eq!(m.chat, dm_id);
    assert_eq!(m.chat_type, ChatType::Direct);
    assert_eq!(m.thread, None);
    assert_eq!(m.sender, r.peer);

    // Upload: a file with a local path goes through multipart POST /files first.
    let body = format!("seagent upload {}\n", uniq("file"));
    let file = scratch.file("note.txt");
    std::fs::write(&file, &body).expect("write");
    let media = seagent_channel::Media { kind: seagent_channel::MediaKind::Document, path: Some(file.display().to_string()), name: "note.txt".into(), mime: "text/plain".into(), ..Default::default() };
    let out = Outbound { chat: r.channel.clone(), text: "with a file".into(), media: vec![media], ..Default::default() };
    let sent = chan.send(&out).expect("upload send");
    let pid = sent.ids.first().expect("id").clone();
    let post = ok(&r, "GET", &format!("/api/v4/posts/{pid}"), &r.token, Value::Null);
    let fid = post["file_ids"][0].as_str().unwrap_or_else(|| panic!("no file_ids: {post}")).to_string();
    let info = ok(&r, "GET", &format!("/api/v4/files/{fid}/info"), &r.token, Value::Null);
    assert_eq!(info["name"].as_str(), Some("note.txt"));
    assert_eq!(info["size"].as_u64(), Some(body.len() as u64), "the whole file was uploaded: {info}");
    let downloaded = chan.fetch_media(&seagent_channel::Media { id: Some(fid), ..Default::default() }).expect("fetch_media");
    assert_eq!(downloaded, body.as_bytes(), "fetch_media reads it back with the bot token");

    // A file without text: one post whose message is empty, as the API allows.
    let only = scratch.file("only.txt");
    std::fs::write(&only, b"file only\n").expect("write");
    let media = seagent_channel::Media { kind: seagent_channel::MediaKind::Document, path: Some(only.display().to_string()), name: "only.txt".into(), mime: "text/plain".into(), ..Default::default() };
    let sent = chan.send(&Outbound { chat: r.channel.clone(), media: vec![media], ..Default::default() }).expect("file-only send");
    let post = ok(&r, "GET", &format!("/api/v4/posts/{}", sent.ids[0]), &r.token, Value::Null);
    assert_eq!(post["message"].as_str(), Some(""), "an empty message with files: {post}");
    assert_eq!(post["file_ids"].as_array().map(Vec::len), Some(1), "the file is attached: {post}");

    // A peer's upload arrives as `Inbound.media` (the WS event's file metadata).
    let peer_file = format!("peer upload {}\n", uniq("peerfile"));
    let parts: [(&str, &str, &str, &[u8]); 2] = [("channel_id", "", "", r.channel.as_bytes()), ("files", "peer.txt", "text/plain", peer_file.as_bytes())];
    let up = Http::new(Duration::from_secs(30)).bearer(&r.peer_token).call("POST", &format!("{}/api/v4/files", r.url), &[], Payload::Multipart(&parts)).expect("peer upload");
    assert_eq!(up.status, 201, "peer upload: {} {}", up.status, up.body);
    let up: Value = serde_json::from_str(&up.body).expect("json");
    let peer_fid = up["file_infos"][0]["id"].as_str().expect("file id").to_string();
    let fpid = ok(&r, "POST", "/api/v4/posts", &r.peer_token, json!({"channel_id": r.channel, "message": "", "file_ids": [peer_fid]}))["id"].as_str().expect("id").to_string();
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.message_id == fpid);
    let m = got.iter().find(|m| m.message_id == fpid).unwrap_or_else(|| panic!("file post not delivered: {got:?}"));
    assert_eq!(m.media.len(), 1, "one file: {m:?}");
    assert_eq!(m.media[0].id.as_deref(), Some(peer_fid.as_str()));
    assert_eq!(m.media[0].kind, seagent_channel::MediaKind::Document, "text/plain is a document: {:?}", m.media[0]);
    assert_eq!(chan.fetch_media(&m.media[0]).expect("fetch inbound media"), peer_file.as_bytes());

    // Delete: the bot's own post is gone afterwards.
    chan.delete(&r.channel, &pid).expect("delete");
    let (st, _) = api(&r, "GET", &format!("/api/v4/posts/{pid}"), &r.token, Value::Null);
    assert_eq!(st, 404, "a deleted post is gone");
}

/// Another bot's post arrives with `is_bot`, and a reaction event arrives with
/// the real broadcast shape; typing frames must not kill the socket.
#[test]
fn bot_posts_and_reaction_events_on_real_mattermost() {
    let Some(r) = real() else {
        support::skipped("mattermost bot/reaction", "SEAGENT_REAL_MATTERMOST_URL");
        return;
    };
    let (Some(bot2_token), Some(bot2)) = (r.bot2_token.clone(), r.bot2.clone()) else {
        eprintln!("skipped: mattermost bot/reaction (set SEAGENT_REAL_MATTERMOST_BOT2_TOKEN/_BOT2_ID to run)");
        return;
    };
    let scratch = support::Scratch::new("mm-bot");
    let chan = build_opts(&r, &r.token, scratch.path(), true);
    let _ = chan.poll(&seagent_core::Cancel::new());

    // Another bot posts: the event arrives and is marked as a bot.
    let text = uniq("from the other bot");
    let pid = ok(&r, "POST", "/api/v4/posts", &bot2_token, json!({"channel_id": r.channel, "message": text}))["id"].as_str().expect("id").to_string();
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.message_id == pid);
    let m = got.iter().find(|m| m.message_id == pid).unwrap_or_else(|| panic!("another bot's post not delivered: {got:?}"));
    assert_eq!(m.sender, bot2);
    assert!(m.is_bot, "props.from_bot must map to is_bot: {m:?}");

    // Typing over the websocket: the frame must not break the connection.
    chan.typing(&r.channel, None).expect("typing");

    // The peer reacts with :eyes:; reaction_events delivers it as a message.
    let (st, v) = api(&r, "POST", "/api/v4/reactions", &r.peer_token, json!({"user_id": r.peer, "post_id": pid, "emoji_name": "eyes"}));
    assert!((200..300).contains(&st), "react: {st} {v}");
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.text.starts_with(":eyes:"));
    let re = got.iter().find(|m| m.text.starts_with(":eyes:")).unwrap_or_else(|| panic!("reaction event not delivered: {got:?}"));
    assert_eq!(re.text, ":eyes: reaction added");
    assert_eq!(re.sender, r.peer);
    assert_eq!(re.chat, r.channel);
    assert_eq!(re.message_id, format!("r:{pid}:{}:eyes:+", r.peer));
    assert_eq!(re.reply.as_ref().map(|x| x.id.as_str()), Some(pid.as_str()));

    // The socket is still alive after the typing frame: a peer post arrives.
    let after = format!("still connected {}", uniq("after"));
    let aid = peer_post(&r, &after, None);
    let got = poll_until(chan.as_ref(), Duration::from_secs(10), |m| m.message_id == aid);
    assert!(got.iter().any(|m| m.message_id == aid), "the websocket died after typing: {got:?}");
}

/// The real websocket answers seagent's ping frames; if it did not, `ping_every`
/// (30 s) would tear down a healthy connection.
#[test]
fn websocket_pings_and_authenticates_on_real_mattermost() {
    use seagent_net::ws::{Message, WebSocket};
    let Some(r) = real() else {
        support::skipped("mattermost websocket", "SEAGENT_REAL_MATTERMOST_URL");
        return;
    };
    let url = format!("{}/api/v4/websocket", r.url.replacen("http://", "ws://", 1));
    let bearer = format!("Bearer {}", r.token);
    let (mut ws, _) = WebSocket::connect(&url, &[("Authorization", &bearer)], Duration::from_secs(15)).expect("ws connect");
    ws.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
    ws.send_text(&json!({"seq": 1, "action": "authentication_challenge", "data": {"token": r.token}}).to_string()).expect("auth frame");

    // Mattermost 12 answers `hello` at once and there is no `seq_reply` frame
    // for the challenge at all; auth is proven by a `posted` event arriving.
    ws.send(&Message::Ping(b"seagent".to_vec())).expect("ping");
    let proof = uniq("ws proof");
    ok(&r, "POST", "/api/v4/posts", &r.peer_token, json!({"channel_id": r.channel, "message": proof}));
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut authed, mut pong) = (false, false);
    while Instant::now() < deadline && !(authed && pong) {
        match ws.recv() {
            Ok(Some(Message::Text(t))) => {
                let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                let post: Value = serde_json::from_str(v["data"]["post"].as_str().unwrap_or("{}")).unwrap_or(Value::Null);
                if v["event"] == "posted" && post["message"].as_str() == Some(proof.as_str()) {
                    authed = true;
                }
            }
            Ok(Some(Message::Pong(_))) => pong = true,
            Ok(_) => {}
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    assert!(authed, "the challenge was never accepted (no posted event in 10 s)");
    assert!(pong, "the server never answered a websocket ping frame");

    // A bad token: the connection is closed instead of authenticating.
    let (mut bad, _) = WebSocket::connect(&url, &[("Authorization", "Bearer 0000000000000000000000000x")], Duration::from_secs(15)).expect("ws connect");
    bad.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
    let _ = bad.send_text(&json!({"seq": 1, "action": "authentication_challenge", "data": {"token": "0000000000000000000000000x"}}).to_string());
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut refused = false;
    while Instant::now() < deadline && !refused {
        match bad.recv() {
            Ok(Some(Message::Text(t))) => {
                let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                if v["status"].as_str().is_some_and(|s| s != "OK") && (v["seq_reply"].is_number() || v["error"].is_object()) {
                    refused = true;
                }
            }
            // Mattermost closes the socket for a rejected challenge: the
            // frame may be a Close or a bare EOF (no Close frame at all).
            Ok(Some(Message::Close(_))) | Err(_) => refused = true,
            Ok(_) => {}
        }
    }
    assert!(refused, "a bad token was silently accepted on the websocket");
}

/// Typing over the websocket is the preferred path; it must reach another
/// member as a `typing` event (a silently rejected action would mean typing
/// never works in practice, since the frame send itself succeeds).
#[test]
fn typing_over_the_websocket_reaches_the_peer_on_real_mattermost() {
    use seagent_net::ws::{Message, WebSocket};
    let Some(r) = real() else {
        support::skipped("mattermost typing", "SEAGENT_REAL_MATTERMOST_URL");
        return;
    };
    let url = format!("{}/api/v4/websocket", r.url.replacen("http://", "ws://", 1));
    let bearer = format!("Bearer {}", r.peer_token);
    let (mut ws, _) = WebSocket::connect(&url, &[("Authorization", &bearer)], Duration::from_secs(15)).expect("ws connect");
    ws.set_read_timeout(Some(Duration::from_millis(200))).expect("timeout");
    ws.send_text(&json!({"seq": 1, "action": "authentication_challenge", "data": {"token": r.peer_token}}).to_string()).expect("auth frame");
    // Proof that the peer's socket is authenticated and subscribed: a bot post
    // arrives as a `posted` event (the author's own session is omitted).
    let proof = uniq("ws proof");
    ok(&r, "POST", "/api/v4/posts", &r.token, json!({"channel_id": r.channel, "message": proof}));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut online = false;
    while Instant::now() < deadline && !online {
        match ws.recv() {
            Ok(Some(Message::Text(t))) => {
                let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                let post: Value = serde_json::from_str(v["data"]["post"].as_str().unwrap_or("{}")).unwrap_or(Value::Null);
                online = v["event"] == "posted" && post["message"].as_str() == Some(proof.as_str());
            }
            Ok(_) => {}
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    assert!(online, "the peer's websocket never received a posted event");

    let scratch = support::Scratch::new("mm-typing");
    let chan = build(&r, &r.token, scratch.path());
    let _ = chan.poll(&seagent_core::Cancel::new());

    // Retry: the bot's own socket may still be authenticating.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut typed = false;
    let mut last = Instant::now();
    while Instant::now() < deadline && !typed {
        if last.elapsed() > Duration::from_secs(2) {
            chan.typing(&r.channel, None).expect("typing over ws");
            last = Instant::now();
        }
        match ws.recv() {
            Ok(Some(Message::Text(t))) => {
                let v: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
                if v["event"] == "typing" && v["data"]["user_id"].as_str() == Some(r.bot.as_str()) {
                    typed = true;
                }
            }
            Ok(_) => {}
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    assert!(typed, "no typing event for the bot reached the peer in 15 s");
}

/// Error mapping: a rejected token is an auth error and a missing channel is
/// `NotFound`, both without retrying for seconds.
#[test]
fn maps_auth_and_missing_channel_errors_on_real_mattermost() {
    let Some(r) = real() else {
        support::skipped("mattermost errors", "SEAGENT_REAL_MATTERMOST_URL");
        return;
    };
    let scratch = support::Scratch::new("mm-err");
    let bad = build(&r, "0000000000000000000000000x", scratch.path());
    let start = Instant::now();
    let mut auth = None;
    while start.elapsed() < Duration::from_secs(15) {
        if let Err(e) = bad.poll(&seagent_core::Cancel::new()) {
            auth = Some(e);
            break;
        }
    }
    let e = auth.expect("an invalid token must fail, not poll forever");
    assert_eq!(e.kind, ChannelErrorKind::Auth, "invalid token: {e}");
    assert!(start.elapsed() < Duration::from_secs(10), "auth error took {:?}", start.elapsed());

    // A channel that does not exist: NotFound, immediate (a retry storm would
    // take retry_base * (1+2+4+8) ≈ 7.5 s).
    let chan = build(&r, &r.token, scratch.path());
    let missing = "00000000000000000000000001";
    let start = Instant::now();
    let e = match chan.send(&Outbound::text(missing, "to nowhere")) {
        Err(e) => e,
        Ok(s) => panic!("sending to a missing channel succeeded: {s:?}"),
    };
    assert_eq!(e.kind, ChannelErrorKind::NotFound, "missing channel: {e}");
    assert!(start.elapsed() < Duration::from_secs(3), "not retried: took {:?} ({e})", start.elapsed());
}

