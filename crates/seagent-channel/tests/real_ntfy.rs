//! Real ntfy server integration test (podman `binwiederhier/ntfy`, see `tests/real/run.sh`).
//!
//! Opt in with `SEAGENT_REAL_NTFY_URL=http://127.0.0.1:<port>`; skipped otherwise.
//! The channel is built through the real `[channels.*]` config path, so this
//! also proves the wiring, not just the struct.

mod support;

use seagent_channel::http::{self, Http, Payload};
use seagent_channel::{config, Channel, ChatType, Outbound, TextFormat};
use std::time::Duration;

fn server() -> Option<String> {
    std::env::var("SEAGENT_REAL_NTFY_URL").ok().map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| !s.is_empty())
}

fn build(server: &str, topic: &str, state: &std::path::Path) -> std::sync::Arc<dyn Channel> {
    let v = serde_json::json!({
        "kind": "ntfy",
        "server": server,
        "topic": topic,
        "title": "seagent e2e",
        "priority": "high",
        "markdown": true,
        "poll_timeout_secs": 5,
    });
    let cfg = config::parse_config("ntfy-real", &v).expect("parse");
    let secrets: config::Secrets = std::sync::Arc::new(|s: &str| s.to_string());
    config::build("ntfy-real", &cfg, state, &secrets).expect("build")
}

/// Post as a human would (the test's own HTTP client, not the code under test).
fn publish(server: &str, topic: &str, body: &str, tags: &str) -> String {
    let resp = Http::new(Duration::from_secs(10))
        .call("POST", &format!("{server}/{topic}"), &[("x-tags", tags)], Payload::Raw("text/plain; charset=utf-8", body.as_bytes()))
        .expect("publish");
    assert_eq!(resp.status, 200, "publish failed: {} {}", resp.status, resp.body);
    let v: serde_json::Value = serde_json::from_str(&resp.body).expect("json");
    v["id"].as_str().expect("id").to_string()
}

/// A human posts on the topic; seagent's poll returns it with the sender/topic contract.
#[test]
fn receives_message_published_by_a_real_ntfy_server() {
    let Some(server) = server() else {
        support::skipped("ntfy inbound", "SEAGENT_REAL_NTFY_URL");
        return;
    };
    let scratch = support::Scratch::new("ntfy-in");
    let topic = format!("seagent-e2e-in-{}", std::process::id());
    let chan = build(&server, &topic, scratch.path());

    let msg = "hello from a real ntfy server";
    let id = publish(&server, &topic, msg, "human");

    let got = support::poll_until(chan.as_ref(), Duration::from_secs(15), |all| all.iter().any(|m| m.text == msg));
    let m = got.iter().find(|m| m.text == msg).unwrap_or_else(|| panic!("not delivered: {got:?}"));
    assert_eq!(m.sender, topic, "ntfy has no user identity: the topic is the sender");
    assert_eq!(m.chat, topic);
    assert_eq!(m.chat_type, ChatType::Direct);
    assert_eq!(m.message_id, id, "the ntfy event id is the message id");
}

/// Sending publishes through the real server and does not loop back to us.
#[test]
fn sends_and_does_not_echo_through_a_real_ntfy_server() {
    let Some(server) = server() else {
        support::skipped("ntfy outbound", "SEAGENT_REAL_NTFY_URL");
        return;
    };
    let scratch = support::Scratch::new("ntfy-out");
    let topic = format!("seagent-e2e-out-{}", std::process::id());
    let chan = build(&server, &topic, scratch.path());

    let mut out = Outbound::text(&topic, "**seagent** says hi");
    out.format = TextFormat::Markdown;
    let sent = chan.send(&out).expect("send");
    assert_eq!(sent.ids.len(), 1, "{sent:?}");

    // What the real server stored: our echo tag, the title/priority headers and
    // the id we returned are the server's.
    let url = format!("{server}/{topic}/json?poll=1&since=all");
    let text = String::from_utf8(http::get_bytes(&url, &[], 1 << 20).expect("poll")).expect("utf8");
    let ev: serde_json::Value = text.lines().find(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).expect("event")).expect("one event");
    assert_eq!(ev["message"].as_str(), Some("**seagent** says hi"));
    assert_eq!(ev["title"].as_str(), Some("seagent e2e"));
    assert_eq!(ev["priority"].as_i64(), Some(4), "high maps to 4: {ev}");
    assert_eq!(ev["content_type"].as_str(), Some("text/markdown"), "markdown setting turns on X-Markdown: {ev}");
    assert!(ev["tags"].as_array().is_some_and(|t| t.iter().any(|t| t.as_str() == Some(seagent_channel::ntfy::ECHO_TAG))), "echo tag missing: {ev}");
    assert_eq!(sent.ids.first().map(String::as_str), ev["id"].as_str());

    // The echo must not come back as an inbound message.
    let got = support::poll_until(chan.as_ref(), Duration::from_secs(4), |_| false);
    assert!(got.is_empty(), "own message echoed back: {got:?}");
}

/// The persisted resume id skips what was already delivered after a restart.
#[test]
fn resumes_from_the_persisted_id_on_a_real_ntfy_server() {
    let Some(server) = server() else {
        support::skipped("ntfy resume", "SEAGENT_REAL_NTFY_URL");
        return;
    };
    let scratch = support::Scratch::new("ntfy-resume");
    let topic = format!("seagent-e2e-resume-{}", std::process::id());
    {
        let chan = build(&server, &topic, scratch.path());
        publish(&server, &topic, "first", "human");
        let got = support::poll_until(chan.as_ref(), Duration::from_secs(15), |all| all.iter().any(|m| m.text == "first"));
        assert!(got.iter().any(|m| m.text == "first"), "first not delivered: {got:?}");
        // The resume id is committed on the next poll (documented at-least-once):
        // one more poll, which returns empty, persists it.
        let _ = chan.poll(&seagent_core::Cancel::new()).expect("poll");
        // Dropping closes the stream and commits the resume id.
    }
    assert!(scratch.file("ntfy-real.ntfy.json").exists(), "state file missing under {}", scratch.path().display());
    publish(&server, &topic, "second", "human");
    let chan = build(&server, &topic, scratch.path());
    let got = support::poll_until(chan.as_ref(), Duration::from_secs(15), |all| all.iter().any(|m| m.text == "second"));
    assert!(got.iter().any(|m| m.text == "second"), "second not delivered: {got:?}");
    assert!(!got.iter().any(|m| m.text == "first"), "replayed an already-delivered message: {got:?}");
}
