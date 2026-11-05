//! Real SMTP+IMAP server integration test (GreenMail standalone, see `tests/real/run.sh`).
//!
//! Opt in with
//! `SEAGENT_REAL_IMAP=127.0.0.1:3143 SEAGENT_REAL_SMTP=127.0.0.1:3025`
//! plus `SEAGENT_REAL_MAIL_USER` / `SEAGENT_REAL_MAIL_PASS` (the GreenMail login) and
//! optionally `SEAGENT_REAL_MAIL_ADDR` (the mailbox address, default `<user>@localhost`).
//! Without them the tests are skipped. The server is started by the operator.

mod support;

use seagent_channel::{config, Channel, Outbound};
use std::time::Duration;

struct Real {
    imap: (String, u16),
    smtp: (String, u16),
    /// IMAP/SMTP login name (GreenMail's `login:password@domain` user).
    user: String,
    pass: String,
    /// The mailbox address (`login@domain`).
    addr: String,
}

fn real() -> Option<Real> {
    Some(Real {
        imap: support::addr("SEAGENT_REAL_IMAP")?,
        smtp: support::addr("SEAGENT_REAL_SMTP")?,
        user: std::env::var("SEAGENT_REAL_MAIL_USER").ok()?,
        pass: std::env::var("SEAGENT_REAL_MAIL_PASS").ok()?,
        addr: std::env::var("SEAGENT_REAL_MAIL_ADDR").unwrap_or_else(|_| format!("{}@localhost", std::env::var("SEAGENT_REAL_MAIL_USER").unwrap_or_default())),
    })
}

/// The channel through the real config path: plain IMAP/SMTP against the test server.
fn build(r: &Real, state: &std::path::Path, authenticated_only: bool) -> std::sync::Arc<dyn Channel> {
    let v = serde_json::json!({
        "kind": "email",
        "address": r.addr,
        "username": r.user,
        "password": r.pass,
        "imap_host": r.imap.0,
        "imap_port": r.imap.1,
        "imap_security": "plain",
        "smtp_host": r.smtp.0,
        "smtp_port": r.smtp.1,
        "smtp_security": "plain",
        "require_authenticated_sender": authenticated_only,
        "idle": false,
        "poll_interval_secs": 1,
        "poll_timeout_secs": 5,
        "strip_quotes": true,
        // The operator's default ignores mail that was already there; this test
        // delivers first, so it must not be skipped as "existing".
        "skip_existing": false,
    });
    let cfg = config::parse_config("mail-real", &v).expect("parse");
    let secrets: config::Secrets = std::sync::Arc::new(|s: &str| s.to_string());
    config::build("mail-real", &cfg, state, &secrets).expect("build")
}

/// Deliver a message the way an MTA would (the test's own SMTP client).
fn deliver(r: &Real, from: &str, subject: &str, body: &str) {
    use std::io::{BufRead, BufReader, Write};
    fn read(rd: &mut BufReader<std::net::TcpStream>) -> String {
        let mut l = String::new();
        rd.read_line(&mut l).expect("read");
        l.trim_end().to_string()
    }
    fn send(w: &mut std::net::TcpStream, c: &str) {
        w.write_all(format!("{c}\r\n").as_bytes()).unwrap();
        w.flush().unwrap();
    }
    let s = std::net::TcpStream::connect(&r.smtp).expect("smtp connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut w = s.try_clone().unwrap();
    let mut rd = BufReader::new(s);
    let greeting = read(&mut rd);
    assert!(greeting.starts_with("220"), "greeting: {greeting:?}");
    send(&mut w, "EHLO test.local");
    loop {
        let l = read(&mut rd);
        assert!(l.starts_with("250"), "EHLO: {l:?}");
        if l.starts_with("250 ") {
            break;
        }
    }
    send(&mut w, &format!("MAIL FROM:<{from}>"));
    let l = read(&mut rd);
    assert!(l.starts_with("250"), "MAIL FROM: {l:?}");
    send(&mut w, &format!("RCPT TO:<{}>", r.addr));
    let l = read(&mut rd);
    assert!(l.starts_with("250"), "RCPT TO: {l:?}");
    send(&mut w, "DATA");
    let l = read(&mut rd);
    assert!(l.starts_with("354"), "DATA: {l:?}");
    let msg = format!(
        "From: Alice <{from}>\r\nTo: <{}>\r\nSubject: {subject}\r\nDate: Wed, 4 Nov 2026 12:00:00 +0000\r\nMessage-ID: <{}@test.local>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n.\r\n",
        r.addr,
        std::process::id(),
    );
    w.write_all(msg.as_bytes()).unwrap();
    w.flush().unwrap();
    let l = read(&mut rd);
    assert!(l.starts_with("250"), "end of DATA: {l:?}");
    send(&mut w, "QUIT");
}

/// Inbound: a real SMTP delivery is picked up over real IMAP.
#[test]
fn receives_delivered_mail_over_real_imap() {
    let Some(r) = real() else {
        support::skipped("email inbound", "SEAGENT_REAL_IMAP/SEAGENT_REAL_SMTP");
        return;
    };
    let scratch = support::Scratch::new("mail-in");
    let chan = build(&r, scratch.path(), false);
    let body = "hello over a real imap server\n\n> quoted reply\n> should be stripped\n";
    deliver(&r, "alice@example.test", "greetings from smtp", body);

    let got = support::poll_until(chan.as_ref(), Duration::from_secs(30), |all| all.iter().any(|m| m.sender == "alice@example.test"));
    let m = got.iter().find(|m| m.sender == "alice@example.test").unwrap_or_else(|| panic!("no mail; got {got:?}"));
    // The subject leads the text (Hermes does the same) and the quoted reply is stripped.
    assert!(m.text.starts_with("[Subject: greetings from smtp]"), "subject prefix: {:?}", m.text);
    assert!(m.text.contains("hello over a real imap server"), "body: {:?}", m.text);
    assert!(!m.text.contains("quoted reply"), "quoted reply must be stripped: {:?}", m.text);
    assert_eq!(m.chat, "alice@example.test");
    assert_eq!(m.chat_type, seagent_channel::ChatType::Direct);
    assert!(m.message_id.contains("@test.local"), "message id from Message-ID: {:?}", m.message_id);
    assert!(!m.is_bot, "human sender");
}

/// Outbound: our message is accepted by the real SMTP server (GreenMail stores it).
#[test]
fn sends_through_real_smtp() {
    let Some(r) = real() else {
        support::skipped("email outbound", "SEAGENT_REAL_IMAP/SEAGENT_REAL_SMTP");
        return;
    };
    let scratch = support::Scratch::new("mail-out");
    let chan = build(&r, scratch.path(), false);
    let mut out = Outbound::text(&r.addr, "reply body from seagent");
    out.thread = None;
    let sent = chan.send(&out).expect("send over real smtp");
    assert_eq!(sent.ids.len(), 1, "{sent:?}");
    let id = sent.ids.first().unwrap().clone();
    assert!(id.contains('@'), "the SMTP Message-ID is returned: {id:?}");
    // The server accepted it: GreenMail's IMAP API lists it for that user.
    let api = std::env::var("SEAGENT_REAL_MAIL_API").ok();
    if let Some(api) = api {
        let url = format!("{api}/api/user/{}/messages", r.addr);
        let body = String::from_utf8(seagent_channel::http::get_bytes(&url, &[], 1 << 20).expect("greenmail api")).expect("utf8");
        assert!(body.contains("reply body from seagent"), "message not stored by the server: {body}");
    }
}
