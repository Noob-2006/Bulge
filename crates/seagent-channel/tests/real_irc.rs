//! Real IRC server (ngircd 27) integration test.
//!
//! Opt in with `SEAGENT_REAL_IRC_ADDR=127.0.0.1:<port>` (see `tests/real/run.sh`);
//! without it the test is skipped. The server is started by the operator, never
//! by this test.

mod support;

use seagent_channel::irc::{Cfg, Irc};
use seagent_channel::{Channel, Outbound};
use std::time::Duration;

fn server() -> Option<(String, u16)> {
    support::addr("SEAGENT_REAL_IRC_ADDR")
}

fn cfg(host: &str, port: u16, nick: &str) -> Cfg {
    let mut c = Cfg::new(host, port, false, nick);
    c.channels = vec![("#seagent".to_string(), None)];
    c.flood_interval = Duration::from_millis(20);
    c.connect_timeout = Duration::from_secs(10);
    c.send_wait = Duration::from_secs(15);
    c.echo_wait = Duration::from_secs(3);
    c
}

/// Registration against a real server: we get a 001 and the JOIN is acknowledged.
#[test]
fn registers_and_joins_on_real_ircd() {
    let Some((host, port)) = server() else {
        support::skipped("irc registration", "SEAGENT_REAL_IRC_ADDR");
        return;
    };
    let irc = Irc::start("real-irc", cfg(&host, port, "seagentbot"), 2).expect("start");
    // A poll that returns empty only means "nothing yet"; a fatal (bad nick,
    // refused connection) surfaces as Err.
    let got = support::poll_until(&irc, Duration::from_secs(5), |_| false);
    assert!(got.is_empty(), "no messages expected yet: {got:?}");

    // The nick the server settled on must be the one we asked for.
    let mut waiter = support::LineClient::connect(&host, port).expect("peer connect");
    waiter.send("NICK dirwatch").unwrap();
    waiter.send("USER dirwatch 0 * :dirwatch").unwrap();
    let end = std::time::Instant::now() + Duration::from_secs(10);
    let mut saw = false;
    while std::time::Instant::now() < end && !saw {
        saw = waiter.until(Duration::from_secs(1), |l| l.contains(" 366 ")).is_some();
    }
    waiter.send("JOIN #seagent").unwrap();
    let who = waiter.until(Duration::from_secs(5), |l| l.contains(" 353 ") && l.contains("seagentbot")).is_some();
    assert!(who, "seagentbot never showed up in #seagent; seen: {:?}", waiter.seen);
    assert_eq!(irc.current_nick(), "seagentbot");
}

/// Inbound: a channel PRIVMSG from another user becomes one `Inbound`.
#[test]
fn receives_channel_message_from_real_ircd() {
    let Some((host, port)) = server() else {
        support::skipped("irc inbound", "SEAGENT_REAL_IRC_ADDR");
        return;
    };
    let irc = Irc::start("real-irc-in", cfg(&host, port, "seagentin"), 2).expect("start");
    let mut peer = support::LineClient::connect(&host, port).expect("peer connect");
    peer.send("NICK alice").unwrap();
    peer.send("USER alice 0 * :alice").unwrap();
    assert!(peer.until(Duration::from_secs(10), |l| l.contains(" 001 ")).is_some(), "peer not registered");
    peer.send("JOIN #seagent").unwrap();
    assert!(peer.until(Duration::from_secs(10), |l| l.contains(" 366 ")).is_some(), "peer join not acknowledged");
    // Give seagent's client time to finish its own JOIN before the message.
    assert!(
        peer.until(Duration::from_secs(10), |l| l.contains("seagentin") && l.contains(" JOIN ")).is_some(),
        "seagentin never joined; seen: {:?}",
        peer.seen
    );
    peer.send("PRIVMSG #seagent :hello from a real ircd").unwrap();

    let got = support::poll_until(&irc, Duration::from_secs(10), |all| all.iter().any(|m| m.text == "hello from a real ircd"));
    let m = got.iter().find(|m| m.text == "hello from a real ircd").unwrap_or_else(|| panic!("no message; got {got:?}"));
    assert_eq!(m.channel, "real-irc-in");
    assert_eq!(m.sender, "alice");
    assert_eq!(m.chat, "#seagent");
    assert_eq!(m.sender_name, "alice");
    assert!(m.message_id.len() > 8, "msgid: {:?}", m.message_id);
    assert!(!m.is_bot);
}

/// Outbound: our line reaches the real server and is delivered to a peer.
#[test]
fn sends_to_real_ircd() {
    let Some((host, port)) = server() else {
        support::skipped("irc outbound", "SEAGENT_REAL_IRC_ADDR");
        return;
    };
    let irc = Irc::start("real-irc-out", cfg(&host, port, "seagentsend"), 2).expect("start");
    let mut peer = support::LineClient::connect(&host, port).expect("peer connect");
    peer.send("NICK bob").unwrap();
    peer.send("USER bob 0 * :bob").unwrap();
    assert!(peer.until(Duration::from_secs(10), |l| l.contains(" 001 ")).is_some());
    peer.send("JOIN #seagent").unwrap();
    assert!(peer.until(Duration::from_secs(10), |l| l.contains(" 366 ")).is_some());
    assert!(
        peer.until(Duration::from_secs(10), |l| l.contains("seagentsend") && l.contains(" JOIN ")).is_some(),
        "seagentsend never joined; seen: {:?}",
        peer.seen
    );

    let sent = irc.send(&Outbound::text("#seagent", "seagent says hi")).expect("send");
    assert_eq!(sent.ids.len(), 1, "{sent:?}");
    let line = peer.privmsg("seagentsend", "#seagent", Duration::from_secs(10)).unwrap_or_else(|| panic!("peer saw no PRIVMSG; seen {:?}", peer.seen));
    assert!(line.contains("seagent says hi"), "{line}");
}

/// A direct message to the bot is a Direct chat and reaches us.
#[test]
fn receives_direct_message_from_real_ircd() {
    let Some((host, port)) = server() else {
        support::skipped("irc dm", "SEAGENT_REAL_IRC_ADDR");
        return;
    };
    let irc = Irc::start("real-irc-dm", cfg(&host, port, "seagentsdm"), 2).expect("start");
    let mut peer = support::LineClient::connect(&host, port).expect("peer connect");
    peer.send("NICK carol").unwrap();
    peer.send("USER carol 0 * :carol").unwrap();
    assert!(peer.until(Duration::from_secs(10), |l| l.contains(" 001 ")).is_some());
    // Wait until seagent is registered so the DM is not dropped as unknown-nick;
    // a 401 from the server would tell us the nick never appeared.
    let end = std::time::Instant::now() + Duration::from_secs(12);
    let mut ok = false;
    while std::time::Instant::now() < end && !ok {
        peer.send("PRIVMSG seagentsdm :ping dm").unwrap();
        ok = support::poll_until(&irc, Duration::from_secs(1), |all| all.iter().any(|m| m.text == "ping dm")).iter().any(|m| m.text == "ping dm");
        if peer.until(Duration::from_millis(300), |l| l.contains(" 401 ")).is_some() {
            eprintln!("server rejected the DM: {:?}", peer.seen.last());
        }
    }
    assert!(ok, "no DM received; peer saw {:?}", peer.seen);
}
