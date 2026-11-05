//! Real IRC server (ngircd 27) integration test.
//!
//! Opt in with `ARK_REAL_IRC_ADDR=127.0.0.1:<port>` (see `tests/real/run.sh`);
//! without it the test is skipped. The server is started by the operator, never
//! by this test.

mod support;

use ark_channel::irc::{Cfg, Irc};
use ark_channel::{Channel, Outbound};
use std::time::Duration;

fn server() -> Option<(String, u16)> {
    support::addr("ARK_REAL_IRC_ADDR")
}

fn cfg(host: &str, port: u16, nick: &str) -> Cfg {
    let mut c = Cfg::new(host, port, false, nick);
    c.channels = vec![("#ark".to_string(), None)];
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
        support::skipped("irc registration", "ARK_REAL_IRC_ADDR");
        return;
    };
    let irc = Irc::start("real-irc", cfg(&host, port, "arkbot"), 2).expect("start");
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
    waiter.send("JOIN #ark").unwrap();
    let who = waiter.until(Duration::from_secs(5), |l| l.contains(" 353 ") && l.contains("arkbot")).is_some();
    assert!(who, "arkbot never showed up in #ark; seen: {:?}", waiter.seen);
    assert_eq!(irc.current_nick(), "arkbot");
}

/// Inbound: a channel PRIVMSG from another user becomes one `Inbound`.
#[test]
fn receives_channel_message_from_real_ircd() {
    let Some((host, port)) = server() else {
        support::skipped("irc inbound", "ARK_REAL_IRC_ADDR");
        return;
    };
    let irc = Irc::start("real-irc-in", cfg(&host, port, "arkin"), 2).expect("start");
    let mut peer = support::LineClient::connect(&host, port).expect("peer connect");
    peer.send("NICK alice").unwrap();
    peer.send("USER alice 0 * :alice").unwrap();
    assert!(peer.until(Duration::from_secs(10), |l| l.contains(" 001 ")).is_some(), "peer not registered");
    peer.send("JOIN #ark").unwrap();
    assert!(peer.until(Duration::from_secs(10), |l| l.contains(" 366 ")).is_some(), "peer join not acknowledged");
    // Give ark's client time to finish its own JOIN before the message.
    assert!(
        peer.until(Duration::from_secs(10), |l| l.contains("arkin") && l.contains(" JOIN ")).is_some(),
        "arkin never joined; seen: {:?}",
        peer.seen
    );
    peer.send("PRIVMSG #ark :hello from a real ircd").unwrap();

    let got = support::poll_until(&irc, Duration::from_secs(10), |all| all.iter().any(|m| m.text == "hello from a real ircd"));
    let m = got.iter().find(|m| m.text == "hello from a real ircd").unwrap_or_else(|| panic!("no message; got {got:?}"));
    assert_eq!(m.channel, "real-irc-in");
    assert_eq!(m.sender, "alice");
    assert_eq!(m.chat, "#ark");
    assert_eq!(m.sender_name, "alice");
    assert!(m.message_id.len() > 8, "msgid: {:?}", m.message_id);
    assert!(!m.is_bot);
}

/// Outbound: our line reaches the real server and is delivered to a peer.
#[test]
fn sends_to_real_ircd() {
    let Some((host, port)) = server() else {
        support::skipped("irc outbound", "ARK_REAL_IRC_ADDR");
        return;
    };
    let irc = Irc::start("real-irc-out", cfg(&host, port, "arksend"), 2).expect("start");
    let mut peer = support::LineClient::connect(&host, port).expect("peer connect");
    peer.send("NICK bob").unwrap();
    peer.send("USER bob 0 * :bob").unwrap();
    assert!(peer.until(Duration::from_secs(10), |l| l.contains(" 001 ")).is_some());
    peer.send("JOIN #ark").unwrap();
    assert!(peer.until(Duration::from_secs(10), |l| l.contains(" 366 ")).is_some());
    assert!(
        peer.until(Duration::from_secs(10), |l| l.contains("arksend") && l.contains(" JOIN ")).is_some(),
        "arksend never joined; seen: {:?}",
        peer.seen
    );

    let sent = irc.send(&Outbound::text("#ark", "ark says hi")).expect("send");
    assert_eq!(sent.ids.len(), 1, "{sent:?}");
    let line = peer.privmsg("arksend", "#ark", Duration::from_secs(10)).unwrap_or_else(|| panic!("peer saw no PRIVMSG; seen {:?}", peer.seen));
    assert!(line.contains("ark says hi"), "{line}");
}

/// A direct message to the bot is a Direct chat and reaches us.
#[test]
fn receives_direct_message_from_real_ircd() {
    let Some((host, port)) = server() else {
        support::skipped("irc dm", "ARK_REAL_IRC_ADDR");
        return;
    };
    let irc = Irc::start("real-irc-dm", cfg(&host, port, "arksdm"), 2).expect("start");
    let mut peer = support::LineClient::connect(&host, port).expect("peer connect");
    peer.send("NICK carol").unwrap();
    peer.send("USER carol 0 * :carol").unwrap();
    assert!(peer.until(Duration::from_secs(10), |l| l.contains(" 001 ")).is_some());
    // Wait until ark is registered so the DM is not dropped as unknown-nick;
    // a 401 from the server would tell us the nick never appeared.
    let end = std::time::Instant::now() + Duration::from_secs(12);
    let mut ok = false;
    while std::time::Instant::now() < end && !ok {
        peer.send("PRIVMSG arksdm :ping dm").unwrap();
        ok = support::poll_until(&irc, Duration::from_secs(1), |all| all.iter().any(|m| m.text == "ping dm")).iter().any(|m| m.text == "ping dm");
        if peer.until(Duration::from_millis(300), |l| l.contains(" 401 ")).is_some() {
            eprintln!("server rejected the DM: {:?}", peer.seen.last());
        }
    }
    assert!(ok, "no DM received; peer saw {:?}", peer.seen);
}
