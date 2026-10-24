//! Relay + host channel + device, all over real TCP on loopback.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use bulge_channel_api::Channel;
use bulge_remote::device;
use bulge_remote::channel::{RemoteChannel, Timing};
use bulge_remote::host;
use bulge_remote::noise::{Keypair, generate_keypair};
use bulge_remote::relay::{Relay, RelayConfig};
use bulge_remote::wire::{Control, Wire, recv_control, send_control};
use bulge_remote::{hex, tunnel};
use tokio::net::TcpListener;
use tokio::time::timeout;

fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bulge-remote-e2e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn timing() -> Timing {
    Timing { ping: Duration::from_millis(500), idle: Duration::from_secs(10), step: Duration::from_secs(5) }
}

const STEP: Duration = Duration::from_secs(5);

/// Start a relay; returns its address and the key clients pin.
async fn start_relay(allow: HashSet<String>) -> (String, String) {
    let keys: Keypair = generate_keypair().unwrap();
    let key = hex(&keys.public);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let udp = tokio::net::UdpSocket::bind(&addr).await.unwrap();
    let relay = Relay::new(RelayConfig { allow_hosts: Some(allow), ..RelayConfig::default() }, keys);
    tokio::spawn(relay.serve(listener));
    tokio::spawn(bulge_remote::relay::serve_stun(udp));
    (addr, key)
}

/// Poll the host channel until a message arrives.
async fn next_inbound(channel: &RemoteChannel) -> bulge_channel_api::Inbound {
    for _ in 0..20 {
        let batch = channel.poll().await.unwrap();
        if let Some(first) = batch.into_iter().next() {
            return first;
        }
    }
    panic!("no message arrived");
}

async fn next_wire(session: &mut device::Session) -> Wire {
    timeout(Duration::from_secs(10), session.next()).await.expect("timed out").unwrap().expect("closed")
}

#[tokio::test(flavor = "multi_thread")]
async fn pair_chat_refuse_revoke_and_deliver_offline_replies() {
    let host_dir = temp("host");
    let device_dir = temp("device");

    // The relay must be told which host to serve, so learn the id first.
    let placeholder = host::init(&host_dir, "127.0.0.1:1", &"00".repeat(32)).unwrap();
    let (relay, relay_key) = start_relay(HashSet::from([placeholder.id()])).await;
    let identity = host::init(&host_dir, &relay, &relay_key).unwrap();
    assert_eq!(identity.id(), placeholder.id(), "re-init keeps the keys");
    let channel = RemoteChannel::start("main", &host_dir, timing()).unwrap();
    assert!(channel.authenticates_senders());

    // Wait for the host to come online, then pair.
    let link = host::new_pairing(&host_dir, bulge_remote::now_secs()).unwrap();
    let mut joined = None;
    for _ in 0..50 {
        match device::join(&device_dir, &link, "home", "laptop").await {
            Ok(known) => {
                joined = Some(known);
                break;
            }
            Err(error) if error.to_string().contains("not online") => tokio::time::sleep(Duration::from_millis(100)).await,
            Err(error) => panic!("join failed: {error}"),
        }
    }
    let known = joined.expect("host never came online");
    assert_eq!(known.device_name, "laptop");
    assert_eq!(host::devices(&host_dir).unwrap().len(), 1);

    // The link is single use.
    let again = device::join(&temp("device2"), &link, "home", "thief").await.unwrap_err();
    assert!(matches!(again, bulge_remote::Failure::Silent(_)), "{again}");
    assert_eq!(host::devices(&host_dir).unwrap().len(), 1);

    // Chat both ways.
    let mut session = device::connect(&device_dir, &known).await.unwrap();
    session.send(&Wire::Msg { id: 1, text: "列出工作區".into() }).await.unwrap();
    let inbound = next_inbound(&channel).await;
    assert_eq!(inbound.text, "列出工作區");
    assert_eq!(inbound.sender_name, "laptop");
    assert_eq!(inbound.channel, "remote:main");
    assert_eq!(next_wire(&mut session).await, Wire::Received { id: 1 }, "the host confirms what it took");
    // A re-send of the same number (after a reconnect) is confirmed but not run twice.
    session.send(&Wire::Msg { id: 1, text: "列出工作區".into() }).await.unwrap();
    assert_eq!(next_wire(&mut session).await, Wire::Received { id: 1 });
    assert!(timeout(Duration::from_millis(300), channel.poll()).await.map_or(true, |batch| batch.unwrap().is_empty()), "no duplicate");
    channel.typing(&inbound.chat_id).await;
    assert_eq!(next_wire(&mut session).await, Wire::Typing);
    channel.send(&inbound.chat_id, "好了").await.unwrap();
    assert!(matches!(next_wire(&mut session).await, Wire::Reply { text, .. } if text == "好了"));
    session.send(&Wire::Ping).await.unwrap();
    assert_eq!(next_wire(&mut session).await, Wire::Pong);

    // Replies for an offline device wait for it; acknowledged ones are not
    // sent again, and a repeat is not shown twice.
    let seen = session.seen();
    drop(session);
    tokio::time::sleep(Duration::from_millis(300)).await;
    channel.send(&inbound.chat_id, "你離線時完成的結果").await.unwrap();
    let mut session = device::connect(&device_dir, &known).await.unwrap();
    session.resume_after(seen);
    assert!(matches!(next_wire(&mut session).await, Wire::Reply { text, .. } if text == "你離線時完成的結果"));
    // Unacknowledged replies survive a reconnect; acknowledged ones do not
    // come back. The first reply was read (and acked) above.
    let seen = session.seen();
    tokio::time::sleep(Duration::from_millis(300)).await;
    channel.send(&inbound.chat_id, "第二則").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    drop(session); // without reading it
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut session = device::connect(&device_dir, &known).await.unwrap();
    session.resume_after(seen);
    assert!(matches!(next_wire(&mut session).await, Wire::Reply { text, .. } if text == "第二則"));
    assert!(timeout(Duration::from_millis(500), session.next()).await.is_err(), "nothing else is re-sent");

    // A relay that is down (connection refused) is a reason to retry, not
    // to give up — unlike a relay with the wrong key.
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
    let mut offline = known.clone();
    offline.relay = dead;
    let failure = device::connect(&device_dir, &offline).await.err().expect("relay is down");
    assert!(matches!(failure, bulge_remote::Failure::Transient(_)), "{failure:?}");

    // Key two: the right device key with the wrong PSK is refused.
    let hosts_file = device_dir.join("hosts.json");
    let original = std::fs::read_to_string(&hosts_file).unwrap();
    let mut tampered: serde_json::Value = serde_json::from_str(&original).unwrap();
    tampered["hosts"][0]["psk"] = serde_json::Value::String("00".repeat(32));
    std::fs::write(&hosts_file, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let hosts = device::hosts(&device_dir).unwrap();
    assert!(device::connect(&device_dir, &hosts[0]).await.is_err());
    std::fs::write(&hosts_file, &original).unwrap();

    // Key one: a device that was never paired (same PSK, different key) is refused.
    let stranger_dir = temp("stranger");
    std::fs::create_dir_all(&stranger_dir).unwrap();
    assert!(device::connect(&stranger_dir, &known).await.is_err());

    // Revoking cuts a live session off at its next message.
    assert!(host::revoke(&host_dir, "laptop").unwrap());
    session.send(&Wire::Msg { id: 3, text: "還在嗎".into() }).await.unwrap();
    assert!(matches!(next_wire(&mut session).await, Wire::Error { .. }));
    assert!(device::connect(&device_dir, &known).await.is_err(), "and it cannot reconnect");

    for dir in [host_dir, device_dir, stranger_dir, temp("device2")] {
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[tokio::test]
async fn the_relay_serves_only_allowed_hosts_with_a_valid_proof() {
    let host_dir = temp("proof");
    let identity = host::init(&host_dir, "127.0.0.1:1", &"00".repeat(32)).unwrap();
    let (relay, relay_key) = start_relay(HashSet::from([identity.id()])).await;
    let pin = bulge_remote::unhex::<32>(&relay_key).unwrap();

    // A client pinned to some other relay key never gets in.
    assert!(tunnel::connect(&relay, &generate_keypair().unwrap().public, STEP).await.is_err());

    // A host id the relay was not told about.
    let mut link = tunnel::connect(&relay, &pin, STEP).await.unwrap();
    send_control(&link, &Control::Host { id: "11".repeat(32) }).await.unwrap();
    assert!(matches!(recv_control(&mut link, STEP).await.unwrap(), Control::Error { .. }));

    // The right id without its private key: the proof fails.
    let mut link = tunnel::connect(&relay, &pin, STEP).await.unwrap();
    send_control(&link, &Control::Host { id: identity.id() }).await.unwrap();
    assert!(matches!(recv_control(&mut link, STEP).await.unwrap(), Control::Challenge { .. }));
    send_control(&link, &Control::Proof { sig: "22".repeat(64) }).await.unwrap();
    assert!(matches!(recv_control(&mut link, STEP).await.unwrap(), Control::Error { .. }));

    // Dialing an offline host, and accepting a session nobody asked for.
    let mut link = tunnel::connect(&relay, &pin, STEP).await.unwrap();
    send_control(&link, &Control::Dial { id: identity.id() }).await.unwrap();
    assert!(matches!(recv_control(&mut link, STEP).await.unwrap(), Control::Error { .. }));
    let mut link = tunnel::connect(&relay, &pin, STEP).await.unwrap();
    send_control(&link, &Control::Accept { sid: "33".repeat(16) }).await.unwrap();
    assert!(matches!(recv_control(&mut link, STEP).await.unwrap(), Control::Error { .. }));
    let _ = std::fs::remove_dir_all(host_dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_conversation_moves_to_a_direct_path_and_keeps_working() {
    use bulge_remote::conversation::{self, Event};
    let host_dir = temp("direct-host");
    let device_dir = temp("direct-device");
    let placeholder = host::init(&host_dir, "127.0.0.1:1", &"00".repeat(32)).unwrap();
    let (relay, relay_key) = start_relay(HashSet::from([placeholder.id()])).await;
    host::init(&host_dir, &relay, &relay_key).unwrap();
    let channel = RemoteChannel::start("main", &host_dir, timing()).unwrap();
    let link = host::new_pairing(&host_dir, bulge_remote::now_secs()).unwrap();
    let mut known = None;
    for _ in 0..50 {
        match device::join(&device_dir, &link, "home", "phone").await {
            Ok(k) => {
                known = Some(k);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let known = known.expect("paired");

    let mut chat = conversation::start(device_dir.clone(), known);
    let next = async |chat: &mut conversation::Conversation| timeout(Duration::from_secs(10), chat.events.recv()).await.expect("event").expect("open");
    assert_eq!(next(&mut chat).await, Event::Connected { direct: false });
    assert_eq!(next(&mut chat).await, Event::Connected { direct: true }, "hole punching on loopback succeeds");

    chat.send.send("走直連了嗎".into()).unwrap();
    let inbound = next_inbound(&channel).await;
    assert_eq!(inbound.text, "走直連了嗎");
    channel.send(&inbound.chat_id, "是的").await.unwrap();
    assert_eq!(next(&mut chat).await, Event::Reply("是的".into()));

    for dir in [host_dir, device_dir] {
        let _ = std::fs::remove_dir_all(dir);
    }
}
