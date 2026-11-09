//! Responder / browser tests: answer sets per interface, folding answers into hosts with IPv6
//! zones, and the multicast loopback round trips (IPv4 and IPv6; skipped where the
//! environment has no multicast).

use super::iface::Iface;
use super::*;

fn svc() -> Service {
    Service {
        instance: "SE Agent on studio".into(),
        host: "studio.local".into(),
        port: 8640,
        txt: vec![("v".into(), "seagent/2".into()), ("id".into(), "studio".into()), ("fp".into(), "0123456789abcdef".into()), ("name".into(), "Studio".into())],
        addrs: vec!["192.168.1.20".parse().unwrap()],
        ..Default::default()
    }
}

fn ifaces() -> Vec<Iface> {
    vec![
        Iface { name: "eth0".into(), index: 2, up: true, multicast: true, loopback: false, v4: vec![("192.168.1.20".parse().unwrap(), 24)], v6: vec!["fd00::20".parse().unwrap(), "fe80::20".parse().unwrap()] },
        Iface { name: "wlan0".into(), index: 3, up: true, multicast: true, loopback: false, v4: vec![("10.0.5.9".parse().unwrap(), 16)], v6: vec!["fe80::9".parse().unwrap()] },
    ]
}

fn unscoped(records: Vec<Record>) -> Vec<(Record, u32)> {
    records.into_iter().map(|r| (r, 0)).collect()
}

#[test]
fn response_round_trips_into_a_found_host() {
    let s = svc();
    let m = parse(&encode_response(&s, 0, None, false)).unwrap();
    assert!(m.response && m.questions.is_empty());
    assert!(m.records.iter().any(|r| r.rtype == T_SRV && r.ttl == 120));
    let found = collect(&unscoped(m.records));
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert_eq!((f.instance.as_str(), f.host.as_str(), f.port), ("SE Agent on studio", "studio.local", 8640));
    assert_eq!(f.addrs, vec![HostAddr { ip: "192.168.1.20".parse().unwrap(), scope: 0 }]);
    assert_eq!(f.txt["v"], "seagent/2");
    assert_eq!(f.txt["fp"], "0123456789abcdef");
    // Goodbye: TTL 0 everywhere, and a goodbye PTR yields no host.
    let bye = parse(&encode_response(&s, 0, Some(0), false)).unwrap();
    assert!(bye.records.iter().all(|r| r.ttl == 0));
    assert!(collect(&unscoped(bye.records)).is_empty());
    // A legacy unicast reply echoes the id and has no cache-flush bit.
    let legacy = encode_response(&s, 0x1234, None, true);
    assert_eq!(&legacy[..2], &[0x12, 0x34]);
}

#[test]
fn answers_carry_the_addresses_of_the_arrival_interface() {
    let l = ifaces();
    let auto = Service { addrs: vec![], auto_v4: true, auto_v6: true, ..svc() };
    let eth = answer_addrs(&auto, &l, Some(&l[0]));
    assert_eq!(eth, ["192.168.1.20", "fd00::20", "fe80::20"].map(|a| a.parse::<IpAddr>().unwrap()).to_vec());
    // A v4 querier on wlan0's subnet gets wlan0's addresses only.
    let from = SocketAddr::new("10.0.77.1".parse().unwrap(), 5353);
    assert_eq!(answer_addrs(&auto, &l, iface::arrival(&l, &from)), ["10.0.5.9", "fe80::9"].map(|a| a.parse::<IpAddr>().unwrap()).to_vec());
    // Unknown arrival: every interface.
    assert_eq!(answer_addrs(&auto, &l, None).len(), 5);
    // IPv4-only server (listen 0.0.0.0): no AAAA.
    let v4only = Service { auto_v6: false, ..auto.clone() };
    assert!(answer_addrs(&v4only, &l, None).iter().all(IpAddr::is_ipv4));
    // A fixed listen address wins over the interface list.
    assert_eq!(answer_addrs(&svc(), &l, Some(&l[1])), svc().addrs);
}

#[test]
fn aaaa_link_local_answers_get_the_arrival_zone_or_are_dropped() {
    let s = Service { addrs: ["192.168.1.20", "169.254.3.3", "fe80::20", "fd00::20", "127.0.0.1"].iter().map(|a| a.parse().unwrap()).collect(), ..svc() };
    let records = parse(&encode_response(&s, 0, None, false)).unwrap().records;
    // Heard on interface 2: the link-local address is usable as fe80::20%2.
    let scoped: Vec<(Record, u32)> = records.iter().cloned().map(|r| (r, 2)).collect();
    let f = &collect(&scoped)[0];
    let want: Vec<HostAddr> = vec![
        HostAddr { ip: "192.168.1.20".parse().unwrap(), scope: 0 },
        HostAddr { ip: "fd00::20".parse().unwrap(), scope: 0 },
        HostAddr { ip: "169.254.3.3".parse().unwrap(), scope: 0 },
        HostAddr { ip: "fe80::20".parse().unwrap(), scope: 2 },
    ];
    assert_eq!(f.addrs, want, "ranked: private v4, routable v6, v4 link-local, v6 link-local; never loopback");
    assert_eq!(f.best().unwrap().ip, "192.168.1.20".parse::<IpAddr>().unwrap());
    // Zone unknown: the link-local address is dropped, the rest kept.
    let f = &collect(&unscoped(records))[0];
    assert_eq!(f.addrs.len(), 3);
    assert!(f.addrs.iter().all(|a| !(a.ip.is_ipv6() && a.is_link_local())));
    // The same link-local address heard on two interfaces is two usable addresses.
    let ll = Service { addrs: vec!["fe80::20".parse().unwrap()], ..svc() };
    let r = parse(&encode_response(&ll, 0, None, false)).unwrap().records;
    let both: Vec<(Record, u32)> = r.iter().cloned().map(|r| (r, 2)).chain(r.iter().cloned().map(|r| (r, 3))).collect();
    assert_eq!(collect(&both)[0].addrs.iter().map(|a| a.scope).collect::<Vec<_>>(), [2, 3]);
}

#[test]
fn host_addresses_format_for_cli_and_urls() {
    let v4 = HostAddr { ip: "192.168.1.20".parse().unwrap(), scope: 0 };
    assert_eq!((v4.to_string(), v4.authority(8640), v4.url("https", 8640)), ("192.168.1.20".into(), "192.168.1.20:8640".into(), "https://192.168.1.20:8640".into()));
    let ula = HostAddr::on("fd00::2".parse().unwrap(), 7);
    assert_eq!(ula.scope, 0, "only link-local keeps a zone");
    assert_eq!(ula.authority(8640), "[fd00::2]:8640");
    // A zone index no interface has prints as the number on every platform.
    let ll = HostAddr::on("fe80::1".parse().unwrap(), 4_000_000);
    assert_eq!(ll.to_string(), "fe80::1%4000000");
    assert_eq!(ll.authority(8640), "[fe80::1%4000000]:8640");
    assert_eq!(ll.url("https", 8640), "https://[fe80::1%254000000]:8640");
    assert_eq!(ll.socket_addr(8640), "[fe80::1%4000000]:8640".parse::<SocketAddr>().unwrap());
}

fn loopback_round_trip(v4: bool, v6: bool) {
    let mut s = svc();
    let fam = if v6 { "v6" } else { "v4" };
    s.instance = format!("SE Agent test {} {fam}", std::process::id());
    // Its own host name: address records are folded by name, and the other test runs alongside.
    s.host = format!("studio-{}-{fam}.local", std::process::id());
    s.port = 18640;
    s.addrs = vec![];
    (s.auto_v4, s.auto_v6) = (v4, v6);
    let r = match Responder::start(s.clone()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skipping: {e}");
            return;
        }
    };
    let st = r.status().clone();
    if (v6 && !st.ipv6) || (v4 && !st.ipv4) {
        eprintln!("skipping: {st:?}");
        return;
    }
    let found = browse_on(Duration::from_millis(1500), v4, v6).unwrap_or_default();
    r.stop();
    match found.iter().find(|f| f.instance == s.instance) {
        Some(f) => {
            assert_eq!((f.port, f.txt.get("id").map(String::as_str)), (18640, Some("studio")));
            assert!(f.addrs.iter().all(|a| !a.ip.is_loopback()), "{f:?}");
            if v6 && !v4 {
                assert!(!f.addrs.is_empty() && f.addrs.iter().all(|a| a.ip.is_ipv6()), "{f:?}");
                // A link-local address arrives with the zone of the interface it was heard on.
                assert!(f.addrs.iter().all(|a| !a.is_link_local() || a.scope != 0), "{f:?}");
                eprintln!("IPv6 loopback found {:?}", f.addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>());
            }
        }
        None => eprintln!("skipping: no multicast loopback here (status {st:?}, found {found:?})"),
    }
}

/// Advertise and browse on this machine over IPv4 (multicast loopback).
#[test]
fn responder_and_browser_find_each_other_over_ipv4() {
    loopback_round_trip(true, false);
}

/// The same over IPv6 (`ff02::fb` on every interface with an IPv6 address).
#[test]
fn responder_and_browser_find_each_other_over_ipv6() {
    loopback_round_trip(false, true);
}
