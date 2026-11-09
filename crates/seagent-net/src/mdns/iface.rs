//! Network interfaces for mDNS: which ones to join the groups on, which addresses to
//! advertise, which interface a packet came from, and IPv6 zone (`%eth0` / `%12`) handling.
//!
//! [`system`] lists the host's interfaces — `getifaddrs` on Linux / Android / macOS / iOS,
//! `GetAdaptersAddresses` on Windows. Everything else here is a pure function over an
//! injected list, so the selection rules are tested without touching the network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// One interface and its unicast addresses.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Iface {
    /// `eth0`, `en0`, `wlan0`; the friendly name ("Wi-Fi") on Windows.
    pub name: String,
    /// Interface index: the IPv6 scope id / zone index, and the multicast interface for IPv6.
    pub index: u32,
    pub up: bool,
    pub multicast: bool,
    pub loopback: bool,
    /// IPv4 addresses with their prefix length.
    pub v4: Vec<(Ipv4Addr, u8)>,
    pub v6: Vec<Ipv6Addr>,
}

pub fn is_v6_link_local(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn v4_usable(ip: &Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

fn v6_usable(ip: &Ipv6Addr) -> bool {
    !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast() && ip.to_ipv4_mapped().is_none()
}

/// Interfaces mDNS runs on: up, multicast-capable, not loopback, with at least one usable
/// address (loopback / unspecified / multicast addresses dropped). Sorted by index with
/// sorted, de-duplicated addresses, so two snapshots compare equal when nothing changed.
pub fn suitable(raw: Vec<Iface>) -> Vec<Iface> {
    let mut out: Vec<Iface> = Vec::new();
    for mut i in raw.into_iter().filter(|i| i.up && i.multicast && !i.loopback && i.index != 0) {
        i.v4.retain(|(a, _)| v4_usable(a));
        i.v6.retain(v6_usable);
        match out.iter_mut().find(|o| o.index == i.index) {
            Some(o) => {
                o.v4.extend(i.v4);
                o.v6.extend(i.v6);
            }
            None => out.push(i),
        }
    }
    for i in &mut out {
        i.v4.sort();
        i.v4.dedup();
        i.v6.sort();
        i.v6.dedup();
    }
    out.retain(|i| !i.v4.is_empty() || !i.v6.is_empty());
    out.sort_by_key(|i| i.index);
    out
}

/// The addresses to advertise from `ifaces` (IPv4 when `v4`, IPv6 when `v6`: global, ULA and
/// link-local — link-local goes on the wire without a zone, the receiver supplies its own).
pub fn advertised<'a>(ifaces: impl IntoIterator<Item = &'a Iface>, v4: bool, v6: bool) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for i in ifaces {
        if v4 {
            out.extend(i.v4.iter().map(|(a, _)| IpAddr::V4(*a)));
        }
        if v6 {
            // Routable addresses first: a receiver that takes only the first AAAA gets one it
            // can use without a zone.
            out.extend(i.v6.iter().filter(|a| !is_v6_link_local(a)).map(|a| IpAddr::V6(*a)));
            out.extend(i.v6.iter().filter(|a| is_v6_link_local(a)).map(|a| IpAddr::V6(*a)));
        }
    }
    let mut uniq: Vec<IpAddr> = Vec::with_capacity(out.len());
    for a in out {
        if !uniq.contains(&a) {
            uniq.push(a);
        }
    }
    uniq
}

/// Does `ip` fall in `net/prefix`?
pub fn same_subnet_v4(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix.min(32))) };
    u32::from(ip) & mask == u32::from(net) & mask
}

fn same_prefix_v6(a: &Ipv6Addr, b: &Ipv6Addr) -> bool {
    a.segments()[..4] == b.segments()[..4]
}

/// The interface a datagram from `from` arrived on, when the source tells: a link-local IPv6
/// source carries its scope id; otherwise the interface whose IPv4 subnet (or IPv6 /64)
/// contains the source. `None`: unknown (answer on / with every interface).
pub fn arrival<'a>(ifaces: &'a [Iface], from: &SocketAddr) -> Option<&'a Iface> {
    match from {
        SocketAddr::V4(a) => ifaces.iter().find(|i| i.v4.iter().any(|(net, p)| same_subnet_v4(*a.ip(), *net, *p))),
        SocketAddr::V6(a) => {
            if let Some(v4) = a.ip().to_ipv4_mapped() {
                return arrival(ifaces, &SocketAddr::new(IpAddr::V4(v4), a.port()));
            }
            if a.scope_id() != 0 {
                return ifaces.iter().find(|i| i.index == a.scope_id());
            }
            ifaces.iter().find(|i| i.v6.iter().any(|n| !is_v6_link_local(n) && same_prefix_v6(n, a.ip())))
        }
    }
}

/// The zone to attach to a link-local address heard from `from`: the arrival interface, or the
/// only interface with an IPv6 link-local address when there is exactly one.
pub fn scope_for(ifaces: &[Iface], from: &SocketAddr) -> Option<u32> {
    if let Some(i) = arrival(ifaces, from) {
        return Some(i.index);
    }
    let mut ll = ifaces.iter().filter(|i| i.v6.iter().any(is_v6_link_local));
    match (ll.next(), ll.next()) {
        (Some(i), None) => Some(i.index),
        _ => None,
    }
}

/// `eth0` / `12` → the interface index (`None`: no such interface).
pub fn zone_index(zone: &str) -> Option<u32> {
    let zone = zone.trim();
    if let Ok(n) = zone.parse::<u32>() {
        return Some(n).filter(|n| *n != 0);
    }
    if zone.is_empty() {
        return None;
    }
    #[cfg(unix)]
    {
        let c = std::ffi::CString::new(zone).ok()?;
        // SAFETY: a NUL-terminated name; the call only reads it.
        let n = unsafe { libc::if_nametoindex(c.as_ptr()) };
        Some(n).filter(|n| *n != 0)
    }
    #[cfg(not(unix))]
    {
        system().into_iter().find(|i| i.name.eq_ignore_ascii_case(zone)).map(|i| i.index)
    }
}

/// How a zone is written for people: the interface name on unix (`fe80::1%eth0`), the index on
/// Windows (`fe80::1%12`, what its tools and resolver use). Both parse back with [`zone_index`].
pub fn zone_name(index: u32) -> String {
    #[cfg(unix)]
    {
        let mut buf = [0 as libc::c_char; 64];
        // SAFETY: `buf` is larger than IF_NAMESIZE; on success it holds a NUL-terminated name.
        let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
        if !p.is_null() {
            // SAFETY: if_indextoname wrote a NUL-terminated string into `buf`.
            let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned();
            if !s.is_empty() {
                return s;
            }
        }
    }
    index.to_string()
}

/// This host's interfaces (unfiltered; see [`suitable`]).
#[cfg(unix)]
pub fn system() -> Vec<Iface> {
    let mut out: Vec<Iface> = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills a linked list we only read and then free with freeifaddrs.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut p = head;
        while !p.is_null() {
            let ifa = &*p;
            p = ifa.ifa_next;
            if ifa.ifa_name.is_null() {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
            let flags = ifa.ifa_flags as libc::c_int;
            let index = libc::if_nametoindex(ifa.ifa_name);
            let pos = match out.iter().position(|i| i.name == name) {
                Some(i) => i,
                None => {
                    out.push(Iface { name, index, up: flags & libc::IFF_UP != 0 && flags & libc::IFF_RUNNING != 0, multicast: flags & libc::IFF_MULTICAST != 0, loopback: flags & libc::IFF_LOOPBACK != 0, ..Default::default() });
                    out.len() - 1
                }
            };
            if ifa.ifa_addr.is_null() {
                continue;
            }
            match i32::from((*ifa.ifa_addr).sa_family) {
                libc::AF_INET => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let ip = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
                    let prefix = if ifa.ifa_netmask.is_null() { 24 } else { u32::from_be((*(ifa.ifa_netmask as *const libc::sockaddr_in)).sin_addr.s_addr).count_ones() as u8 };
                    out[pos].v4.push((ip, prefix));
                }
                libc::AF_INET6 => {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    out[pos].v6.push(Ipv6Addr::from(sa.sin6_addr.s6_addr));
                }
                _ => {}
            }
        }
        libc::freeifaddrs(head);
    }
    out
}

/// This host's interfaces (unfiltered; see [`suitable`]).
#[cfg(windows)]
pub fn system() -> Vec<Iface> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_NO_MULTICAST};
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    let mut size: u32 = 16 * 1024;
    for _ in 0..4 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let head = buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;
        // SAFETY: `buf` is `size` bytes, 8-aligned; the list is only read while `buf` lives.
        let rc = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER, std::ptr::null(), head, &mut size) };
        if rc == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if rc != 0 {
            return vec![];
        }
        let mut out = vec![];
        // SAFETY: walking the linked lists GetAdaptersAddresses built inside `buf`.
        unsafe {
            let mut a = head;
            while !a.is_null() {
                let ad = &*a;
                a = ad.Next;
                let mut name = String::new();
                if !ad.FriendlyName.is_null() {
                    let mut n = 0;
                    while *ad.FriendlyName.add(n) != 0 && n < 256 {
                        n += 1;
                    }
                    name = String::from_utf16_lossy(std::slice::from_raw_parts(ad.FriendlyName, n));
                }
                let v4_index = ad.Anonymous1.Anonymous.IfIndex;
                let index = if ad.Ipv6IfIndex != 0 { ad.Ipv6IfIndex } else { v4_index };
                let mut i = Iface { name, index, up: ad.OperStatus == IfOperStatusUp, multicast: ad.Anonymous2.Flags & IP_ADAPTER_NO_MULTICAST == 0, loopback: ad.IfType == IF_TYPE_SOFTWARE_LOOPBACK, ..Default::default() };
                let mut u = ad.FirstUnicastAddress;
                while !u.is_null() {
                    let sa = (*u).Address.lpSockaddr;
                    if !sa.is_null() {
                        if (*sa).sa_family == AF_INET {
                            let s = &*(sa as *const SOCKADDR_IN);
                            i.v4.push((Ipv4Addr::from(u32::from_be(s.sin_addr.S_un.S_addr)), (*u).OnLinkPrefixLength));
                        } else if (*sa).sa_family == AF_INET6 {
                            let s = &*(sa as *const SOCKADDR_IN6);
                            i.v6.push(Ipv6Addr::from(s.sin6_addr.u.Byte));
                        }
                    }
                    u = (*u).Next;
                }
                out.push(i);
            }
        }
        return out;
    }
    vec![]
}

#[cfg(not(any(unix, windows)))]
pub fn system() -> Vec<Iface> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV6;

    fn ip4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn ip6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    fn sample() -> Vec<Iface> {
        vec![
            Iface { name: "lo".into(), index: 1, up: true, multicast: false, loopback: true, v4: vec![(ip4("127.0.0.1"), 8)], v6: vec![ip6("::1")] },
            Iface { name: "eth0".into(), index: 2, up: true, multicast: true, loopback: false, v4: vec![(ip4("192.168.1.20"), 24)], v6: vec![ip6("fe80::20"), ip6("fd00::20"), ip6("fe80::20")] },
            Iface { name: "wlan0".into(), index: 3, up: true, multicast: true, loopback: false, v4: vec![(ip4("10.0.5.9"), 16)], v6: vec![ip6("fe80::9")] },
            Iface { name: "docker0".into(), index: 4, up: false, multicast: true, loopback: false, v4: vec![(ip4("172.17.0.1"), 16)], v6: vec![] },
            Iface { name: "tun0".into(), index: 5, up: true, multicast: false, loopback: false, v4: vec![(ip4("100.64.0.2"), 32)], v6: vec![] },
            Iface { name: "empty".into(), index: 6, up: true, multicast: true, loopback: false, v4: vec![(ip4("0.0.0.0"), 0)], v6: vec![ip6("::1")] },
            // getifaddrs lists one entry per address: a second eth0 entry is merged.
            Iface { name: "eth0".into(), index: 2, up: true, multicast: true, loopback: false, v4: vec![(ip4("192.168.1.21"), 24)], v6: vec![] },
        ]
    }

    #[test]
    fn only_up_multicast_non_loopback_interfaces_with_addresses_are_used() {
        let s = suitable(sample());
        assert_eq!(s.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["eth0", "wlan0"]);
        assert_eq!(s[0].v4, vec![(ip4("192.168.1.20"), 24), (ip4("192.168.1.21"), 24)]);
        assert_eq!(s[0].v6, vec![ip6("fd00::20"), ip6("fe80::20")], "sorted, de-duplicated");
        assert_eq!(suitable(sample()), s, "stable snapshot: unchanged interfaces compare equal");
        let all = advertised(&s, true, true);
        assert!(all.iter().all(|a| !a.is_loopback()));
        assert_eq!(advertised(&s, true, false).len(), 3);
        assert_eq!(advertised(&s, false, true), vec!["fd00::20".parse::<IpAddr>().unwrap(), "fe80::20".parse().unwrap(), "fe80::9".parse().unwrap()], "routable before link-local");
        assert!(advertised(&s, false, false).is_empty());
    }

    #[test]
    fn the_arrival_interface_is_found_from_the_source_address() {
        let s = suitable(sample());
        let from4 = |a: &str| SocketAddr::new(IpAddr::V4(ip4(a)), 5353);
        assert_eq!(arrival(&s, &from4("192.168.1.77")).map(|i| i.index), Some(2));
        assert_eq!(arrival(&s, &from4("10.0.200.1")).map(|i| i.index), Some(3));
        assert_eq!(arrival(&s, &from4("8.8.8.8")), None);
        let ll = SocketAddr::V6(SocketAddrV6::new(ip6("fe80::77"), 5353, 0, 3));
        assert_eq!(arrival(&s, &ll).map(|i| i.name.as_str()), Some("wlan0"), "scope id names the interface");
        let ula = SocketAddr::V6(SocketAddrV6::new(ip6("fd00::77"), 5353, 0, 0));
        assert_eq!(arrival(&s, &ula).map(|i| i.index), Some(2), "same /64");
        let mapped = SocketAddr::V6(SocketAddrV6::new(ip6("::ffff:192.168.1.9"), 5353, 0, 0));
        assert_eq!(arrival(&s, &mapped).map(|i| i.index), Some(2));
        assert!(same_subnet_v4(ip4("10.1.2.3"), ip4("10.9.9.9"), 8) && !same_subnet_v4(ip4("10.1.2.3"), ip4("10.9.9.9"), 16));
        assert!(same_subnet_v4(ip4("1.2.3.4"), ip4("9.9.9.9"), 0));
    }

    #[test]
    fn link_local_zones_come_from_the_arrival_interface_or_the_only_candidate() {
        let s = suitable(sample());
        assert_eq!(scope_for(&s, &SocketAddr::new(IpAddr::V4(ip4("10.0.0.1")), 5353)), Some(3));
        // Unknown source with two link-local interfaces: no guess.
        assert_eq!(scope_for(&s, &SocketAddr::new(IpAddr::V4(ip4("8.8.8.8")), 5353)), None);
        let one: Vec<Iface> = s.iter().filter(|i| i.index == 2).cloned().collect();
        assert_eq!(scope_for(&one, &SocketAddr::new(IpAddr::V4(ip4("8.8.8.8")), 5353)), Some(2));
        assert_eq!(zone_index("12"), Some(12));
        assert_eq!(zone_index("0"), None);
        assert_eq!(zone_index(""), None);
        assert_eq!(zone_index("no-such-interface-xyz"), None);
        assert!(is_v6_link_local(&ip6("fe80::1")) && is_v6_link_local(&ip6("febf::1")) && !is_v6_link_local(&ip6("fd00::1")));
    }

    #[test]
    fn the_system_list_never_yields_loopback_after_filtering() {
        for i in suitable(system()) {
            assert!(!i.loopback && i.index != 0, "{i:?}");
            assert!(i.v4.iter().all(|(a, _)| !a.is_loopback()) && i.v6.iter().all(|a| !a.is_loopback()));
            assert_eq!(zone_index(&zone_name(i.index)), Some(i.index));
        }
    }
}
