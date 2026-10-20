//! Classify one guest-originated Ethernet frame.
//!
//! Only headers are read; payloads are never inspected. Anything that cannot be
//! parsed with certainty is dropped (fail closed).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::policy::EgressPolicy;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    /// Dropped: a forbidden or unparseable destination.
    Drop { dst: Option<IpAddr> },
}

pub fn inspect_guest_frame(frame: &[u8], policy: &EgressPolicy) -> Verdict {
    let Some(ethertype) = frame.get(12..14).map(|b| u16::from_be_bytes([b[0], b[1]])) else {
        return Verdict::Drop { dst: None };
    };
    let l3 = &frame[14..];
    match ethertype {
        // ARP never leaves passt; it resolves the virtual gateway.
        ETHERTYPE_ARP => Verdict::Pass,
        ETHERTYPE_IPV4 => ipv4(l3, policy),
        ETHERTYPE_IPV6 => ipv6(l3, policy),
        _ => Verdict::Drop { dst: None },
    }
}

fn ipv4(packet: &[u8], policy: &EgressPolicy) -> Verdict {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return Verdict::Drop { dst: None };
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return Verdict::Drop { dst: None };
    }
    let proto = packet[9];
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    // Non-first fragments carry no L4 header; their destination is still checked.
    let first_fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff == 0;
    let l4 = first_fragment.then(|| &packet[header_len..]);
    let dst_port = l4.and_then(|l4| l4_dst_port(proto, l4));

    // DHCP discovery/request to passt's built-in server.
    if dst == Ipv4Addr::BROADCAST {
        return if proto == PROTO_UDP && dst_port == Some(67) { Verdict::Pass } else { Verdict::Drop { dst: Some(dst.into()) } };
    }
    verdict(policy, dst.into(), dst_port)
}

fn ipv6(packet: &[u8], policy: &EgressPolicy) -> Verdict {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return Verdict::Drop { dst: None };
    }
    let next_header = packet[6];
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&packet[24..40]);
    let dst = Ipv6Addr::from(octets);
    let l4 = &packet[40..];
    let dst_port = l4_dst_port(next_header, l4);

    // Link-scope control traffic that passt answers itself: neighbour
    // discovery (ICMPv6 133-137) and DHCPv6 to ff02::1:2.
    let link_scope = dst.segments()[0] & 0xffc0 == 0xfe80 || dst.segments()[0] == 0xff02;
    if link_scope {
        let ndp = next_header == PROTO_ICMPV6 && l4.first().is_some_and(|t| (133..=137).contains(t));
        let dhcpv6 = next_header == PROTO_UDP && dst_port == Some(547);
        return if ndp || dhcpv6 { Verdict::Pass } else { Verdict::Drop { dst: Some(dst.into()) } };
    }
    // Extension headers would hide the real L4 port; only plain TCP/UDP/ICMPv6 pass.
    if !matches!(next_header, PROTO_TCP | PROTO_UDP | PROTO_ICMPV6) {
        return Verdict::Drop { dst: Some(dst.into()) };
    }
    verdict(policy, dst.into(), dst_port)
}

fn l4_dst_port(proto: u8, l4: &[u8]) -> Option<u16> {
    matches!(proto, PROTO_TCP | PROTO_UDP).then(|| l4.get(2..4).map(|b| u16::from_be_bytes([b[0], b[1]]))).flatten()
}

fn verdict(policy: &EgressPolicy, dst: IpAddr, dst_port: Option<u16>) -> Verdict {
    if policy.allows(dst, dst_port) { Verdict::Pass } else { Verdict::Drop { dst: Some(dst) } }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 53));

    fn policy() -> EgressPolicy {
        EgressPolicy::with_host_addrs(DNS, ["203.0.113.7".parse().unwrap(), "2001:db8:1::7".parse().unwrap()])
    }

    fn eth(ethertype: u16, l3: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(l3);
        frame
    }

    fn v4(dst: [u8; 4], proto: u8, dst_port: u16) -> Vec<u8> {
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0, 10, 0, 2, 15];
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&[0x30, 0x39]);
        ip.extend_from_slice(&dst_port.to_be_bytes());
        ip.extend_from_slice(&[0; 16]);
        eth(ETHERTYPE_IPV4, &ip)
    }

    fn v6(dst: &str, next: u8, l4: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x60, 0, 0, 0, 0, 0, next, 64];
        ip.extend_from_slice(&[0; 16]);
        ip.extend_from_slice(&dst.parse::<Ipv6Addr>().unwrap().octets());
        ip.extend_from_slice(l4);
        eth(ETHERTYPE_IPV6, &ip)
    }

    #[test]
    fn host_own_addresses_are_dropped_even_when_public() {
        assert!(matches!(inspect_guest_frame(&v4([203, 0, 113, 7], PROTO_TCP, 22), &policy()), Verdict::Drop { .. }));
        assert!(matches!(inspect_guest_frame(&v6("2001:db8:1::7", PROTO_TCP, &[0, 1, 0, 22]), &policy()), Verdict::Drop { .. }));
    }

    #[test]
    fn dns_forwarder_only_on_port_53() {
        assert_eq!(inspect_guest_frame(&v4([198, 51, 100, 53], PROTO_UDP, 53), &policy()), Verdict::Pass);
        assert!(matches!(inspect_guest_frame(&v4([198, 51, 100, 53], PROTO_TCP, 80), &policy()), Verdict::Drop { .. }));
    }

    #[test]
    fn dhcp_broadcast_passes_other_broadcast_drops() {
        assert_eq!(inspect_guest_frame(&v4([255, 255, 255, 255], PROTO_UDP, 67), &policy()), Verdict::Pass);
        assert!(matches!(inspect_guest_frame(&v4([255, 255, 255, 255], PROTO_UDP, 137), &policy()), Verdict::Drop { .. }));
    }

    #[test]
    fn ipv6_neighbour_discovery_passes_other_link_scope_drops() {
        assert_eq!(inspect_guest_frame(&v6("ff02::1:ff00:1", PROTO_ICMPV6, &[135, 0]), &policy()), Verdict::Pass);
        assert_eq!(inspect_guest_frame(&v6("fe80::1", PROTO_ICMPV6, &[133, 0]), &policy()), Verdict::Pass);
        assert!(matches!(inspect_guest_frame(&v6("fe80::1", PROTO_TCP, &[0, 1, 0, 80]), &policy()), Verdict::Drop { .. }));
        assert!(matches!(inspect_guest_frame(&v6("ff02::1", PROTO_ICMPV6, &[128, 0]), &policy()), Verdict::Drop { .. }));
    }

    #[test]
    fn malformed_and_unknown_frames_drop() {
        assert!(matches!(inspect_guest_frame(&[0; 10], &policy()), Verdict::Drop { dst: None }));
        assert!(matches!(inspect_guest_frame(&eth(0x88cc, &[0; 40]), &policy()), Verdict::Drop { dst: None }));
        assert!(matches!(inspect_guest_frame(&eth(ETHERTYPE_IPV4, &[0x45, 0, 0]), &policy()), Verdict::Drop { dst: None }));
        assert_eq!(inspect_guest_frame(&eth(ETHERTYPE_ARP, &[0; 28]), &policy()), Verdict::Pass);
    }
}
