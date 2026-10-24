//! Destination policy for guest egress.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One CIDR from ipaddr.js 2.5.0 `IPv4.prototype.SpecialRanges` whose category
/// is blocked by openclaw (`BLOCKED_IPV4_SPECIAL_USE_RANGES` in
/// `packages/net-policy/src/ip.ts`).
struct Ipv4Cidr {
    network: Ipv4Addr,
    /// Prefix length in bits.
    prefix: u8,
    /// Source ipaddr.js category, kept so the table can be audited against the
    /// upstream range list.
    category: &'static str,
}

impl Ipv4Cidr {
    fn contains(&self, addr: Ipv4Addr) -> bool {
        let bits = u32::from(self.prefix);
        debug_assert!(bits <= 32, "IPv4 prefix cannot exceed 32 bits");
        let mask = if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        };
        (u32::from(addr) & mask) == (u32::from(self.network) & mask)
    }
}

/// Blocked IPv4 special-use ranges. Overlaps between entries do not matter:
/// membership in any of them is enough to block.
const BLOCKED_IPV4: &[Ipv4Cidr] = &[
    // RFC4291
    Ipv4Cidr {
        network: Ipv4Addr::new(0, 0, 0, 0),
        prefix: 8,
        category: "unspecified",
    },
    // RFC919
    Ipv4Cidr {
        network: Ipv4Addr::new(255, 255, 255, 255),
        prefix: 32,
        category: "broadcast",
    },
    // RFC3171
    Ipv4Cidr {
        network: Ipv4Addr::new(224, 0, 0, 0),
        prefix: 4,
        category: "multicast",
    },
    // RFC3927
    Ipv4Cidr {
        network: Ipv4Addr::new(169, 254, 0, 0),
        prefix: 16,
        category: "linkLocal",
    },
    // RFC5735
    Ipv4Cidr {
        network: Ipv4Addr::new(127, 0, 0, 0),
        prefix: 8,
        category: "loopback",
    },
    // RFC6598
    Ipv4Cidr {
        network: Ipv4Addr::new(100, 64, 0, 0),
        prefix: 10,
        category: "carrierGradeNat",
    },
    // RFC1918
    Ipv4Cidr {
        network: Ipv4Addr::new(10, 0, 0, 0),
        prefix: 8,
        category: "private",
    },
    Ipv4Cidr {
        network: Ipv4Addr::new(172, 16, 0, 0),
        prefix: 12,
        category: "private",
    },
    Ipv4Cidr {
        network: Ipv4Addr::new(192, 168, 0, 0),
        prefix: 16,
        category: "private",
    },
    // RFC2544 benchmarking range, which ipaddr.js also folds into `reserved`
    // but openclaw tracks separately as `RFC2544_BENCHMARK_PREFIX`.
    Ipv4Cidr {
        network: Ipv4Addr::new(198, 18, 0, 0),
        prefix: 15,
        category: "rfc2544Benchmark",
    },
    // Reserved and testing-only ranges; RFCs 5735, 5737, 1700
    Ipv4Cidr {
        network: Ipv4Addr::new(192, 0, 0, 0),
        prefix: 24,
        category: "reserved",
    },
    Ipv4Cidr {
        network: Ipv4Addr::new(192, 0, 2, 0),
        prefix: 24,
        category: "reserved",
    },
    Ipv4Cidr {
        network: Ipv4Addr::new(192, 88, 99, 0),
        prefix: 24,
        category: "reserved",
    },
    Ipv4Cidr {
        network: Ipv4Addr::new(198, 51, 100, 0),
        prefix: 24,
        category: "reserved",
    },
    Ipv4Cidr {
        network: Ipv4Addr::new(203, 0, 113, 0),
        prefix: 24,
        category: "reserved",
    },
    Ipv4Cidr {
        network: Ipv4Addr::new(240, 0, 0, 0),
        prefix: 4,
        category: "reserved",
    },
];

/// Cloud metadata endpoints (`CLOUD_METADATA_IP_ADDRESSES` in ip.ts). They are
/// listed separately because they stay blocked even where their surrounding
/// range might otherwise be up for debate.
const CLOUD_METADATA_IPV4: &[Ipv4Addr] = &[Ipv4Addr::new(100, 100, 100, 200)];

/// One CIDR from ipaddr.js 2.5.0 `IPv6.prototype.SpecialRanges` whose category
/// is blocked by openclaw (`BLOCKED_IPV6_SPECIAL_USE_RANGES` in
/// `packages/net-policy/src/ip.ts`), plus deprecated site-local and RFC8215.
struct Ipv6Cidr {
    network: Ipv6Addr,
    /// Prefix length in bits.
    prefix: u8,
    category: &'static str,
}

impl Ipv6Cidr {
    fn contains(&self, addr: Ipv6Addr) -> bool {
        let bits = u32::from(self.prefix);
        debug_assert!(bits <= 128, "IPv6 prefix cannot exceed 128 bits");
        let mask = if bits == 0 {
            0
        } else {
            u128::MAX << (128 - bits)
        };
        (u128::from(addr) & mask) == (u128::from(self.network) & mask)
    }
}

/// Blocked IPv6 special-use ranges. The more specific blocked categories are
/// listed before the broad `2001::/23` reserved block so the table doubles as
/// an audit of ipaddr.js's categories; membership in any entry blocks, so order
/// does not change the verdict. Note that `2001::/23` also contains Teredo
/// (`2001::/32`), so a Teredo destination is blocked even when its embedded
/// IPv4 address is public; that is conservative relative to ipaddr.js's
/// first-match classification.
const BLOCKED_IPV6: &[Ipv6Cidr] = &[
    // RFC4291
    Ipv6Cidr {
        network: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        prefix: 128,
        category: "unspecified",
    },
    Ipv6Cidr {
        network: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        prefix: 128,
        category: "loopback",
    },
    Ipv6Cidr {
        network: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        prefix: 10,
        category: "linkLocal",
    },
    // RFC4193
    Ipv6Cidr {
        network: Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
        prefix: 7,
        category: "uniqueLocal",
    },
    // RFC4291
    Ipv6Cidr {
        network: Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
        prefix: 8,
        category: "multicast",
    },
    // RFC5180
    Ipv6Cidr {
        network: Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0),
        prefix: 48,
        category: "benchmarking",
    },
    // RFC6666
    Ipv6Cidr {
        network: Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0),
        prefix: 64,
        category: "discard",
    },
    // RFC7343
    Ipv6Cidr {
        network: Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 0),
        prefix: 28,
        category: "orchid2",
    },
    // RFC3879 deprecated site-local; ipaddr.js does not classify it as private.
    Ipv6Cidr {
        network: Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0),
        prefix: 10,
        category: "siteLocal",
    },
    // RFC8215 local-use NAT64.
    Ipv6Cidr {
        network: Ipv6Addr::new(0x0064, 0xff9b, 0x0001, 0, 0, 0, 0, 0),
        prefix: 48,
        category: "rfc8215LocalUseNat64",
    },
    // RFC3849, RFC2928, RFC9637
    Ipv6Cidr {
        network: Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0),
        prefix: 23,
        category: "reserved",
    },
    Ipv6Cidr {
        network: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0),
        prefix: 32,
        category: "reserved",
    },
    Ipv6Cidr {
        network: Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0),
        prefix: 20,
        category: "reserved",
    },
];

/// IPv6 cloud metadata endpoint (`CLOUD_METADATA_IP_ADDRESSES` in ip.ts).
const CLOUD_METADATA_IPV6: &[Ipv6Addr] = &[Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)];

fn ipv4_category(addr: Ipv4Addr) -> Option<&'static str> {
    if CLOUD_METADATA_IPV4.contains(&addr) {
        return Some("cloudMetadata");
    }
    BLOCKED_IPV4
        .iter()
        .find(|cidr| cidr.contains(addr))
        .map(|cidr| cidr.category)
}

fn ipv6_category(addr: Ipv6Addr) -> Option<&'static str> {
    if CLOUD_METADATA_IPV6.contains(&addr) {
        return Some("cloudMetadata");
    }
    BLOCKED_IPV6
        .iter()
        .find(|cidr| cidr.contains(addr))
        .map(|cidr| cidr.category)
}

fn is_blocked_ipv4(addr: Ipv4Addr) -> bool {
    ipv4_category(addr).is_some()
}

/// Decode a network-order IPv4 address from two hextets.
fn ipv4_from_hextets(high: u16, low: u16) -> Ipv4Addr {
    let [a, b] = high.to_be_bytes();
    let [c, d] = low.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

/// Extract the IPv4 address carried by an IPv6 transition form, mirroring
/// `extractEmbeddedIpv4FromIpv6` in openclaw's `ip.ts`. Local-use NAT64
/// (`64:ff9b:1::/48`) is blocked outright and yields `None`: without the
/// deployment's NAT64 prefix length there is no single embedded IPv4.
fn embedded_ipv4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    let p = addr.segments();

    // ::ffff:0:0/96 (ipaddr.js `ipv4Mapped`, RFC4291).
    if p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0 && p[4] == 0 && p[5] == 0xffff {
        return Some(ipv4_from_hextets(p[6], p[7]));
    }
    // ::ffff:0:0:0/96 (ipaddr.js `rfc6145`, IPv4-translated).
    if p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0 && p[4] == 0xffff && p[5] == 0 {
        return Some(ipv4_from_hextets(p[6], p[7]));
    }
    // 64:ff9b::/96 (ipaddr.js `rfc6052`, NAT64 well-known prefix).
    if p[0] == 0x0064 && p[1] == 0xff9b && p[2] == 0 && p[3] == 0 && p[4] == 0 && p[5] == 0 {
        return Some(ipv4_from_hextets(p[6], p[7]));
    }
    // 2002::/16 (ipaddr.js `6to4`, RFC3056).
    if p[0] == 0x2002 {
        return Some(ipv4_from_hextets(p[1], p[2]));
    }
    // 2001::/32 (ipaddr.js `teredo`, RFC4380): the client address is XORed.
    if p[0] == 0x2001 && p[1] == 0 {
        return Some(ipv4_from_hextets(p[6] ^ 0xffff, p[7] ^ 0xffff));
    }
    // ISATAP (RFC5214) is not classified by ipaddr.js, but its interface
    // identifier marks the low 32 bits as an IPv4 address.
    if (p[4] & 0xfcff) == 0 && p[5] == 0x5efe {
        return Some(ipv4_from_hextets(p[6], p[7]));
    }
    // IPv4-compatible (deprecated, RFC4291): ::a.b.c.d.
    if p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 0 && p[4] == 0 && p[5] == 0 {
        return Some(ipv4_from_hextets(p[6], p[7]));
    }
    None
}

/// True when `ip` must never be reachable from the guest: loopback, private,
/// link-local, CGNAT, multicast, broadcast, reserved/documentation,
/// benchmarking, unique-local, deprecated site-local, cloud metadata, NAT64
/// local-use, and any IPv6 form that embeds a forbidden IPv4 address
/// (mapped, compatible, NAT64 well-known prefix, 6to4, Teredo, ISATAP, RFC6145).
/// MARK: M10 — transcribed by dsh; see marks/M10-ip-policy.md.
pub fn is_forbidden_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_ipv4(v4),
        IpAddr::V6(v6) => {
            ipv6_category(v6).is_some() || embedded_ipv4(v6).is_some_and(is_blocked_ipv4)
        }
    }
}

/// The networks this host is attached to: every interface address together with
/// its on-link prefix. A destination inside any of them is the host itself or a
/// LAN neighbour. This covers IPv6 as well as IPv4: a NAS or router on the LAN
/// with a global IPv6 address is not in any special-use range, so
/// `is_forbidden_destination` alone would let it through.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostNetworks {
    nets: Vec<(IpAddr, u8)>,
}

impl HostNetworks {
    /// Read the host's interfaces now. Callers check per connection, so an
    /// address acquired later (DHCP renewal, IPv6 privacy address) is covered.
    pub fn current() -> std::io::Result<Self> {
        let ifaces = if_addrs::get_if_addrs()?;
        Ok(Self::from_nets(ifaces.into_iter().map(|iface| match iface.addr {
            if_addrs::IfAddr::V4(v4) => (IpAddr::V4(v4.ip), v4.prefixlen),
            if_addrs::IfAddr::V6(v6) => (IpAddr::V6(v6.ip), v6.prefixlen),
        })))
    }

    pub fn from_nets(nets: impl IntoIterator<Item = (IpAddr, u8)>) -> Self {
        Self { nets: nets.into_iter().collect() }
    }

    /// Whether `ip` is one of this host's addresses or on one of its links.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.nets.iter().any(|&(net, len)| same_prefix(net.to_canonical(), ip, len))
    }
}

/// Whether `a` and `b` share their first `len` bits (same address family only).
fn same_prefix(a: IpAddr, b: IpAddr, len: u8) -> bool {
    fn masked(bits: u128, width: u32, len: u8) -> u128 {
        let len = u32::from(len).min(width);
        if len == 0 { 0 } else { bits >> (width - len) }
    }
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => masked(u32::from(a).into(), 32, len) == masked(u32::from(b).into(), 32, len),
        (IpAddr::V6(a), IpAddr::V6(b)) => masked(u128::from(a), 128, len) == masked(u128::from(b), 128, len),
        _ => false,
    }
}

/// Per-VM egress policy. Host networks are refreshed by the relay so that a
/// network change cannot expose a newly acquired host address. If the host's
/// interfaces could never be read, nothing but the DNS forwarder is allowed
/// (fail closed: an unknown LAN cannot be told apart from the internet).
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    host: Option<HostNetworks>,
    /// passt's DNS forwarder address handed to the guest (`--dns-forward`).
    dns_forwarder: IpAddr,
}

impl EgressPolicy {
    pub fn new(dns_forwarder: IpAddr) -> Self {
        let mut policy = Self { host: None, dns_forwarder };
        policy.refresh_host_addrs();
        policy
    }

    /// Re-read every address and on-link prefix of the host's interfaces. A
    /// failed read keeps the previous view rather than forgetting it.
    pub fn refresh_host_addrs(&mut self) {
        if let Ok(host) = HostNetworks::current() {
            self.host = Some(host);
        }
    }

    pub fn dns_forwarder(&self) -> IpAddr {
        self.dns_forwarder
    }

    /// Ordinary (non-control) guest traffic to `dst`.
    pub fn allows(&self, dst: IpAddr, dst_port: Option<u16>) -> bool {
        if dst == self.dns_forwarder {
            return dst_port == Some(53);
        }
        self.host.as_ref().is_some_and(|host| !host.contains(dst)) && !is_forbidden_destination(dst)
    }

    #[cfg(test)]
    pub(crate) fn with_host_addrs(
        dns_forwarder: IpAddr,
        host_addrs: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        let nets = host_addrs.into_iter().map(|ip| (ip, if ip.is_ipv4() { 32 } else { 128 }));
        Self { host: Some(HostNetworks::from_nets(nets)), dns_forwarder }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_networks_cover_lan_neighbours_in_both_families() {
        let host = HostNetworks::from_nets([
            ("192.168.1.20".parse().unwrap(), 24),
            ("2001:db8:aa:bb::20".parse().unwrap(), 64),
            ("203.0.113.9".parse().unwrap(), 32),
        ]);
        assert!(host.contains("192.168.1.77".parse().unwrap()));
        assert!(host.contains("::ffff:192.168.1.77".parse().unwrap()), "IPv4-mapped form");
        assert!(host.contains("2001:db8:aa:bb::1234".parse().unwrap()), "LAN global IPv6");
        assert!(host.contains("203.0.113.9".parse().unwrap()), "host's own public address");
        assert!(!host.contains("203.0.113.10".parse().unwrap()));
        assert!(!host.contains("2001:db8:aa:cc::1".parse().unwrap()));
        assert!(!host.contains("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn unknown_host_networks_fail_closed() {
        let dns: IpAddr = "10.0.2.3".parse().unwrap();
        let policy = EgressPolicy { host: None, dns_forwarder: dns };
        assert!(!policy.allows("8.8.8.8".parse().unwrap(), Some(443)));
        assert!(policy.allows(dns, Some(53)));
    }

    fn parse(literal: &str) -> IpAddr {
        literal.parse().expect("test literal must be an IP address")
    }

    fn v4(literal: &str) -> Ipv4Addr {
        literal
            .parse()
            .expect("test literal must be an IPv4 address")
    }

    fn v6(literal: &str) -> Ipv6Addr {
        literal
            .parse()
            .expect("test literal must be an IPv6 address")
    }

    fn assert_blocked(literals: &[&str]) {
        for literal in literals {
            assert!(
                is_forbidden_destination(parse(literal)),
                "{literal} must be blocked"
            );
        }
    }

    fn assert_allowed(literals: &[&str]) {
        for literal in literals {
            assert!(
                !is_forbidden_destination(parse(literal)),
                "{literal} must be allowed"
            );
        }
    }

    fn last_ipv4(cidr: &Ipv4Cidr) -> Ipv4Addr {
        let host_bits = 32 - u32::from(cidr.prefix);
        let host_mask = if host_bits == 32 {
            u32::MAX
        } else {
            (1u32 << host_bits) - 1
        };
        Ipv4Addr::from(u32::from(cidr.network) | host_mask)
    }

    fn last_ipv6(cidr: &Ipv6Cidr) -> Ipv6Addr {
        let host_bits = 128 - u32::from(cidr.prefix);
        let host_mask = if host_bits == 128 {
            u128::MAX
        } else {
            (1u128 << host_bits) - 1
        };
        Ipv6Addr::from(u128::from(cidr.network) | host_mask)
    }

    /// The first and last address of every CIDR are inside; its immediate
    /// neighbours are outside. This catches any typo in the transcribed table.
    #[test]
    fn ipv4_cidr_boundaries_are_exact() {
        for cidr in BLOCKED_IPV4 {
            assert!(
                cidr.contains(cidr.network),
                "{} first address",
                cidr.category
            );
            let last = last_ipv4(cidr);
            assert!(cidr.contains(last), "{} last address {last}", cidr.category);
            assert!(
                is_forbidden_destination(IpAddr::V4(last)),
                "{} last address {last}",
                cidr.category
            );
            if let Some(before) = u32::from(cidr.network).checked_sub(1).map(Ipv4Addr::from) {
                assert!(
                    !cidr.contains(before),
                    "{} must not contain {before}",
                    cidr.category
                );
            }
            if let Some(after) = u32::from(last).checked_add(1).map(Ipv4Addr::from) {
                assert!(
                    !cidr.contains(after),
                    "{} must not contain {after}",
                    cidr.category
                );
            }
        }
    }

    #[test]
    fn ipv6_cidr_boundaries_are_exact() {
        for cidr in BLOCKED_IPV6 {
            assert!(
                cidr.contains(cidr.network),
                "{} first address",
                cidr.category
            );
            let last = last_ipv6(cidr);
            assert!(cidr.contains(last), "{} last address {last}", cidr.category);
            assert!(
                is_forbidden_destination(IpAddr::V6(last)),
                "{} last address {last}",
                cidr.category
            );
            if let Some(before) = u128::from(cidr.network).checked_sub(1).map(Ipv6Addr::from) {
                assert!(
                    !cidr.contains(before),
                    "{} must not contain {before}",
                    cidr.category
                );
            }
            if let Some(after) = u128::from(last).checked_add(1).map(Ipv6Addr::from) {
                assert!(
                    !cidr.contains(after),
                    "{} must not contain {after}",
                    cidr.category
                );
            }
        }
    }

    #[test]
    fn ipv4_categories_have_inside_and_outside_addresses() {
        let inside: &[(&str, &str)] = &[
            ("0.0.0.0", "unspecified"),
            ("255.255.255.255", "broadcast"),
            ("224.0.0.1", "multicast"),
            ("169.254.169.254", "linkLocal"),
            ("127.0.0.1", "loopback"),
            ("100.64.0.1", "carrierGradeNat"),
            ("10.42.0.59", "private"),
            ("172.16.0.1", "private"),
            ("192.168.1.1", "private"),
            ("192.0.2.1", "reserved"),
            ("198.18.0.1", "rfc2544Benchmark"),
            ("198.19.255.255", "rfc2544Benchmark"),
            ("198.51.100.1", "reserved"),
            ("203.0.113.1", "reserved"),
            ("240.0.0.1", "reserved"),
            ("100.100.100.200", "cloudMetadata"),
        ];
        for (literal, category) in inside {
            let addr = v4(literal);
            assert_eq!(ipv4_category(addr), Some(*category), "{literal}");
            assert!(is_forbidden_destination(IpAddr::V4(addr)), "{literal}");
        }

        // Just outside each blocked range (where no other blocked range applies).
        let outside = [
            "1.0.0.0",
            "223.255.255.255",
            "169.253.255.255",
            "169.255.0.0",
            "126.255.255.255",
            "128.0.0.1",
            "100.63.255.255",
            "100.128.0.0",
            "9.255.255.255",
            "11.0.0.1",
            "172.15.255.255",
            "172.32.0.0",
            "192.167.255.255",
            "192.169.0.0",
            "191.255.255.255",
            "192.0.1.1",
            "192.0.3.1",
            "192.88.100.1",
            "198.17.255.255",
            "198.20.0.0",
            "198.51.99.255",
            "198.51.101.0",
            "203.0.112.255",
            "203.0.114.0",
            "223.255.255.254",
        ];
        for literal in outside {
            let addr = v4(literal);
            assert_eq!(ipv4_category(addr), None, "{literal}");
            assert!(!is_forbidden_destination(IpAddr::V4(addr)), "{literal}");
        }
    }

    #[test]
    fn ipv6_categories_have_inside_and_outside_addresses() {
        let inside: &[(&str, &str)] = &[
            ("::", "unspecified"),
            ("::1", "loopback"),
            ("fe80::1", "linkLocal"),
            ("fc00::1", "uniqueLocal"),
            ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "uniqueLocal"),
            ("ff02::1", "multicast"),
            ("ff05::1:3", "multicast"),
            ("2001:2::1", "benchmarking"),
            ("100::1", "discard"),
            ("2001:20::1", "orchid2"),
            ("fec0::1", "siteLocal"),
            ("fd00:ec2::254", "cloudMetadata"),
            ("64:ff9b:1::1", "rfc8215LocalUseNat64"),
            ("2001::1", "reserved"),
            ("2001:db8::1", "reserved"),
            ("3fff::1", "reserved"),
        ];
        for (literal, category) in inside {
            let addr = v6(literal);
            assert_eq!(ipv6_category(addr), Some(*category), "{literal}");
            assert!(is_forbidden_destination(IpAddr::V6(addr)), "{literal}");
        }

        // Just outside each blocked range (where no other blocked range applies).
        let outside = [
            "fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe00::1",
            "fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "100:0:0:1::1",
            "2001:200::1",
            "2001:db9::1",
            "3fff:1000::1",
            "64:ff9b:2::1",
        ];
        for literal in outside {
            let addr = v6(literal);
            assert_eq!(ipv6_category(addr), None, "{literal}");
            assert!(!is_forbidden_destination(IpAddr::V6(addr)), "{literal}");
        }
    }

    /// Positives from `ip.test.ts` (`isPrivateOrLoopbackIpAddress`,
    /// `isLinkLocalIpAddress`, `isCloudMetadataIpAddress`, unspecified) plus
    /// the public addresses that must stay reachable.
    #[test]
    fn openclaw_ip_fixtures() {
        assert_blocked(&[
            "0.0.0.0",
            "127.0.0.1",
            "10.42.0.59",
            "100.64.0.1",
            "169.254.169.254",
            "198.18.0.1",
            "192.0.2.1",
            "203.0.113.9",
            "240.0.0.1",
            "100.100.100.200",
            "::",
            "::1",
            "fe80::1",
            "fc00::1",
            "fd00::1",
            "ff02::1",
            "ff05::1:3",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fec0::1",
            "2001:db8::1",
            "2001:2::1",
            "100::1",
            "2001:20::1",
            "fd00:ec2::254",
            "64:ff9b:1:7f00:0:100:808:808",
            "64:ff9b:1:a9fe:a9:fe00:808:808",
            "64:ff9b:1:808:808:808:808:808",
            "64:ff9b:1:808:808:808:a9fe:a9fe",
        ]);
        assert_allowed(&[
            "1.1.1.1",
            "8.8.8.8",
            "2606:4700:4700::1111",
            "2001:4860:4860::8888",
        ]);
    }

    #[test]
    fn embedded_ipv4_extraction_matches_reference() {
        let cases: &[(&str, Option<&str>)] = &[
            ("::ffff:127.0.0.1", Some("127.0.0.1")),
            ("::ffff:0:808:808", Some("8.8.8.8")),
            ("::127.0.0.1", Some("127.0.0.1")),
            ("64:ff9b::8.8.8.8", Some("8.8.8.8")),
            ("2002:0808:0808::", Some("8.8.8.8")),
            ("2001::f7f7:f7f7", Some("8.8.8.8")),
            ("2001:0:4136:e378:8000:63bf:3f57:fefe", Some("192.168.1.1")),
            ("2001:4860:1::5efe:7f00:1", Some("127.0.0.1")),
            ("64:ff9b:1:808:808:808:a9fe:a9fe", None),
            ("64:ff9b:1:a00:0:100::", None),
            ("64:ff9b:1:a9fe:a9:fe00:808:808", None),
            ("64:ff9b:1:7f00:0:100:808:808", None),
            ("64:ff9b:1::8.8.8.8", None),
        ];
        for (literal, expected) in cases {
            let extracted = embedded_ipv4(v6(literal));
            assert_eq!(
                extracted.as_ref().map(Ipv4Addr::to_string).as_deref(),
                *expected,
                "{literal}"
            );
        }
    }

    #[test]
    fn embedded_ipv4_destinations_follow_ipv4_rules() {
        assert_blocked(&[
            "::ffff:192.168.1.1",
            "::ffff:0.0.0.0",
            "::ffff:169.254.169.254",
            "::ffff:100.100.100.200",
            "::ffff:0:c0a8:101",
            "::10.0.0.1",
            "::127.0.0.1",
            "64:ff9b::a00:1",
            "64:ff9b::0.0.0.0",
            "64:ff9b::127.0.0.1",
            "64:ff9b::169.254.169.254",
            "64:ff9b::100.100.100.200",
            "2002:c0a8:0101::",
            "2002:a9fe:a9fe::",
            "2002:6464:64c8::",
            // Teredo embeds 192.168.1.1 (XOR 0xffff).
            "2001:0:4136:e378:8000:63bf:3f57:fefe",
            "2001:4860:1::5efe:7f00:1",
        ]);
        assert_allowed(&[
            "::ffff:1.1.1.1",
            "::ffff:0:808:808",
            "::1.1.1.1",
            "64:ff9b::8.8.8.8",
            "2002:0808:0808::",
            "2001:4860:1::5efe:808:808",
        ]);
    }

    #[test]
    fn teredo_is_blocked_by_the_reserved_2001_block_too() {
        // `2001::/23` (reserved) contains Teredo `2001::/32`, so a Teredo
        // destination stays blocked even when it embeds a public IPv4
        // (here 8.8.8.8). This is deliberately conservative.
        assert_blocked(&["2001::f7f7:f7f7"]);
    }

    #[test]
    fn cloud_metadata_is_exact() {
        assert_blocked(&[
            "100.100.100.200",
            "fd00:ec2::254",
            "::ffff:100.100.100.200",
            "64:ff9b::100.100.100.200",
            "2002:6464:64c8::",
        ]);
        assert_eq!(ipv4_category(v4("100.100.100.200")), Some("cloudMetadata"));
        assert_eq!(ipv6_category(v6("fd00:ec2::254")), Some("cloudMetadata"));
        // Neighbours are not metadata themselves, though they stay blocked by
        // their surrounding CGNAT/unique-local range.
        assert_ne!(ipv4_category(v4("100.100.100.201")), Some("cloudMetadata"));
        assert_ne!(ipv6_category(v6("fd00:ec2::253")), Some("cloudMetadata"));
    }
}

#[cfg(test)]
mod review_checks {
    use super::is_forbidden_destination as f;

    #[test]
    fn review_spot_checks() {
        for allowed in ["1.1.1.1", "8.8.8.8", "140.82.112.3", "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:1.1.1.1"] {
            assert!(!f(allowed.parse().unwrap()), "{allowed} should be allowed");
        }
        for blocked in ["127.0.0.1", "192.168.43.10", "10.1.2.3", "172.20.0.1", "100.64.0.1", "169.254.169.254", "198.51.100.53", "255.255.255.255", "::1", "fe80::1", "fd00::1", "::ffff:192.168.1.1", "64:ff9b::c0a8:101", "2002:c0a8:101::"] {
            assert!(f(blocked.parse().unwrap()), "{blocked} should be blocked");
        }
    }
}
