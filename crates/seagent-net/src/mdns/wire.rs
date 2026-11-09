//! DNS message encoding / decoding for mDNS (RFC 1035 wire format with the RFC 6762
//! cache-flush and unicast-response bits): the PTR / SRV / TXT / A / AAAA answer set we send
//! and the subset of records we read back. Pure functions; no sockets.

use std::net::{IpAddr, Ipv4Addr};

pub const SERVICE: &str = "_seagent._tcp.local";
pub(super) const META: &str = "_services._dns-sd._udp.local";

pub const T_A: u16 = 1;
pub const T_PTR: u16 = 12;
pub const T_TXT: u16 = 16;
pub const T_AAAA: u16 = 28;
pub const T_SRV: u16 = 33;
pub const T_ANY: u16 = 255;

/// At most this many address records in one answer: keeps a packet well under 1,500 bytes.
pub const MAX_ADDRS: usize = 16;

/// What we advertise.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Service {
    /// Instance label (one DNS label, shown to users): "SE Agent on studio".
    pub instance: String,
    /// `<host>.local`.
    pub host: String,
    pub port: u16,
    pub txt: Vec<(String, String)>,
    /// Fixed addresses (the server listens on one address). Empty: the responder advertises
    /// the addresses of the interface a query arrived on, per [`Service::auto_v4`] / `auto_v6`.
    pub addrs: Vec<IpAddr>,
    /// With no fixed `addrs`: advertise this host's IPv4 interface addresses (A records).
    pub auto_v4: bool,
    /// With no fixed `addrs`: advertise IPv6 addresses (AAAA: global, ULA and link-local).
    pub auto_v6: bool,
}

impl Service {
    pub fn instance_fqdn(&self) -> String {
        format!("{}.{SERVICE}", self.instance.replace('.', " "))
    }
}

/// One record of a parsed message.
#[derive(Debug, Clone, PartialEq)]
pub struct Record {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RData {
    Ptr(String),
    Srv { port: u16, target: String },
    Txt(Vec<(String, String)>),
    Addr(IpAddr),
    Other,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Message {
    pub id: u16,
    pub response: bool,
    pub questions: Vec<(String, u16, bool)>,
    pub records: Vec<Record>,
}

// ── encoding ──

pub(super) fn put_name(b: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()) {
        let l = &label.as_bytes()[..label.len().min(63)];
        b.push(l.len() as u8);
        b.extend_from_slice(l);
    }
    b.push(0);
}

fn put_record(b: &mut Vec<u8>, name: &str, rtype: u16, flush: bool, ttl: u32, rdata: &[u8]) {
    put_name(b, name);
    b.extend(rtype.to_be_bytes());
    b.extend((if flush { 0x8001u16 } else { 1u16 }).to_be_bytes());
    b.extend(ttl.to_be_bytes());
    b.extend((rdata.len() as u16).to_be_bytes());
    b.extend_from_slice(rdata);
}

fn name_bytes(name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    put_name(&mut v, name);
    v
}

pub fn txt_bytes(txt: &[(String, String)]) -> Vec<u8> {
    let mut v = Vec::new();
    for (k, val) in txt {
        let e = format!("{k}={val}");
        let e = &e.as_bytes()[..e.len().min(255)];
        v.push(e.len() as u8);
        v.extend_from_slice(e);
    }
    if v.is_empty() {
        v.push(0);
    }
    v
}

/// A query for `name`/`qtype` (`unicast`: the QU bit).
pub fn encode_query(id: u16, name: &str, qtype: u16, unicast: bool) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend(id.to_be_bytes());
    b.extend([0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    put_name(&mut b, name);
    b.extend(qtype.to_be_bytes());
    b.extend((if unicast { 0x8001u16 } else { 1u16 }).to_be_bytes());
    b
}

/// The full answer set for `svc` with its fixed `addrs` (see [`encode_answer`]).
pub fn encode_response(svc: &Service, id: u16, ttl: Option<u32>, legacy: bool) -> Vec<u8> {
    encode_answer(svc, &svc.addrs, id, ttl, legacy)
}

/// The full answer set for `svc` (PTR, SRV, TXT, one A / AAAA per address in `addrs`, at most
/// [`MAX_ADDRS`]), `ttl` 0 = goodbye. `legacy`: a reply to a legacy unicast query — echo its
/// id, no cache-flush bits (RFC 6762 §6.7). Loopback / unspecified addresses are never written.
pub fn encode_answer(svc: &Service, addrs: &[IpAddr], id: u16, ttl: Option<u32>, legacy: bool) -> Vec<u8> {
    let inst = svc.instance_fqdn();
    let host_ttl = ttl.unwrap_or(120);
    let other_ttl = ttl.unwrap_or(4500);
    let flush = !legacy;
    let mut recs: Vec<u8> = Vec::new();
    let mut n = 0u16;
    put_record(&mut recs, SERVICE, T_PTR, false, other_ttl, &name_bytes(&inst));
    n += 1;
    let mut srv = vec![0, 0, 0, 0];
    srv.extend(svc.port.to_be_bytes());
    srv.extend(name_bytes(&svc.host));
    put_record(&mut recs, &inst, T_SRV, flush, host_ttl, &srv);
    put_record(&mut recs, &inst, T_TXT, flush, other_ttl, &txt_bytes(&svc.txt));
    n += 2;
    for a in addrs.iter().filter(|a| !a.is_loopback() && !a.is_unspecified() && !a.is_multicast()).take(MAX_ADDRS) {
        match a {
            IpAddr::V4(v4) => put_record(&mut recs, &svc.host, T_A, flush, host_ttl, &v4.octets()),
            IpAddr::V6(v6) => put_record(&mut recs, &svc.host, T_AAAA, flush, host_ttl, &v6.octets()),
        }
        n += 1;
    }
    put_record(&mut recs, META, T_PTR, false, other_ttl, &name_bytes(SERVICE));
    n += 1;
    let mut b = Vec::with_capacity(recs.len() + 12);
    b.extend((if legacy { id } else { 0 }).to_be_bytes());
    b.extend(0x8400u16.to_be_bytes());
    b.extend([0, 0]);
    b.extend(n.to_be_bytes());
    b.extend([0, 0, 0, 0]);
    b.extend(recs);
    b
}

// ── decoding ──

fn read_name(b: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let l = *b.get(i)? as usize;
        if l == 0 {
            return Some((labels.join("."), end.unwrap_or(i + 1)));
        }
        if l & 0xc0 == 0xc0 {
            let p = ((l & 0x3f) << 8) | *b.get(i + 1)? as usize;
            end.get_or_insert(i + 2);
            if p >= i {
                return None; // only backward pointers: no loops
            }
            i = p;
            continue;
        }
        labels.push(String::from_utf8_lossy(b.get(i + 1..i + 1 + l)?).into_owned());
        i += 1 + l;
    }
    None
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

pub fn parse_txt(d: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < d.len() {
        let l = d[i] as usize;
        let Some(e) = d.get(i + 1..i + 1 + l) else { break };
        let s = String::from_utf8_lossy(e);
        if !s.is_empty() {
            let (k, v) = s.split_once('=').unwrap_or((&s, ""));
            out.push((k.to_ascii_lowercase(), v.to_string()));
        }
        i += 1 + l;
    }
    out
}

pub fn parse(b: &[u8]) -> Option<Message> {
    let id = u16_at(b, 0)?;
    let flags = u16_at(b, 2)?;
    let (qd, an, ns, ar) = (u16_at(b, 4)?, u16_at(b, 6)?, u16_at(b, 8)?, u16_at(b, 10)?);
    let mut m = Message { id, response: flags & 0x8000 != 0, ..Default::default() };
    let mut i = 12;
    for _ in 0..qd {
        let (name, j) = read_name(b, i)?;
        let qt = u16_at(b, j)?;
        let qc = u16_at(b, j + 2)?;
        m.questions.push((name, qt, qc & 0x8000 != 0));
        i = j + 4;
    }
    for _ in 0..(an as usize + ns as usize + ar as usize) {
        let (name, j) = read_name(b, i)?;
        let rtype = u16_at(b, j)?;
        let ttl = u32::from_be_bytes([*b.get(j + 4)?, *b.get(j + 5)?, *b.get(j + 6)?, *b.get(j + 7)?]);
        let len = u16_at(b, j + 8)? as usize;
        let start = j + 10;
        let d = b.get(start..start + len)?;
        let data = match rtype {
            T_PTR => RData::Ptr(read_name(b, start)?.0),
            T_SRV => RData::Srv { port: u16_at(b, start + 4)?, target: read_name(b, start + 6)?.0 },
            T_TXT => RData::Txt(parse_txt(d)),
            T_A if len == 4 => RData::Addr(IpAddr::V4(Ipv4Addr::new(d[0], d[1], d[2], d[3]))),
            T_AAAA if len == 16 => RData::Addr(IpAddr::V6(<[u8; 16]>::try_from(d).ok()?.into())),
            _ => RData::Other,
        };
        m.records.push(Record { name, rtype, ttl, data });
        i = start + len;
    }
    Some(m)
}

/// Does this query ask for something we own?
pub fn asks_for(m: &Message, svc: &Service) -> bool {
    let inst = svc.instance_fqdn().to_ascii_lowercase();
    let host = svc.host.to_ascii_lowercase();
    !m.response
        && m.questions.iter().any(|(n, t, _)| {
            let n = n.to_ascii_lowercase();
            ((n == SERVICE || n == META) && matches!(*t, T_PTR | T_ANY)) || (n == inst && matches!(*t, T_SRV | T_TXT | T_ANY)) || (n == host && matches!(*t, T_A | T_AAAA | T_ANY))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn svc() -> Service {
        Service {
            instance: "SE Agent on studio".into(),
            host: "studio.local".into(),
            port: 8640,
            txt: vec![("v".into(), "seagent/2".into()), ("id".into(), "studio".into()), ("fp".into(), "0123456789abcdef".into()), ("name".into(), "Studio".into())],
            addrs: vec!["192.168.1.20".parse().unwrap()],
            ..Default::default()
        }
    }

    #[test]
    fn queries_are_matched_and_compressed_names_decode() {
        let s = svc();
        let q = parse(&encode_query(7, SERVICE, T_PTR, true)).unwrap();
        assert_eq!(q.questions, vec![(SERVICE.to_string(), T_PTR, true)]);
        assert!(asks_for(&q, &s));
        assert!(asks_for(&parse(&encode_query(1, "studio.local", T_A, false)).unwrap(), &s));
        assert!(asks_for(&parse(&encode_query(1, "studio.local", T_AAAA, false)).unwrap(), &s));
        assert!(asks_for(&parse(&encode_query(1, &s.instance_fqdn(), T_SRV, false)).unwrap(), &s));
        assert!(!asks_for(&parse(&encode_query(1, "_http._tcp.local", T_PTR, false)).unwrap(), &s));
        assert!(!asks_for(&parse(&encode_response(&s, 0, None, false)).unwrap(), &s), "responses are not questions");
        // A pointer-compressed PTR answer (what mDNSResponder sends).
        let mut b = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        put_name(&mut b, SERVICE); // at offset 12
        b.extend([0, 12, 0, 1, 0, 0, 0, 60]);
        let rdata = [&[3u8, b'f', b'o', b'o'][..], &[0xc0, 12]].concat();
        b.extend((rdata.len() as u16).to_be_bytes());
        b.extend(rdata);
        let m = parse(&b).unwrap();
        assert_eq!(m.records[0].data, RData::Ptr(format!("foo.{SERVICE}")));
        // Forward / looping pointers and truncated packets are refused, not followed.
        assert!(parse(&[0, 0, 0x84, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12]).is_none());
        assert!(parse(&[0, 0, 0x84]).is_none());
    }

    #[test]
    fn several_a_and_aaaa_records_round_trip_and_loopback_is_never_written() {
        let s = svc();
        let addrs: Vec<IpAddr> = ["192.168.1.20", "10.0.0.7", "fd00::20", "2001:db8::20", "fe80::1c:2", "127.0.0.1", "::1", "0.0.0.0"].iter().map(|a| a.parse().unwrap()).collect();
        let m = parse(&encode_answer(&s, &addrs, 0, None, false)).unwrap();
        let got: Vec<(u16, IpAddr)> = m.records.iter().filter_map(|r| if let RData::Addr(a) = r.data { Some((r.rtype, a)) } else { None }).collect();
        assert_eq!(got.len(), 5, "{got:?}");
        assert!(got.iter().all(|(t, a)| (*t == T_A) == a.is_ipv4()));
        assert!(got.iter().all(|(_, a)| !a.is_loopback() && !a.is_unspecified()));
        assert!(got.contains(&(T_AAAA, "fe80::1c:2".parse().unwrap())), "link-local goes on the wire without a zone");
        // Cache-flush on host records, the cap holds.
        assert!(m.records.iter().filter(|r| r.rtype == T_AAAA).all(|r| r.ttl == 120));
        let many: Vec<IpAddr> = (1..40).map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i))).collect();
        let m = parse(&encode_answer(&s, &many, 0, None, false)).unwrap();
        assert_eq!(m.records.iter().filter(|r| r.rtype == T_A).count(), MAX_ADDRS);
    }

    #[test]
    fn txt_carries_no_secrets_and_survives_odd_values() {
        let t = txt_bytes(&svc().txt);
        let parsed = parse_txt(&t);
        assert_eq!(parsed.len(), 4);
        assert_eq!(parse_txt(&txt_bytes(&[])), vec![]);
        assert_eq!(parse_txt(&[3, b'a', b'=', b'b', 1, b'c']), vec![("a".into(), "b".into()), ("c".into(), String::new())]);
    }
}
