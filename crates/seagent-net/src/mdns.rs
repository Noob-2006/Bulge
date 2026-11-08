//! mDNS / DNS-SD (RFC 6762 / 6763) for LAN mode: advertise `_seagent._tcp.local` and browse
//! for other SE Agent hosts. std `UdpSocket` plus one `setsockopt` per platform — no mDNS crate.
//!
//! **Responder** ([`Responder::start`]): a socket on `0.0.0.0:5353` joined to `224.0.0.251`,
//! opened with `SO_REUSEADDR` (+ `SO_REUSEPORT` on unix) so it shares the port with Avahi,
//! systemd-resolved, mDNSResponder (macOS) or the Windows DNS client. It announces twice on
//! start, answers PTR / SRV / TXT / A / ANY questions for our names (multicast to the group,
//! or unicast to the asker for a legacy query from a port other than 5353, RFC 6762 §6.7), and
//! sends a goodbye (TTL 0) when stopped or dropped.
//!
//! **Browser** ([`browse`]): sends a PTR query from an ephemeral port (legacy unicast: every
//! responder answers it directly, so browsing works even when port 5353 cannot be shared), and
//! also listens on a shared 5353 socket for multicast answers when it can get one.
//!
//! Limits (documented in docs/cross-platform.md): IPv4 only; one interface (the system's
//! default multicast route); a host whose port 5353 is held exclusively cannot *advertise*
//! (the start error says so) but can still browse and be reached by address or QR code.
//! The TXT record carries `v`, `id`, `fp` (fingerprint prefix) and `name` — never a token.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const PORT: u16 = 5353;
pub const SERVICE: &str = "_seagent._tcp.local";
const META: &str = "_services._dns-sd._udp.local";

pub const T_A: u16 = 1;
pub const T_PTR: u16 = 12;
pub const T_TXT: u16 = 16;
pub const T_AAAA: u16 = 28;
pub const T_SRV: u16 = 33;
pub const T_ANY: u16 = 255;

/// What we advertise.
#[derive(Debug, Clone, PartialEq)]
pub struct Service {
    /// Instance label (one DNS label, shown to users): "SE Agent on studio".
    pub instance: String,
    /// `<host>.local`.
    pub host: String,
    pub port: u16,
    pub txt: Vec<(String, String)>,
    pub addrs: Vec<IpAddr>,
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

fn put_name(b: &mut Vec<u8>, name: &str) {
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

/// The full answer set for `svc` (PTR, SRV, TXT, A/AAAA), `ttl` 0 = goodbye. `legacy`: a reply
/// to a legacy unicast query — echo its id, no cache-flush bits (RFC 6762 §6.7).
pub fn encode_response(svc: &Service, id: u16, ttl: Option<u32>, legacy: bool) -> Vec<u8> {
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
    for a in &svc.addrs {
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

// ── sockets ──

/// `0.0.0.0:5353` shared with the system's responder (`SO_REUSEADDR`, + `SO_REUSEPORT` on unix).
#[cfg(unix)]
fn shared_socket() -> std::io::Result<UdpSocket> {
    use std::os::fd::FromRawFd;
    // SAFETY: plain BSD socket calls on a descriptor we own; it is handed to UdpSocket (which
    // closes it) or closed here on error.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let one: libc::c_int = 1;
        let sz = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one as *const _ as *const libc::c_void, sz);
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, &one as *const _ as *const libc::c_void, sz);
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = PORT.to_be();
        sa.sin_addr = libc::in_addr { s_addr: 0 };
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
        }
        if libc::bind(fd, &sa as *const libc::sockaddr_in as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t) != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(UdpSocket::from_raw_fd(fd))
    }
}

#[cfg(windows)]
fn shared_socket() -> std::io::Result<UdpSocket> {
    use std::os::windows::io::FromRawSocket;
    use windows_sys::Win32::Networking::WinSock as ws;
    // std initialises Winsock lazily; make sure it has happened before calling it directly.
    drop(UdpSocket::bind("127.0.0.1:0"));
    // SAFETY: Winsock calls on a socket we own; it is handed to UdpSocket or closed on error.
    unsafe {
        let s = ws::socket(ws::AF_INET as i32, ws::SOCK_DGRAM, ws::IPPROTO_UDP);
        if s == ws::INVALID_SOCKET {
            return Err(std::io::Error::last_os_error());
        }
        let one: i32 = 1;
        ws::setsockopt(s, ws::SOL_SOCKET, ws::SO_REUSEADDR, &one as *const i32 as *const u8, 4);
        let mut sa: ws::SOCKADDR_IN = std::mem::zeroed();
        sa.sin_family = ws::AF_INET;
        sa.sin_port = PORT.to_be();
        if ws::bind(s, &sa as *const ws::SOCKADDR_IN as *const ws::SOCKADDR, std::mem::size_of::<ws::SOCKADDR_IN>() as i32) != 0 {
            let e = std::io::Error::last_os_error();
            ws::closesocket(s);
            return Err(e);
        }
        Ok(UdpSocket::from_raw_socket(s as u64))
    }
}

#[cfg(not(any(unix, windows)))]
fn shared_socket() -> std::io::Result<UdpSocket> {
    UdpSocket::bind(("0.0.0.0", PORT))
}

fn join(s: &UdpSocket) -> std::io::Result<()> {
    s.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)?;
    s.set_multicast_loop_v4(true)?;
    s.set_multicast_ttl_v4(255)
}

/// This machine's address on the LAN: the source address the system would use for a private
/// destination (no packet is sent). `None` when it is not in a private range.
pub fn lan_ipv4() -> Option<Ipv4Addr> {
    for probe in ["192.168.255.254:9", "10.254.254.254:9", "172.31.255.254:9"] {
        let Ok(s) = UdpSocket::bind("0.0.0.0:0") else { continue };
        if s.connect(probe).is_err() {
            continue;
        }
        if let Ok(SocketAddr::V4(a)) = s.local_addr() {
            let ip = *a.ip();
            let [x, y, ..] = ip.octets();
            if x == 10 || (x == 172 && (16..=31).contains(&y)) || (x == 192 && y == 168) || (x == 169 && y == 254) || (x == 100 && (64..=127).contains(&y)) {
                return Some(ip);
            }
        }
    }
    None
}

/// A running responder; dropping it sends the goodbye.
pub struct Responder {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Responder {
    /// Bind, announce and answer in a background thread.
    pub fn start(svc: Service) -> Result<Responder, String> {
        let sock = shared_socket().map_err(|e| format!("mDNS: cannot share UDP port 5353 ({e}); this host will not be discoverable, but devices can still pair by address or QR code"))?;
        join(&sock).map_err(|e| format!("mDNS: cannot join 224.0.0.251 ({e})"))?;
        sock.set_read_timeout(Some(Duration::from_millis(250))).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let st = stop.clone();
        let thread = std::thread::Builder::new().name("seagent-mdns".into()).spawn(move || serve(sock, svc, st)).map_err(|e| e.to_string())?;
        Ok(Responder { stop, thread: Some(thread) })
    }

    pub fn stop(mut self) {
        self.halt();
    }

    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.halt();
    }
}

fn serve(sock: UdpSocket, svc: Service, stop: Arc<AtomicBool>) {
    let group = SocketAddr::V4(SocketAddrV4::new(GROUP, PORT));
    let announce = encode_response(&svc, 0, None, false);
    let _ = sock.send_to(&announce, group);
    let mut next_announce = Some(Instant::now() + Duration::from_secs(1));
    let mut buf = [0u8; 9000];
    while !stop.load(Ordering::SeqCst) {
        if next_announce.is_some_and(|t| Instant::now() >= t) {
            let _ = sock.send_to(&announce, group);
            next_announce = None;
        }
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        let Some(m) = parse(&buf[..n]) else { continue };
        if !asks_for(&m, &svc) {
            continue;
        }
        if from.port() != PORT {
            // Legacy unicast (a plain resolver or our own browser): answer the asker directly,
            // TTL at most 10 s (RFC 6762 §6.7).
            let _ = sock.send_to(&encode_response(&svc, m.id, Some(10), true), from);
        } else if m.questions.iter().any(|q| q.2) {
            let _ = sock.send_to(&announce, from);
        } else {
            let _ = sock.send_to(&announce, group);
        }
    }
    let _ = sock.send_to(&encode_response(&svc, 0, Some(0), false), group);
}

/// A host found by [`browse`].
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Found {
    pub instance: String,
    pub host: String,
    pub port: u16,
    pub addrs: Vec<IpAddr>,
    pub txt: BTreeMap<String, String>,
}

/// Fold the records of one or more responses into hosts.
pub fn collect(records: &[Record]) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    let svc = SERVICE.to_ascii_lowercase();
    for r in records {
        if let (true, RData::Ptr(inst)) = (r.name.to_ascii_lowercase() == svc, &r.data) {
            if r.ttl > 0 && !out.iter().any(|f| f.instance.eq_ignore_ascii_case(inst)) {
                out.push(Found { instance: inst.clone(), ..Default::default() });
            }
        }
    }
    for f in &mut out {
        for r in records.iter().filter(|r| r.name.eq_ignore_ascii_case(&f.instance)) {
            match &r.data {
                RData::Srv { port, target } => {
                    f.port = *port;
                    f.host = target.clone();
                }
                RData::Txt(t) => f.txt = t.iter().cloned().collect(),
                _ => {}
            }
        }
        for r in records.iter().filter(|r| !f.host.is_empty() && r.name.eq_ignore_ascii_case(&f.host)) {
            if let RData::Addr(a) = r.data {
                if !f.addrs.contains(&a) {
                    f.addrs.push(a);
                }
            }
        }
        // `<instance>._seagent._tcp.local` → the readable instance label.
        if let Some(label) = f.instance.strip_suffix(&format!(".{SERVICE}")) {
            f.instance = label.to_string();
        }
    }
    out.retain(|f| f.port != 0);
    out
}

/// Look for `_seagent._tcp` hosts for `timeout`.
pub fn browse(timeout: Duration) -> Result<Vec<Found>, String> {
    let q = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("mDNS: {e}"))?;
    let _ = q.set_multicast_ttl_v4(255);
    let _ = q.set_multicast_loop_v4(true);
    let shared = shared_socket().ok().filter(|s| join(s).is_ok());
    let id = u16::from_be_bytes([crate::crypto::random_bytes(1)[0], crate::crypto::random_bytes(1)[0]]);
    let query = encode_query(id, SERVICE, T_PTR, false);
    let group = SocketAddr::V4(SocketAddrV4::new(GROUP, PORT));
    q.send_to(&query, group).map_err(|e| format!("mDNS: cannot send a query ({e})"))?;
    if let Some(s) = &shared {
        let _ = s.send_to(&query, group);
    }
    let until = Instant::now() + timeout;
    let mut records = Vec::new();
    let mut buf = [0u8; 9000];
    let mut resent = false;
    while Instant::now() < until {
        if !resent && Instant::now() + timeout / 2 >= until {
            let _ = q.send_to(&query, group);
            resent = true;
        }
        for s in std::iter::once(&q).chain(shared.iter()) {
            let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
            while let Ok((n, _)) = s.recv_from(&mut buf) {
                if let Some(m) = parse(&buf[..n]).filter(|m| m.response) {
                    records.extend(m.records);
                }
            }
        }
    }
    Ok(collect(&records))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc() -> Service {
        Service {
            instance: "SE Agent on studio".into(),
            host: "studio.local".into(),
            port: 8640,
            txt: vec![("v".into(), "seagent/2".into()), ("id".into(), "studio".into()), ("fp".into(), "0123456789abcdef".into()), ("name".into(), "Studio".into())],
            addrs: vec!["192.168.1.20".parse().unwrap()],
        }
    }

    #[test]
    fn response_round_trips_into_a_found_host() {
        let s = svc();
        let m = parse(&encode_response(&s, 0, None, false)).unwrap();
        assert!(m.response && m.questions.is_empty());
        assert!(m.records.iter().any(|r| r.rtype == T_SRV && r.ttl == 120));
        let found = collect(&m.records);
        assert_eq!(found.len(), 1);
        let f = &found[0];
        assert_eq!((f.instance.as_str(), f.host.as_str(), f.port), ("SE Agent on studio", "studio.local", 8640));
        assert_eq!(f.addrs, vec!["192.168.1.20".parse::<IpAddr>().unwrap()]);
        assert_eq!(f.txt["v"], "seagent/2");
        assert_eq!(f.txt["fp"], "0123456789abcdef");
        // Goodbye: TTL 0 everywhere, and a goodbye PTR yields no host.
        let bye = parse(&encode_response(&s, 0, Some(0), false)).unwrap();
        assert!(bye.records.iter().all(|r| r.ttl == 0));
        assert!(collect(&bye.records).is_empty());
        // A legacy unicast reply echoes the id and has no cache-flush bit.
        let legacy = encode_response(&s, 0x1234, None, true);
        assert_eq!(&legacy[..2], &[0x12, 0x34]);
    }

    #[test]
    fn queries_are_matched_and_compressed_names_decode() {
        let s = svc();
        let q = parse(&encode_query(7, SERVICE, T_PTR, true)).unwrap();
        assert_eq!(q.questions, vec![(SERVICE.to_string(), T_PTR, true)]);
        assert!(asks_for(&q, &s));
        assert!(asks_for(&parse(&encode_query(1, "studio.local", T_A, false)).unwrap(), &s));
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
    fn txt_carries_no_secrets_and_survives_odd_values() {
        let t = txt_bytes(&svc().txt);
        let parsed = parse_txt(&t);
        assert_eq!(parsed.len(), 4);
        assert_eq!(parse_txt(&txt_bytes(&[])), vec![]);
        assert_eq!(parse_txt(&[3, b'a', b'=', b'b', 1, b'c']), vec![("a".into(), "b".into()), ("c".into(), String::new())]);
    }

    /// Advertise and browse on this machine (multicast loopback). Skips when the environment
    /// has no multicast (containers, some CI runners).
    #[test]
    fn responder_and_browser_find_each_other_on_loopback() {
        let mut s = svc();
        s.instance = format!("SE Agent test {}", std::process::id());
        s.port = 18640;
        let r = match Responder::start(s.clone()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("skipping: {e}");
                return;
            }
        };
        let found = browse(Duration::from_millis(1500)).unwrap_or_default();
        r.stop();
        match found.iter().find(|f| f.instance == s.instance) {
            Some(f) => assert_eq!((f.port, f.txt.get("id").map(String::as_str)), (18640, Some("studio"))),
            None => eprintln!("skipping: no multicast loopback here (found {found:?})"),
        }
    }
}
